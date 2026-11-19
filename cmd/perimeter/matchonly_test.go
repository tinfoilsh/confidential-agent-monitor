package main

import (
	"bufio"
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"maps"
	"math/big"
	"net"
	"net/http"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/tinfoilsh/confidential-agent-monitor/cmd/perimeter/config"
	"github.com/tinfoilsh/confidential-agent-monitor/cmd/perimeter/connections"
	"github.com/tinfoilsh/confidential-agent-monitor/connector/catalog"
	"github.com/tinfoilsh/confidential-agent-monitor/connector/slots"
	"github.com/tinfoilsh/confidential-agent-monitor/connector/web"
	"github.com/tinfoilsh/confidential-agent-monitor/core/connector"
	"github.com/tinfoilsh/confidential-agent-monitor/core/facts"
	"github.com/tinfoilsh/confidential-agent-monitor/core/tomledit"
	"golang.org/x/crypto/ssh"
)

const (
	testSecret      = "xoxb-real-secret-value"
	testPlaceholder = "tfm_slack_placeholder"
)

var loadPresets = sync.OnceValues(func() (map[string]*catalog.Preset, error) {
	p, _, err := config.LoadPresets(nil)
	return p, err
})

// upstream records the requests the connector forwards instead of sending them.
type upstream struct {
	mu   sync.Mutex
	seen []*http.Request
}

func (u *upstream) RoundTrip(r *http.Request) (*http.Response, error) {
	u.mu.Lock()
	u.seen = append(u.seen, r)
	u.mu.Unlock()
	return &http.Response{StatusCode: http.StatusOK, Header: http.Header{"Content-Type": {"application/json"}}, Body: io.NopCloser(strings.NewReader(`{"ok":true}`)), Request: r}, nil
}

func (u *upstream) last() *http.Request {
	u.mu.Lock()
	defer u.mu.Unlock()
	if len(u.seen) == 0 {
		return nil
	}
	return u.seen[len(u.seen)-1]
}

type perimeterHarness struct {
	t        *testing.T
	st       *settings
	name     string
	handler  web.Handler
	upstream *upstream
	who      facts.Principal
	tls      *tls.Config
}

type outcome struct {
	status   int
	body     string
	decision *record
	err      error
}

func testKey(t *testing.T) string {
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	key, err := ssh.NewPublicKey(pub)
	if err != nil {
		t.Fatal(err)
	}
	return strings.TrimSpace(string(ssh.MarshalAuthorizedKey(key)))
}

func selfSigned(t *testing.T) *tls.Config {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{SerialNumber: big.NewInt(1), NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), DNSNames: []string{"*"}}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return &tls.Config{Certificates: []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: key}}}
}

// newHarness loads a policy with one Slack connection and builds the same connector and policy evaluation the Perimeter uses.
func newHarness(t *testing.T, matchOnly bool, level string) *perimeterHarness {
	t.Helper()
	loaded, err := loadPresets()
	if err != nil {
		t.Fatal(err)
	}
	source := fmt.Sprintf(`
[connections.slack]
preset = "slack"
contents = "me"
sends = "team"
strangers = false
match_only = %t
policy_options = { origin = "https://slack.com" }

[identities.sandbox]
key = %q

[identities.sandbox.connections.slack]
level = %q

[policies]
sentinel = """
package sentinel

allow := true
"""
`, matchOnly, testKey(t), level)
	cfg, err := config.Load(source, loaded)
	if err != nil {
		t.Fatal(err)
	}
	program, err := config.PreparePolicy(context.Background(), cfg, "")
	if err != nil {
		t.Fatal(err)
	}
	spec, err := cfg.Spec("slack")
	if err != nil {
		t.Fatal(err)
	}
	p, err := connections.Parse(spec)
	if err != nil {
		t.Fatal(err)
	}
	setup, err := web.Parse(spec.Config, spec.Definition, spec.Options, func(raw json.RawMessage) (web.Slots, error) {
		var list []slots.Slot
		if len(raw) != 0 {
			if err := facts.DecodeNumbers(raw, &list); err != nil {
				return nil, err
			}
		}
		return slots.New(list, slots.Options{Prefix: "tfm_", MaxSignedBody: 16 << 20})
	})
	if err != nil {
		t.Fatal(err)
	}
	// The package-level presets resolve operations as they do in the running Perimeter.
	before := presets
	presets = loaded
	t.Cleanup(func() { presets = before })
	h := &perimeterHarness{
		t:        t,
		name:     "slack",
		upstream: &upstream{},
		who:      facts.Principal{Name: "sandbox"},
		st:       &settings{Config: cfg, policy: program, publicScope: map[string][]string{"slack": spec.PublicScope}, connections: map[string]*installed{"slack": {Setup: p}}},
	}
	h.tls = selfSigned(t)
	h.handler = web.Handler{
		Setup:       setup,
		Transport:   h.upstream,
		TLS:         func(context.Context, string) *tls.Config { return h.tls },
		Placeholder: func(string) string { return testPlaceholder },
		Secret:      func(context.Context, string) (string, error) { return testSecret, nil },
		MaxBody:     8 << 20,
	}
	return h
}

// do sends one request over TLS to the connector for host, as a bunker would through the Perimeter.
func (h *perimeterHarness) do(host, method, path, body string, header http.Header) outcome {
	h.t.Helper()
	server, client := net.Pipe()
	var out outcome
	var mu sync.Mutex
	gate := func(ctx context.Context, event facts.Event) error {
		r, err := h.st.decide(ctx, h.who, h.name, &grant{kind: config.KindOperation, event: event, label: config.InitialLabel, approved: []string{}})
		mu.Lock()
		out.decision, out.err = r, err
		mu.Unlock()
		switch {
		case err != nil:
			return err
		case !r.Allow:
			return errors.New(strings.Join(append(r.Deny, "not allowed"), "; "))
		}
		return nil
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan struct{})
	go func() {
		defer close(done)
		h.handler.Serve(ctx, server, "", connector.Target{Network: "tcp", Host: host, Port: 443}, gate)
	}()
	conn := tls.Client(client, &tls.Config{ServerName: host, InsecureSkipVerify: true})
	req, err := http.NewRequest(method, "https://"+host+path, strings.NewReader(body))
	if err != nil {
		h.t.Fatal(err)
	}
	for k, v := range header {
		req.Header[k] = v
	}
	if body != "" && req.Header.Get("Content-Type") == "" {
		req.Header.Set("Content-Type", "application/json")
	}
	req.Close = true
	if err := req.Write(conn); err != nil {
		h.t.Fatal(err)
	}
	resp, err := http.ReadResponse(bufio.NewReader(conn), req)
	if err != nil {
		h.t.Fatal(err)
	}
	b, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	conn.Close()
	cancel()
	<-done
	mu.Lock()
	defer mu.Unlock()
	out.status, out.body = resp.StatusCode, string(b)
	return out
}

func bearer() http.Header {
	return http.Header{"Authorization": {"Bearer " + testPlaceholder}}
}

func (o outcome) operation(t *testing.T) *catalog.Operation {
	t.Helper()
	if o.decision == nil {
		t.Fatalf("no decision recorded (status %d, %s, err %v)", o.status, o.body, o.err)
	}
	var f struct {
		Operation *catalog.Operation `json:"operation"`
		Context   struct {
			Sends string `json:"sends"`
		} `json:"context"`
	}
	if err := json.Unmarshal(o.decision.Facts, &f); err != nil {
		t.Fatal(err)
	}
	return f.Operation
}

func TestMatchOnlyOffKeepsReviewedOperationsAndFailsClosed(t *testing.T) {
	h := newHarness(t, false, "allow")

	known := h.do("slack.com", "POST", "/api/chat.postMessage", `{"channel":"C123","text":"hi"}`, bearer())
	if known.status != http.StatusOK {
		t.Fatalf("chat.postMessage: %d %s", known.status, known.body)
	}
	if op := known.operation(t); op == nil || op.ID != "chat.postMessage" || op.Action != "chat.message.send" {
		t.Fatalf("chat.postMessage was described as %+v", op)
	}

	unknown := h.do("slack.com", "POST", "/api/not.a.real.method", `{}`, bearer())
	if unknown.status != http.StatusForbidden {
		t.Fatalf("an unknown method must not pass without match-only mode: %d %s", unknown.status, unknown.body)
	}
	if op := unknown.operation(t); op != nil {
		t.Fatalf("unknown method was described as %+v", op)
	}
	if !hasRequirement(unknown.decision, "ask") {
		t.Fatalf("an unknown method should wait for approval, got %+v", unknown.decision.Decision)
	}
}

func TestMatchOnlyForwardsAnyRequestWithCredentials(t *testing.T) {
	h := newHarness(t, true, "allow")
	for _, c := range []struct{ method, path, body string }{
		{"POST", "/api/not.a.real.method", `{"x":1}`},
		{"POST", "/api/chat.postMessage", `{"channel":"C123","text":"hi"}`},
		{"GET", "/api/conversations.history?channel=C123&limit=5", ""},
		{"POST", "/api/admin.users.remove", `{"user_id":"U1"}`},
		{"DELETE", "/api/some/new/rest/route", ""},
	} {
		t.Run(c.method+" "+c.path, func(t *testing.T) {
			out := h.do("slack.com", c.method, c.path, c.body, bearer())
			if out.status != http.StatusOK {
				t.Fatalf("got %d %s (decision %+v)", out.status, out.body, out.decision)
			}
			op := out.operation(t)
			if op == nil || op.ID != config.MatchOnlyAction || op.Action != config.MatchOnlyAction || strings.Join(op.Effects, ",") != "execute,send" {
				t.Fatalf("described as %+v", op)
			}
			if title := out.title(t); !strings.HasPrefix(title, "Slack: "+c.method+" slack.com/") {
				t.Fatalf("title %q does not say what was requested", title)
			}
			sent := h.upstream.last()
			if got := sent.Header.Get("Authorization"); got != "Bearer "+testSecret {
				t.Fatalf("upstream Authorization = %q, want the substituted secret", got)
			}
			if sent.URL.Host != "slack.com" || !strings.HasPrefix(c.path, sent.URL.Path) {
				t.Fatalf("forwarded to %s", sent.URL)
			}
		})
	}
}

func TestMatchOnlyStillMatchesHostsAndCredentialSlots(t *testing.T) {
	h := newHarness(t, true, "allow")

	other := h.do("example.com", "GET", "/api/auth.test", "", bearer())
	if other.status != http.StatusForbidden || h.upstream.last() != nil {
		t.Fatalf("a host outside the service must be refused: %d %s", other.status, other.body)
	}

	// The credential's slot covers slack.com/api only; a placeholder sent elsewhere on the host is refused.
	outside := h.do("slack.com", "GET", "/intl/en-gb/", "", bearer())
	if outside.status != http.StatusForbidden || !strings.Contains(outside.body, "credential token is not allowed") || h.upstream.last() != nil {
		t.Fatalf("a credential outside its slot must be refused: %d %s", outside.status, outside.body)
	}

	// Without a placeholder nothing is substituted, but the request is still described as match-only.
	plain := h.do("slack.com", "GET", "/api/api.test", "", nil)
	if plain.status != http.StatusOK {
		t.Fatalf("api.test: %d %s", plain.status, plain.body)
	}
	if got := h.upstream.last().Header.Get("Authorization"); got != "" {
		t.Fatalf("unexpected Authorization %q", got)
	}

	// Malformed requests stay refused.
	bad := h.do("slack.com", "GET", "/api/../admin", "", bearer())
	if bad.status != http.StatusForbidden && bad.status != http.StatusBadRequest {
		t.Fatalf("a noncanonical path must be refused: %d %s", bad.status, bad.body)
	}
}

func TestMatchOnlyRespectsAccessLevels(t *testing.T) {
	ask := newHarness(t, true, "ask")
	out := ask.do("slack.com", "POST", "/api/not.a.real.method", `{}`, bearer())
	if out.status != http.StatusForbidden || !hasRequirement(out.decision, "ask") {
		t.Fatalf("Ask access should still ask: %d %+v", out.status, out.decision)
	}
	for _, r := range out.decision.Requirements {
		if strings.Contains(r.Message, "no recognized operation") {
			t.Fatalf("match-only requests are not unknown operations: %q", r.Message)
		}
	}

	read := newHarness(t, true, "read")
	out = read.do("slack.com", "GET", "/api/conversations.list", "", bearer())
	if out.status != http.StatusForbidden || len(out.decision.Deny) == 0 {
		t.Fatalf("Read access cannot make broad requests: %d %+v", out.status, out.decision)
	}

	off := newHarness(t, true, "off")
	out = off.do("slack.com", "GET", "/api/auth.test", "", bearer())
	if out.status != http.StatusForbidden {
		t.Fatalf("Off access must refuse: %d", out.status)
	}
}

func TestMatchOnlyKeepsTheConnectionsAudienceAndTrust(t *testing.T) {
	h := newHarness(t, true, "allow")
	out := h.do("slack.com", "POST", "/api/not.a.real.method", `{}`, bearer())
	if out.decision == nil || !out.decision.Allow {
		t.Fatalf("not allowed: %+v", out.decision)
	}
	// The request is sent to the connection's audience, not to anyone, and is not treated as untrusted.
	if out.decision.Sends != "team" {
		t.Fatalf("sends = %q, want the connection's team audience", out.decision.Sends)
	}
	if out.decision.Next.Trust != config.TrustTrusted || out.decision.Next.Audience != "me" {
		t.Fatalf("next label = %+v", out.decision.Next)
	}
}

func TestMatchOnlyDescribesOtherProtocolsAsOneRequest(t *testing.T) {
	unknown := requestFacts{}
	matchOnly(&unknown, "Svc")
	if unknown.Operation == nil || unknown.Operation.Action != config.MatchOnlyAction || unknown.Context.Sends != config.SendsConnection {
		t.Fatalf("unknown request became %+v / %+v", unknown.Operation, unknown.Context)
	}

	tool := requestFacts{Operation: &catalog.Operation{ID: "use.delete_everything", Action: "use.delete_everything", Effects: []string{"delete"}}}
	tool.Context.Sends = config.AudienceAnyone
	matchOnly(&tool, "Svc")
	if tool.Operation.Action != config.MatchOnlyAction || tool.Context.Sends != config.AudienceAnyone {
		t.Fatalf("tool became %+v, sends %q", tool.Operation, tool.Context.Sends)
	}

	signIn := requestFacts{Operation: &catalog.Operation{ID: web.SignInAction, Action: web.SignInAction, Effects: []string{"session"}}}
	matchOnly(&signIn, "Svc")
	if signIn.Operation.Action != web.SignInAction {
		t.Fatalf("sign-ins keep their description, got %+v", signIn.Operation)
	}
}

func hasRequirement(r *record, id string) bool {
	if r == nil {
		return false
	}
	for _, req := range r.Requirements {
		if req.ID == id {
			return true
		}
	}
	return false
}

func TestMatchOnlyToggleKeepsSetupAndDropsSavedApprovals(t *testing.T) {
	loaded, err := loadPresets()
	if err != nil {
		t.Fatal(err)
	}
	source := fmt.Sprintf(`
[connections.slack]
preset = "slack"
contents = "me"
sends = "team"
policy_options = { origin = "https://slack.com" }

[identities.sandbox]
key = %q

[identities.sandbox.connections.slack]
level = "ask"

[identities.sandbox.rules.post]
version = %d
connection = "slack"
action = "chat.message.send"
operation = "chat.postMessage"
scope = { channel = "C123" }
requirements = [{ id = "ask", message = "approve" }]
`, testKey(t), config.FactsVersion)
	cfg, err := config.Load(source, loaded)
	if err != nil {
		t.Fatal(err)
	}
	before, err := cfg.Spec("slack")
	if err != nil {
		t.Fatal(err)
	}
	edited, rebuild, _, err := cfg.Edit(source, []tomledit.Change{{Path: []string{"connections", "slack", "match_only"}, Value: true}})
	if err != nil {
		t.Fatal(err)
	}
	if !rebuild("slack") {
		t.Fatal("turning on match-only mode must rebuild the connection")
	}
	next, err := config.Load(edited, loaded)
	if err != nil {
		t.Fatal(err)
	}
	if !next.Connections["slack"].MatchOnly {
		t.Fatal("match_only was not saved")
	}
	if len(next.Identities["sandbox"].Rules) != 0 {
		t.Fatalf("saved approvals for the old descriptions must be removed, got %v", next.Identities["sandbox"].Rules)
	}
	after, err := next.Spec("slack")
	if err != nil {
		t.Fatal(err)
	}
	// Hosts, credential slots and options are unchanged; only the operations and actions are replaced.
	if before.Protocol != after.Protocol || string(before.Config) != string(after.Config) || string(before.Options) != string(after.Options) {
		t.Fatalf("setup changed:\n%s\n%s", before.Config, after.Config)
	}
	var definition struct {
		HTTP struct {
			Operations     map[string]json.RawMessage `json:"operations"`
			Origins        map[string][]string        `json:"origins"`
			SensitiveQuery []string                   `json:"sensitive_query"`
		} `json:"http"`
		Catalog struct {
			Actions map[string]json.RawMessage `json:"actions"`
		} `json:"catalog"`
	}
	if err := json.Unmarshal(after.Definition, &definition); err != nil {
		t.Fatal(err)
	}
	if len(definition.HTTP.Operations) != 1 || definition.HTTP.Operations[config.MatchOnlyAction] == nil {
		t.Fatalf("operations = %d", len(definition.HTTP.Operations))
	}
	if len(definition.Catalog.Actions) != 1 || definition.Catalog.Actions[config.MatchOnlyAction] == nil {
		t.Fatalf("actions = %v", definition.Catalog.Actions)
	}
	if len(definition.HTTP.Origins["origin"]) == 0 || len(definition.HTTP.SensitiveQuery) == 0 {
		t.Fatal("origins and sensitive query fingerprints must be kept")
	}

}

// Every shipped preset whose connection can be built can also be built in match-only mode.
func TestMatchOnlyBuildsForEveryShippedPreset(t *testing.T) {
	loaded, err := loadPresets()
	if err != nil {
		t.Fatal(err)
	}
	key := testKey(t)
	build := func(name string, matchOnly bool) error {
		source := fmt.Sprintf("[connections.svc]\npreset = %q\ncontents = \"me\"\nsends = \"me\"\nmatch_only = %t\npolicy_options = { origin = \"https://example.com\" }\n\n[identities.sandbox]\nkey = %q\n", name, matchOnly, key)
		cfg, err := config.Load(source, loaded)
		if err != nil {
			return err
		}
		spec, err := cfg.Spec("svc")
		if err != nil {
			return err
		}
		_, err = connections.Parse(spec)
		return err
	}
	built := 0
	for _, name := range slices.Sorted(maps.Keys(loaded)) {
		if build(name, false) != nil {
			continue
		}
		built++
		if err := build(name, true); err != nil {
			t.Errorf("%s: %v", name, err)
		}
	}
	if built < 300 {
		t.Fatalf("only %d presets built; the check is not exercising the catalog", built)
	}
	t.Logf("%d presets build in match-only mode", built)
}

func (o outcome) title(t *testing.T) string {
	t.Helper()
	var f struct {
		Title string `json:"title"`
	}
	if err := json.Unmarshal(o.decision.Facts, &f); err != nil {
		t.Fatal(err)
	}
	return f.Title
}
