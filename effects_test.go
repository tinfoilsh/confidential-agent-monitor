package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"errors"
	"maps"
	"net"
	"net/http"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/tinfoilsh/monitor/connector"
	"github.com/tinfoilsh/monitor/connector/web"
	"github.com/tinfoilsh/monitor/facts"
	"gocloud.dev/blob/memblob"
	"golang.org/x/crypto/ssh"
)

func effectMonitor(t *testing.T) (*monitor, string) {
	t.Helper()
	bucket := memblob.OpenBucket(nil)
	m := &monitor{store: bucket, dev: true}
	if err := m.unlock(t.Context(), bytes.Repeat([]byte{42}, 32), 0); err != nil {
		t.Fatal(err)
	}
	signer, err := ssh.NewSignerFromKey(ed25519.NewKeyFromSeed(make([]byte, 32)))
	if err != nil {
		t.Fatal(err)
	}
	effectEdit(t, m,
		sourceChange{Path: []string{"lattices"}, Value: map[string]any{"confidentiality": false, "integrity": false}},
		sourceChange{Path: []string{"accounts", "api"}, Value: map[string]any{
			"preset": "anthropic", "contents": "anyone", "sends": "anyone", "strangers": false,
			"connections": map[string]any{"": map[string]any{"http": map[string]any{"hosts": []string{"api.anthropic.com"}}}}}},
		sourceChange{Path: []string{"identities", "agent"}, Value: map[string]any{
			"key":      strings.TrimSpace(string(ssh.MarshalAuthorizedKey(signer.PublicKey()))),
			"accounts": map[string]any{"api": map[string]any{"level": "allow"}}}})
	t.Cleanup(func() {
		for _, c := range m.running {
			c.cancel()
		}
		for _, c := range m.running {
			<-c.done
		}
		bucket.Close()
	})
	return m, ssh.FingerprintSHA256(signer.PublicKey())
}

func effectEdit(t *testing.T, m *monitor, changes ...sourceChange) {
	t.Helper()
	m.mu.Lock()
	err := m.editPolicy(t.Context(), changes)
	m.mu.Unlock()
	if err != nil {
		t.Fatal(err)
	}
}

type effectRequest struct {
	effects []string
	kind    facts.Kind
	unknown bool
}

func (r effectRequest) Describe(connector.Context) (facts.Facts, error) {
	f := facts.Facts{Title: "Effect probe", Kind: r.kind,
		Operation: &facts.Operation{ID: "messages.create", Action: "messages.generate", Effects: r.effects}}
	if r.unknown {
		f.Operation = nil
	}
	return f, nil
}

func TestEffectPrecedenceAndPersistence(t *testing.T) {
	m, _ := effectMonitor(t)
	paths := [][]string{{"effects", "pay"}, {"accounts", "api", "effects", "pay"},
		{"identities", "agent", "effects", "pay"}, {"identities", "agent", "accounts", "api", "effects", "pay"}}
	modes := []string{"allow", "off", "ask", "allow"}
	check := func(want string) {
		t.Helper()
		st := m.live.Load()
		if got := st.cfg.effectModes("agent", "api")["pay"]; got != want {
			t.Fatalf("pay=%s; want %s", got, want)
		}
		reloaded, _, err := compileSource(m.doc.Policy, m.doc.Secrets.clone())
		if err != nil || !maps.Equal(reloaded.effectModes("agent", "api"), st.cfg.effectModes("agent", "api")) {
			t.Fatalf("stored policy differs: %v", err)
		}
	}
	check("ask")
	for i, path := range paths {
		effectEdit(t, m, sourceChange{Path: path, Value: modes[i]})
		check(modes[i])
	}
	for i := len(paths) - 1; i >= 0; i-- {
		effectEdit(t, m, sourceChange{Path: paths[i], Delete: true})
		want := "ask"
		if i > 0 {
			want = modes[i-1]
		}
		check(want)
	}
	// A pair effect override can be added to access inherited from default_access.
	effectEdit(t, m, sourceChange{Path: []string{"default_access", "api"}, Value: map[string]any{"level": "allow",
		"actions": map[string]any{"messages": "off"}, "effects": map[string]any{"publish": "off"}}},
		sourceChange{Path: []string{"identities", "agent", "accounts", "api"}, Delete: true})
	effectEdit(t, m, sourceChange{Path: paths[3], Value: "off"})
	check("off")
	if got := m.live.Load().cfg.Identities["agent"].Accounts["api"].Level; got != "allow" {
		t.Fatalf("lost inherited access: %s", got)
	}
	if got := m.live.Load().cfg.Identities["agent"].Accounts["api"]; got.Actions["messages"] != "off" || got.Effects["publish"] != "off" {
		t.Fatalf("effect override lost inherited restrictions: %+v", got)
	}
	for _, path := range paths {
		for _, bad := range []sourceChange{{Path: path, Value: "read"}, {Path: append(slices.Clone(path[:len(path)-1]), "typo"), Value: "allow"}} {
			m.mu.Lock()
			err := m.editPolicy(t.Context(), []sourceChange{bad})
			m.mu.Unlock()
			if err == nil {
				t.Fatalf("accepted invalid effect setting: %+v", bad)
			}
		}
	}
}

func TestEffectDecisions(t *testing.T) {
	for _, tc := range []struct {
		name, level, action, pay, publish string
		kind                              facts.Kind
		effects                           []string
		unknown, deny, inference          bool
		want                              []string
	}{
		{name: "payment default", want: []string{"effect.pay"}},
		{name: "inference allowed", inference: true},
		{name: "other payments still ask", inference: true, effects: []string{"pay"}, want: []string{"effect.pay"}},
		{name: "inference payment ask override", inference: true, pay: "ask", want: []string{"effect.pay"}},
		{name: "inference payment deny override", inference: true, pay: "off", deny: true},
		{name: "inference publishing still asks", inference: true, effects: []string{"generate", "pay", "publish"}, want: []string{"effect.publish"}},
		{name: "inference account ask remains", inference: true, level: "ask", want: []string{"ask"}},
		{name: "inference read only remains", inference: true, level: "read", deny: true, want: []string{"ask"}},
		{name: "inference action denial remains", inference: true, action: "off", deny: true, want: []string{"ask"}},
		{name: "inference unknown still asks", inference: true, unknown: true, want: []string{"ask"}},
		{name: "payment allowed", pay: "allow"},
		{name: "payment denied", pay: "off", deny: true},
		{name: "action allow still asks", action: "allow", want: []string{"effect.pay"}},
		{name: "action allow still denies", action: "allow", pay: "off", deny: true},
		{name: "action denial remains", action: "off", pay: "allow", deny: true, want: []string{"ask"}},
		{name: "action ask remains", action: "ask", pay: "allow", want: []string{"ask"}},
		{name: "account ask remains", level: "ask", pay: "allow", want: []string{"ask"}},
		{name: "read only remains", level: "read", pay: "allow", deny: true, want: []string{"ask"}},
		{name: "no access remains", level: "off", pay: "allow", deny: true, want: []string{"ask"}},
		{name: "both effects ask", effects: []string{"pay", "publish"}, want: []string{"effect.pay", "effect.publish"}},
		{name: "publishing still asks", effects: []string{"pay", "publish"}, pay: "allow", want: []string{"effect.publish"}},
		{name: "mixed denial", effects: []string{"pay", "publish"}, pay: "ask", publish: "off", deny: true, want: []string{"effect.pay"}},
		{name: "unrelated effect", effects: []string{"read"}, pay: "off"},
		{name: "unknown still asks", unknown: true, pay: "allow", want: []string{"ask"}},
		{name: "session default", effects: []string{"session"}, kind: facts.KindAdmission},
	} {
		t.Run(tc.name, func(t *testing.T) {
			m, key := effectMonitor(t)
			changes := []sourceChange{{Path: []string{"identities", "agent", "profile"}, Value: true},
				{Path: []string{"allow_paid_inference"}, Value: tc.inference}}
			for _, setting := range []struct {
				path []string
				mode string
			}{{[]string{"effects", "pay"}, tc.pay}, {[]string{"effects", "publish"}, tc.publish},
				{[]string{"identities", "agent", "accounts", "api", "level"}, tc.level},
				{[]string{"identities", "agent", "accounts", "api", "actions", "messages"}, tc.action}} {
				if setting.mode != "" {
					changes = append(changes, sourceChange{Path: setting.path, Value: setting.mode})
				}
			}
			effectEdit(t, m, changes...)
			if tc.effects == nil {
				tc.effects = []string{"generate", "pay", "send"}
			}
			if err := m.check(t.Context(), input{Key: key, Connection: "api", Request: effectRequest{tc.effects, tc.kind, tc.unknown}}); err != nil {
				t.Fatal(err)
			}
			r := m.records[len(m.records)-1]
			var got []string
			for _, req := range r.Requirements {
				got = append(got, req.ID)
				if strings.HasPrefix(req.ID, "effect.") && !strings.Contains(req.Message, strings.TrimPrefix(req.ID, "effect.")) {
					t.Fatalf("unexplained effect approval: %+v", req)
				}
			}
			slices.Sort(got)
			if (len(r.Deny) > 0) != tc.deny || !slices.Equal(got, tc.want) {
				t.Fatalf("deny=%v requirements=%v; want deny=%v requirements=%v", r.Deny, got, tc.deny, tc.want)
			}
		})
	}
}

func TestEffectApprovalAndRevocation(t *testing.T) {
	m, key := effectMonitor(t)
	in := input{Key: key, Connection: "api", Request: effectRequest{effects: []string{"pay"}}}
	ctx, cancel := context.WithCancel(t.Context())
	result := make(chan error, 1)
	go func() { result <- m.check(ctx, in) }()
	defer cancel()
	deadline := time.Now().Add(5 * time.Second)
	for {
		m.mu.Lock()
		if len(m.records) > 0 && m.records[len(m.records)-1].State == statePending {
			r := m.records[len(m.records)-1]
			err := m.answer(t.Context(), r.ID, answerSave)
			m.mu.Unlock()
			if err != nil {
				t.Fatal(err)
			}
			break
		}
		m.mu.Unlock()
		if time.Now().After(deadline) {
			t.Fatal("payment never asked for approval")
		}
		time.Sleep(time.Millisecond)
	}
	if err := <-result; err == nil || err.Error() != errRuleSaved.Error() {
		t.Fatalf("save result: %v", err)
	}
	if err := m.check(t.Context(), in); err != nil {
		t.Fatalf("saved approval was not applied: %v", err)
	}
	client, peer := net.Pipe()
	defer peer.Close()
	stream := connector.NewStream(t.Context(), client)
	stream.Name = "api"
	defer stream.Close()
	m.mu.Lock()
	m.streams[stream] = key
	m.mu.Unlock()
	effectEdit(t, m, sourceChange{Path: []string{"effects", "pay"}, Value: "off"})
	if stream.Context.Err() == nil {
		t.Fatal("effect change left an affected stream open")
	}
	if err := m.check(t.Context(), in); err == nil || !strings.Contains(err.Error(), "pay effect is set to Deny") {
		t.Fatalf("saved approval bypassed Deny: %v", err)
	}
	effectEdit(t, m, sourceChange{Path: []string{"effects", "pay"}, Value: "allow"})
	if err := m.check(t.Context(), in); err != nil {
		t.Fatalf("allowed payment failed: %v", err)
	}
	// Effect decisions also apply when a connector authorizes an entire session.
	effectEdit(t, m, sourceChange{Path: []string{"effects", "session"}, Value: "ask"})
	ctx, stop := context.WithTimeout(t.Context(), 50*time.Millisecond)
	defer stop()
	err := m.check(ctx, input{Key: key, Connection: "api", Request: effectRequest{effects: []string{"session"}, kind: facts.KindAdmission}})
	if !errors.Is(err, context.DeadlineExceeded) || m.records[len(m.records)-1].Requirements[0].ID != "effect.session" {
		t.Fatalf("session effect did not ask: %v", err)
	}
}

func TestEffectInference(t *testing.T) {
	m, key := effectMonitor(t)
	request := &web.Request{HTTP: &facts.HTTP{Method: "POST", Origin: "https://api.anthropic.com", Host: "api.anthropic.com",
		Path: "/v1/messages", Headers: http.Header{"Anthropic-Version": {"2023-06-01"}}, BodyKind: "json",
		Body: map[string]any{"model": "test-model", "max_tokens": 1, "messages": []any{map[string]any{"role": "user", "content": "hello"}}}}}
	in := input{Key: key, Connection: "api", Request: request}
	effectEdit(t, m, sourceChange{Path: []string{"identities", "agent", "profile"}, Value: true})
	if err := m.check(t.Context(), in); err != nil {
		t.Fatal(err)
	}
	r := m.records[len(m.records)-1]
	if r.Facts.Operation == nil || r.Facts.Operation.ID != "messages.create" || len(r.Requirements) != 1 || r.Requirements[0].ID != "effect.pay" {
		t.Fatalf("inference did not require payment approval: %+v", r)
	}
	effectEdit(t, m, sourceChange{Path: []string{"identities", "agent", "profile"}, Value: false},
		sourceChange{Path: []string{"allow_paid_inference"}, Value: true})
	if err := m.check(t.Context(), in); err != nil {
		t.Fatalf("inference remained blocked after allowing paid inference: %v", err)
	}
	reloaded, _, err := compileSource(m.doc.Policy, m.doc.Secrets.clone())
	if err != nil || !reloaded.AllowPaidInference || reloaded.effectModes("agent", "api", "generate", "pay")["pay"] != "allow" || reloaded.effectModes("agent", "api", "pay")["pay"] != "ask" {
		t.Fatalf("paid inference setting did not persist: %v", err)
	}
	for _, path := range [][]string{{"effects", "pay"}, {"accounts", "api", "effects", "pay"},
		{"identities", "agent", "effects", "pay"}, {"identities", "agent", "accounts", "api", "effects", "pay"}} {
		effectEdit(t, m, sourceChange{Path: path, Value: "off"})
		if err := m.check(t.Context(), in); err == nil || !strings.Contains(err.Error(), "pay effect is set to Deny") {
			t.Fatalf("inference bypassed explicit payment restriction at %v: %v", path, err)
		}
		effectEdit(t, m, sourceChange{Path: path, Delete: true})
	}
	client, peer := net.Pipe()
	defer peer.Close()
	stream := connector.NewStream(t.Context(), client)
	stream.Name = "api"
	defer stream.Close()
	m.mu.Lock()
	m.streams[stream] = key
	m.mu.Unlock()
	effectEdit(t, m, sourceChange{Path: []string{"allow_paid_inference"}, Value: false})
	if stream.Context.Err() == nil {
		t.Fatal("disabling paid inference left an affected stream open")
	}
	effectEdit(t, m, sourceChange{Path: []string{"identities", "agent", "profile"}, Value: true})
	if err := m.check(t.Context(), in); err != nil {
		t.Fatal(err)
	}
	r = m.records[len(m.records)-1]
	if len(r.Requirements) != 1 || r.Requirements[0].ID != "effect.pay" {
		t.Fatalf("disabling paid inference did not restore payment approval: %+v", r)
	}
	effectEdit(t, m, sourceChange{Path: []string{"allow_paid_inference"}, Value: true},
		sourceChange{Path: []string{"identities", "agent", "profile"}, Value: false})
	effectEdit(t, m, sourceChange{Path: []string{"policies", "owner"}, Value: "package sentinel\ndeny contains \"custom denial\""})
	if err := m.check(t.Context(), in); err == nil || !strings.Contains(err.Error(), "custom denial") {
		t.Fatalf("allowing paid inference bypassed custom policy: %v", err)
	}
}

func TestPaidInferenceNewProviders(t *testing.T) {
	m, key := effectMonitor(t)
	effectEdit(t, m, sourceChange{Path: []string{"allow_paid_inference"}, Value: true})
	for _, provider := range []string{"openai", "codex"} {
		t.Run(provider, func(t *testing.T) {
			// The setting also covers providers connected after onboarding.
			effectEdit(t, m, sourceChange{Path: []string{"accounts", provider}, Value: map[string]any{
				"preset": provider, "contents": "anyone", "sends": "anyone", "strangers": false}},
				sourceChange{Path: []string{"identities", "agent", "accounts", provider}, Value: map[string]any{"level": "allow"}})
			request := &web.Request{HTTP: &facts.HTTP{Method: "POST", Origin: "https://api.openai.com", Host: "api.openai.com",
				Path: "/v1/responses", BodyKind: "json", Body: map[string]any{"model": "test-model", "input": "hello"}}}
			ctx, cancel := context.WithTimeout(t.Context(), time.Second)
			defer cancel()
			if err := m.check(ctx, input{Key: key, Connection: provider, Request: request}); err != nil {
				t.Fatalf("paid inference was blocked: %v", err)
			}
			r := m.records[len(m.records)-1]
			if r.Facts.Operation == nil || r.Facts.Operation.ID != "createResponse" || len(r.Requirements) != 0 {
				t.Fatalf("unexpected inference decision: %+v", r)
			}
		})
	}
}
