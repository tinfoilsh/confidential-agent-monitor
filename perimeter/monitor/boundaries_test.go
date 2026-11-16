package monitor

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"reflect"
	"slices"
	"testing"
	"time"

	"github.com/tinfoilsh/confidential-agent-monitor/connector"
	"github.com/tinfoilsh/confidential-agent-monitor/core/facts"
	"github.com/tinfoilsh/confidential-agent-monitor/perimeter/internal/authz"
	"github.com/tinfoilsh/confidential-agent-monitor/perimeter/internal/config"
	"github.com/tinfoilsh/confidential-agent-monitor/perimeter/policy/standard"
	"github.com/tinfoilsh/confidential-agent-monitor/perimeter/presets"
	"gocloud.dev/blob/memblob"
	"golang.org/x/crypto/ssh"
)

func testMonitor(t *testing.T) (*Monitor, string, []byte) {
	t.Helper()
	v := standard.Vocabulary()
	p, err := presets.Decode([]byte(`{"title":"Fixture","catalog":{"defaults":{},"connection":{"fixture":{}}}}`), v)
	if err != nil {
		t.Fatal(err)
	}
	bucket := memblob.OpenBucket(nil)
	t.Cleanup(func() { bucket.Close() })
	m, err := New(Options{Bucket: bucket, Presets: presets.Set{"fixture": p}, Vocabulary: v, PolicyLibrary: standard.Library(), Connectors: map[string]connector.Kind{"fixture": {
		Parse: func(source connector.Setup) (connector.Prepared, error) {
			return connector.Prepared{Operations: map[string]facts.OperationSummary{"inspect": {Action: "inspect", Effects: []string{"read"}}}}, nil
		},
		Open: func(context.Context, connector.Prepared, map[string]connector.Secret, *connector.Env) (connector.Handler, error) {
			return connector.HandlerFunc(func(*connector.Stream) {}), nil
		},
	}}})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(m.Close)
	key := make([]byte, 32)
	rand.Read(key)
	if err := m.Unlock(t.Context(), key); err != nil {
		t.Fatal(err)
	}
	public, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	pk, err := ssh.NewPublicKey(public)
	if err != nil {
		t.Fatal(err)
	}
	source := fmt.Sprintf(`[connections.service]
preset="fixture"
contents="anyone"
sends="anyone"
[identities.agent]
key=%q
[identities.agent.connections.service]
level="ask"
`, string(ssh.MarshalAuthorizedKey(pk)))
	m.writes.Lock()
	err = m.writeSettings(t.Context(), settingsWrite{source: &source})
	m.writes.Unlock()
	if err != nil {
		t.Fatal(err)
	}
	return m, ssh.FingerprintSHA256(pk), key
}

func TestStandardDecisionsAndCatalogSurviveSettingsUpdate(t *testing.T) {
	m, key, _ := testMonitor(t)
	st := m.settings.Load()
	if got := st.Catalog["fixture"].Operations; got == nil || (*got)["inspect"].Action != "inspect" {
		t.Fatal("non-HTTP metadata missing")
	}
	before := st.CatalogID
	m.writes.Lock()
	err := m.writeSettings(t.Context(), settingsWrite{changes: []config.Change{{Path: []string{"identities", "agent", "connections", "service", "level"}, Value: "allow"}}})
	m.writes.Unlock()
	if err != nil {
		t.Fatal(err)
	}
	st = m.settings.Load()
	if st.CatalogID != before {
		t.Fatal("catalog changed on policy-only update")
	}
	p, _ := m.identities.Lookup(key)
	for _, tc := range []struct {
		name         string
		effects      []string
		paid         bool
		pay          string
		deny         bool
		requirements []string
	}{
		{name: "read", effects: []string{"read"}},
		{name: "payment", effects: []string{"pay"}, requirements: []string{"effect.pay"}},
		{name: "inference", effects: []string{"generate", "pay"}, paid: true},
		{name: "explicit ask", effects: []string{"generate", "pay"}, paid: true, pay: "ask", requirements: []string{"effect.pay"}},
		{name: "explicit deny", effects: []string{"generate", "pay"}, paid: true, pay: "off", deny: true},
		{name: "publish", effects: []string{"publish"}, requirements: []string{"effect.publish"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			copy := *st
			cfg := *st.Config
			copy.Config = &cfg
			cfg.AllowPaidInference = tc.paid
			if tc.pay != "" {
				cfg.Effects = map[string]string{"pay": tc.pay}
			}
			q := authz.Query{Principal: p, Connection: "service", Kind: facts.KindOperation, Label: m.vocabulary.Initial, Event: facts.Capture(facts.Facts{Operation: &facts.Operation{ID: "op", Action: "op", Effects: tc.effects}}, nil)}
			got, err := copy.Decide(t.Context(), q)
			if err != nil {
				t.Fatal(err)
			}
			if (len(got.Deny) > 0) != tc.deny {
				t.Fatalf("deny: %+v", got.Decision)
			}
			var ids []string
			for _, req := range got.Requirements {
				ids = append(ids, req.ID)
			}
			slices.Sort(ids)
			if !reflect.DeepEqual(ids, tc.requirements) {
				t.Fatalf("requirements: %v", ids)
			}
		})
	}
}

func TestApprovalAndRevocationUseOneRecord(t *testing.T) {
	m, key, _ := testMonitor(t)
	admitted := &authz.Admission{Key: key, Connection: "service", PerMessage: true, Valid: func() bool { return true }}
	admit := facts.Capture(facts.Facts{Operation: &facts.Operation{ID: "session", Action: "session", Effects: []string{"session"}}}, nil)
	if err := m.gate.Admit(t.Context(), admitted, admit); err != nil {
		t.Fatal(err)
	}
	revoked := make(chan struct{}, 1)
	m.mu.Lock()
	gate, ok := m.gate.Watch(t.Context(), func() {
		select {
		case revoked <- struct{}{}:
		default:
		}
	}, admitted)
	m.mu.Unlock()
	if !ok {
		t.Fatal("admission lost")
	}
	done := make(chan error, 1)
	go func() {
		done <- gate(t.Context(), facts.Capture(facts.Facts{Operation: &facts.Operation{ID: "write", Action: "write", Effects: []string{"write"}}}, nil))
	}()
	var pending *record
	deadline := time.After(5 * time.Second)
	for pending == nil {
		m.mu.Lock()
		for _, r := range m.records {
			if r.State == authz.StatePending {
				pending = r
				break
			}
		}
		m.mu.Unlock()
		if pending == nil {
			select {
			case err := <-done:
				t.Fatalf("did not wait: %v", err)
			case <-deadline:
				t.Fatal("no pending approval")
			case <-time.After(time.Millisecond):
			}
		}
	}
	owner := WithCaller(t.Context(), Caller{Name: Owner, Owner: true})
	if err := m.answerRequest(owner, pending.ID, authz.Answer{Choice: authz.AnswerOnce}, m.store.Doc.Revision); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-deadline:
		t.Fatal("approval did not wake gate")
	}
	m.mu.Lock()
	retained := m.findRecord(pending.ID)
	m.mu.Unlock()
	if retained != pending || retained.State != authz.StateApproved {
		t.Fatal("approval record was replaced")
	}
	m.writes.Lock()
	err := m.writeSettings(owner, settingsWrite{changes: []config.Change{{Path: []string{"identities", "agent", "connections", "service", "level"}, Value: "off"}}})
	m.writes.Unlock()
	if err != nil {
		t.Fatal(err)
	}
	select {
	case <-revoked:
	case <-deadline:
		t.Fatal("policy did not revoke stream")
	}
}

func TestProposalCommitAndAuditKeepChanges(t *testing.T) {
	m, key, _ := testMonitor(t)
	changes := []config.Change{{Path: []string{"identities", "agent", "connections", "service", "level"}, Value: "allow"}}
	receipts, err := m.proposePolicy(t.Context(), key, proposalInput{Changes: changes, Reason: "Allow operations"})
	if err != nil {
		t.Fatal(err)
	}
	if len(receipts) != 1 {
		t.Fatal(receipts)
	}
	r := m.findRecord(receipts[0].ID)
	owner := WithCaller(t.Context(), Caller{Name: Owner, Owner: true})
	if err := m.answerRequest(owner, r.ID, authz.Answer{Choice: authz.AnswerOnce}, m.store.Doc.Revision); err != nil {
		t.Fatal(err)
	}
	if m.settings.Load().Access("agent", "service").Level != "allow" || r.State != authz.StateApproved {
		t.Fatal("proposal not committed")
	}
	// An audit envelope remains complete after its entry leaves the live window.
	m.records = nil
	m.settleRecord(r, nil)
	m.audit.Flush()
	page, err := m.readAuditPage(t.Context(), "")
	if err != nil {
		t.Fatal(err)
	}
	for _, summary := range page.Records {
		if summary.ID == r.ID {
			stored, err := m.readAuditRecord(t.Context(), summary.Segment, r.ID)
			if err != nil {
				t.Fatal(err)
			}
			if !reflect.DeepEqual(stored.Changes, changes) {
				t.Fatalf("changes lost: %+v", stored)
			}
			raw, _ := json.Marshal(stored)
			var fields map[string]any
			json.Unmarshal(raw, &fields)
			if fields["id"] != r.ID || fields["changes"] == nil || fields["Record"] != nil {
				t.Fatalf("wire shape changed: %s", raw)
			}
			return
		}
	}
	t.Fatal("proposal missing from audit")
}

func TestSavedApprovalSurvivesEncryptedReload(t *testing.T) {
	m, key, ownerKey := testMonitor(t)
	principal, _ := m.identities.Lookup(key)
	q := authz.Query{Principal: principal, Connection: "service", Kind: facts.KindOperation, Label: m.vocabulary.Initial, Event: facts.Capture(facts.Facts{Operation: &facts.Operation{ID: "write", Action: "write", Effects: []string{"write"}}, Parameters: map[string]any{"resource": json.Number("9007199254740993")}}, nil)}
	decided, err := m.settings.Load().Decide(t.Context(), q)
	if err != nil {
		t.Fatal(err)
	}
	r := m.addRecord(&record{Record: decided})
	r.State = authz.StateExpired
	owner := WithCaller(t.Context(), Caller{Name: Owner, Owner: true})
	if err := m.answerRequest(owner, r.ID, authz.Answer{Choice: authz.AnswerSave}, m.store.Doc.Revision); err != nil {
		t.Fatal(err)
	}
	if r.State != authz.StateRefused || len(r.Deny) != 1 {
		t.Fatal("expired approval should require a retry")
	}
	m.Close()
	restarted, err := New(Options{Bucket: m.store.Bucket, Presets: m.presets, Vocabulary: standard.Vocabulary(), PolicyLibrary: standard.Library(), Connectors: m.kinds})
	if err != nil {
		t.Fatal(err)
	}
	defer restarted.Close()
	if err := restarted.Unlock(t.Context(), ownerKey); err != nil {
		t.Fatal(err)
	}
	got, err := restarted.settings.Load().Decide(t.Context(), q)
	if err != nil {
		t.Fatal(err)
	}
	if len(got.Deny) != 0 || len(got.Requirements) != 0 {
		t.Fatalf("saved approval lost: %+v", got.Decision)
	}
	// A nearby resource must still need its own approval, without float rounding.
	q.Event = facts.Capture(facts.Facts{Operation: &facts.Operation{ID: "write", Action: "write", Effects: []string{"write"}}, Parameters: map[string]any{"resource": json.Number("9007199254740992")}}, nil)
	got, err = restarted.settings.Load().Decide(t.Context(), q)
	if err != nil {
		t.Fatal(err)
	}
	if len(got.Requirements) == 0 {
		t.Fatal("saved approval covered a different resource")
	}
}
