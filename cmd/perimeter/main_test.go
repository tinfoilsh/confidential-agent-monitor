package main

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"io/fs"
	"os"
	"reflect"
	"slices"
	"testing"
	"time"

	"github.com/tinfoilsh/confidential-agent-monitor/cmd/perimeter/format"
	"github.com/tinfoilsh/confidential-agent-monitor/connector/catalog"
	"github.com/tinfoilsh/confidential-agent-monitor/core"
	"github.com/tinfoilsh/confidential-agent-monitor/core/facts"
	"gocloud.dev/blob"
	"gocloud.dev/blob/memblob"
	"golang.org/x/crypto/ssh"
)

const fixturePreset = `{"title":"Fixture","catalog":{"connection":{"http":{"hosts":["fixture.example"]}}},
"http":{"operations":{"inspect":{"action":"inspect","effects":["read"],"method":"GET","origin":"https://fixture.example","path":"/","scope":{}}}}}`

// start unlocks a Perimeter over bucket; stop ends it as shutdown does.
func start(t *testing.T, bucket *blob.Bucket, key []byte) (s *state, stop func()) {
	t.Helper()
	life, end := context.WithCancel(t.Context())
	s = newState(life, bucket)
	stop = func() { end(); s.close() }
	t.Cleanup(stop)
	if _, err := s.unlock(t.Context(), key, 0); err != nil {
		t.Fatal(err)
	}
	return s, stop
}

func testState(t *testing.T) (*state, string, []byte) {
	t.Helper()
	p, err := catalog.Decode([]byte(fixturePreset))
	if err != nil {
		t.Fatal(err)
	}
	presets, presetDefaults = map[string]*catalog.Preset{"fixture": p}, map[string]json.RawMessage{"fixture": json.RawMessage(`{}`)}
	bucket := memblob.OpenBucket(nil)
	t.Cleanup(func() { bucket.Close() })
	key := make([]byte, format.KeyBytes)
	rand.Read(key)
	s, _ := start(t, bucket, key)
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
	s.writes.Lock()
	err = s.writeSettings(t.Context(), settingsWrite{source: &source})
	s.writes.Unlock()
	if err != nil {
		t.Fatal(err)
	}
	return s, ssh.FingerprintSHA256(pk), key
}

func operationEvent(id string, effects []string, parameters map[string]any) *grant {
	return &grant{kind: kindOperation, label: initialLabel, approved: []string{},
		event: facts.Capture(facts.Observation{Operation: &facts.Operation{ID: id, Action: id, Effects: effects}, Parameters: parameters}, nil)}
}

func TestStandardDecisionsAndCatalogSurviveSettingsUpdate(t *testing.T) {
	s, key, _ := testState(t)
	st := s.settings.Load()
	if got := st.catalog["fixture"].Operations; got == nil || (*got)["inspect"].Action != "inspect" {
		t.Fatal("operation metadata missing")
	}
	before := st.catalogID
	s.writes.Lock()
	err := s.writeSettings(t.Context(), settingsWrite{changes: []format.Change{{Path: []string{"identities", "agent", "connections", "service", "level"}, Value: "allow"}}})
	s.writes.Unlock()
	if err != nil {
		t.Fatal(err)
	}
	st = s.settings.Load()
	if st.catalogID != before {
		t.Fatal("catalog changed on policy-only update")
	}
	p, _ := s.identities.Lookup(key)
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
			got, err := copy.decide(t.Context(), p, "service", operationEvent("op", tc.effects, nil))
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
	s, key, _ := testState(t)
	p, _ := s.identities.Lookup(key)
	watch, err := s.admit(t.Context(), p, core.Request{Connection: "service", Host: "fixture.example", Port: 443, PerMessage: true, Valid: func() bool { return true }})
	if err != nil {
		t.Fatal(err)
	}
	revoked := make(chan struct{}, 1)
	gate, ok := watch(t.Context(), func() {
		select {
		case revoked <- struct{}{}:
		default:
		}
	})
	if !ok {
		t.Fatal("admission lost")
	}
	done := make(chan error, 1)
	go func() {
		done <- gate(t.Context(), facts.Capture(facts.Observation{Operation: &facts.Operation{ID: "write", Action: "write", Effects: []string{"write"}}}, nil))
	}()
	var pending *record
	deadline := time.After(5 * time.Second)
	for pending == nil {
		s.mu.Lock()
		pending, _ = s.records.Find(func(r *record) bool { return r.State == statePending })
		s.mu.Unlock()
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
	owner := withCaller(t.Context(), caller{Name: ownerName, Owner: true})
	if err := s.answerRequest(owner, pending.ID, Answer{Choice: answerOnce}, s.doc.Revision); err != nil {
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
	s.mu.Lock()
	retained := s.findRecord(pending.ID)
	s.mu.Unlock()
	if retained != pending || retained.State != stateApproved {
		t.Fatal("approval record was replaced")
	}
	s.writes.Lock()
	err = s.writeSettings(owner, settingsWrite{changes: []format.Change{{Path: []string{"identities", "agent", "connections", "service", "level"}, Value: "off"}}})
	s.writes.Unlock()
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
	s, key, _ := testState(t)
	changes := []format.Change{{Path: []string{"identities", "agent", "connections", "service", "level"}, Value: "allow"}}
	receipts, err := s.proposePolicy(t.Context(), key, proposalInput{Changes: changes, Reason: "Allow operations"})
	if err != nil {
		t.Fatal(err)
	}
	if len(receipts) != 1 {
		t.Fatal(receipts)
	}
	r := s.findRecord(receipts[0].ID)
	owner := withCaller(t.Context(), caller{Name: ownerName, Owner: true})
	if err := s.answerRequest(owner, r.ID, Answer{Choice: answerOnce}, s.doc.Revision); err != nil {
		t.Fatal(err)
	}
	if s.settings.Load().Access("agent", "service").Level != "allow" || r.State != stateApproved {
		t.Fatal("proposal not committed")
	}
	// An audit envelope remains complete after its entry leaves the live window.
	s.mu.Lock()
	for range maxRecords {
		s.addRecord(&record{Facts: json.RawMessage(`{}`)})
	}
	if s.findRecord(r.ID) != nil {
		t.Fatal("settled record outlived retention")
	}
	s.settleRecord(r, nil)
	s.mu.Unlock()
	s.audit.Flush()
	page, err := s.readAuditPage(t.Context(), "")
	if err != nil {
		t.Fatal(err)
	}
	for _, summary := range page.Records {
		if summary.ID == receipts[0].ID {
			stored, err := s.readAuditRecord(t.Context(), summary.Segment, receipts[0].ID)
			if err != nil {
				t.Fatal(err)
			}
			if !reflect.DeepEqual(stored.Changes, changes) {
				t.Fatalf("changes lost: %+v", stored)
			}
			raw, _ := json.Marshal(stored)
			var fields map[string]any
			json.Unmarshal(raw, &fields)
			if fields["id"] != receipts[0].ID || fields["changes"] == nil || fields["Record"] != nil {
				t.Fatalf("wire shape changed: %s", raw)
			}
			return
		}
	}
	t.Fatal("proposal missing from audit")
}

func TestSavedApprovalSurvivesEncryptedReload(t *testing.T) {
	s, key, ownerKey := testState(t)
	principal, _ := s.identities.Lookup(key)
	resource := func(value string) *grant {
		return operationEvent("write", []string{"write"}, map[string]any{"resource": json.Number(value)})
	}
	decided, err := s.settings.Load().decide(t.Context(), principal, "service", resource("9007199254740993"))
	if err != nil {
		t.Fatal(err)
	}
	s.mu.Lock()
	r := s.addRecord(decided)
	r.State = stateExpired
	s.mu.Unlock()
	owner := withCaller(t.Context(), caller{Name: ownerName, Owner: true})
	if err := s.answerRequest(owner, r.ID, Answer{Choice: answerSave}, s.doc.Revision); err != nil {
		t.Fatal(err)
	}
	if r.State != stateRefused || len(r.Deny) != 1 {
		t.Fatal("expired approval should require a retry")
	}
	restarted, _ := start(t, s.bucket, ownerKey)
	got, err := restarted.settings.Load().decide(t.Context(), principal, "service", resource("9007199254740993"))
	if err != nil {
		t.Fatal(err)
	}
	if len(got.Deny) != 0 || len(got.Requirements) != 0 {
		t.Fatalf("saved approval lost: %+v", got.Decision)
	}
	// A nearby resource must still need its own approval, without float rounding.
	got, err = restarted.settings.Load().decide(t.Context(), principal, "service", resource("9007199254740992"))
	if err != nil {
		t.Fatal(err)
	}
	if len(got.Requirements) == 0 {
		t.Fatal("saved approval covered a different resource")
	}
}

func TestAttestedHTTPProjectsCatalogWithoutOpeningTransport(t *testing.T) {
	shipped, err := fs.Sub(shippedPresets, "presets")
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"tinfoil", "tinfoil_websearch"} {
		raw, err := fs.ReadFile(shipped, name+".json")
		if err != nil {
			t.Fatal(err)
		}
		p, err := catalog.Decode(raw)
		if err != nil {
			t.Fatal(err)
		}
		cfg := p.Catalog.Connection["tinfoil"]
		if cfg == nil {
			continue
		}
		parsed, err := parseConnection(ConnectionSpec{Name: "inference", Protocol: "tinfoil", Config: cfg, Definition: p.Source, Options: json.RawMessage(`{}`)})
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		var old struct {
			HTTP struct {
				Operations map[string]operationSummary `json:"operations"`
			} `json:"http"`
		}
		if err := json.Unmarshal(p.Source, &old); err != nil {
			t.Fatal(err)
		}
		if !reflect.DeepEqual(parsed.operations, old.HTTP.Operations) {
			t.Fatalf("%s: operations changed", name)
		}
	}
}

// Main selects every shipped preset's deployed defaults.
func TestShippedPresetDefaultsMatchDeployedCatalog(t *testing.T) {
	raw, err := os.ReadFile("testdata/preset-defaults.json")
	if err != nil {
		t.Fatal(err)
	}
	var deployed map[string]json.RawMessage
	if err := json.Unmarshal(raw, &deployed); err != nil {
		t.Fatal(err)
	}
	loaded, defaults, err := loadPresets(nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(loaded) != len(deployed) {
		t.Fatalf("%d presets, %d deployed", len(loaded), len(deployed))
	}
	for name, want := range deployed {
		var got, expected connectionDefaults
		json.Unmarshal(defaults[name], &got)
		json.Unmarshal(want, &expected)
		if got != expected {
			t.Errorf("%s: defaults %s, deployed %s", name, defaults[name], want)
		}
	}
}

// Connectors capture raw observations; main binds the sends and observes hints each protocol had.
func TestObservationsBindProtocolHints(t *testing.T) {
	p, err := catalog.Decode([]byte(fixturePreset))
	if err != nil {
		t.Fatal(err)
	}
	presets = map[string]*catalog.Preset{"fixture": p}
	st := &settings{Config: &Config{Connections: map[string]Connection{}}, connections: map[string]*installed{}}
	for name, spec := range map[string]ConnectionSpec{
		"db":   {Protocol: "tcp", Config: json.RawMessage(`{"hosts":["db.example"]}`)},
		"web":  {Protocol: "http", Config: json.RawMessage(`{"hosts":["fixture.example"]}`), Definition: json.RawMessage(fixturePreset), Options: json.RawMessage(`{}`)},
		"mail": {Protocol: "smtp", Config: json.RawMessage(`{"url":"smtps://mail.example"}`), Options: json.RawMessage(`{"address":"me@example.com"}`)},
	} {
		parsed, err := parseConnection(spec)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		st.Connections[name], st.connections[name] = Connection{Preset: "fixture"}, &installed{parsed: parsed}
	}
	for _, tc := range []struct {
		name, connection string
		observation      facts.Observation
		sends            string
		observes         format.Label
		effects          []string
		invalid          bool
	}{
		{name: "tcp", connection: "db", observation: facts.Observation{Operation: &facts.Operation{Action: "connect"}}, sends: "anyone", observes: format.Label{Audience: "me", Trust: "untrusted"}},
		{name: "websocket receive", connection: "web", sends: "me", effects: []string{"read"}, observation: facts.Observation{
			Operation: &facts.Operation{ID: "websocket.receive", Action: "receive"}, Details: map[string]any{"http": map[string]any{"websocket": true, "method": ""}}}},
		{name: "unreviewed websocket", connection: "web", invalid: true, observation: facts.Observation{Details: map[string]any{"http": map[string]any{"websocket": true, "method": "GET"}}}},
		{name: "mail to self", connection: "mail", sends: sendsConnection, observation: facts.Observation{Details: map[string]any{"smtp": map[string]any{"to": []string{"ME@example.com"}}}}},
		{name: "mail to others", connection: "mail", sends: "anyone", observation: facts.Observation{Details: map[string]any{"smtp": map[string]any{"to": []string{"me@example.com", "you@example.com"}}}}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f, err := st.observe(tc.connection, facts.Capture(tc.observation, nil))
			if (err != nil) != tc.invalid {
				t.Fatalf("invalid: %v", err)
			}
			if f.Context.Sends != tc.sends || !reflect.DeepEqual(f.Context.Observes, tc.observes) {
				t.Fatalf("context: %+v", f.Context)
			}
			if tc.effects != nil && (f.Operation == nil || !slices.Equal(f.Operation.Effects, tc.effects)) {
				t.Fatalf("operation: %+v", f.Operation)
			}
		})
	}
}

func event(id string, effects ...string) facts.Event {
	return facts.Capture(facts.Observation{Operation: &facts.Operation{ID: id, Action: id, Effects: effects}}, nil)
}

func edit(t *testing.T, s *state, changes ...format.Change) {
	t.Helper()
	s.writes.Lock()
	defer s.writes.Unlock()
	if err := s.writeSettings(t.Context(), settingsWrite{changes: changes}); err != nil {
		t.Fatal(err)
	}
}

func set(value any, path ...string) format.Change {
	return format.Change{Path: path, Value: value}
}

// admitStream admits one stream of key to the fixture service; ended receives each revocation.
func admitStream(t *testing.T, s *state, key string, perMessage bool) (gate core.Gate, ended chan struct{}) {
	t.Helper()
	p, _ := s.identities.Lookup(key)
	watch, err := s.admit(t.Context(), p, core.Request{Connection: "service", Host: "fixture.example", Port: 443, PerMessage: perMessage, Valid: func() bool { return true }})
	if err != nil {
		t.Fatal(err)
	}
	ended = make(chan struct{}, 8)
	gate, ok := watch(t.Context(), func() { ended <- struct{}{} })
	if !ok {
		t.Fatal("admission lost")
	}
	return gate, ended
}

func revoked(ended chan struct{}) bool {
	select {
	case <-ended:
		return true
	case <-time.After(100 * time.Millisecond):
		return false
	}
}

// Reading a private, untrusted service lowers the agent's label.
func privateService(t *testing.T, s *state) {
	edit(t, s, set("me", "connections", "service", "contents"), set(true, "connections", "service", "strangers"))
}

func TestFailedLabelWriteRefusesOperation(t *testing.T) {
	s, key, _ := testState(t)
	privateService(t, s)
	gate, _ := admitStream(t, s, key, true)
	generation := s.doc.Generation
	s.bucket.Close()
	if err := gate(t.Context(), event("read", "read")); err == nil {
		t.Fatal("an operation ran without its label persisted")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	r, _ := s.records.Find(func(r *record) bool { op := summarize(r).Facts.Operation; return op != nil && op.ID == "read" })
	if r == nil || r.State != stateRefused || s.label(key).Audience != initialLabel.Audience || s.doc.Generation != generation {
		t.Fatalf("a failed write published state: %+v label %+v", r, s.label(key))
	}
}

func TestRevocationFollowsLabelsAndCapabilities(t *testing.T) {
	s, key, _ := testState(t)
	privateService(t, s)
	edit(t, s, set("allow", "identities", "agent", "connections", "service", "level"))
	_, opaque := admitStream(t, s, key, false)
	gate, perMessage := admitStream(t, s, key, true)
	if err := gate(t.Context(), event("read", "read")); err != nil {
		t.Fatal(err)
	}
	if !revoked(opaque) || revoked(perMessage) {
		t.Fatal("a label change must end only the key's opaque streams")
	}
	s.mu.Lock()
	err := s.relabel(t.Context(), key, initialLabel, nil)
	s.mu.Unlock()
	if err != nil || !revoked(perMessage) {
		t.Fatalf("an owner reset must end every stream: %v", err)
	}

	edit(t, s, set(true, "identities", "agent", "routes"))
	held, release, ok := s.hold(t.Context(), key, capabilityRoutes)
	if !ok {
		t.Fatal("routes capability refused")
	}
	defer release()
	edit(t, s, set(false, "identities", "agent", "routes"))
	select {
	case <-held.Done():
	case <-time.After(5 * time.Second):
		t.Fatal("a capability outlived the setting that granted it")
	}
}

func TestPendingRequestFollowsSettingsChange(t *testing.T) {
	s, key, _ := testState(t)
	installed := s.settings.Load().connections["service"]
	for _, tc := range []struct {
		level   string
		allowed bool
	}{{"allow", true}, {"off", false}} {
		edit(t, s, set("ask", "identities", "agent", "connections", "service", "level"))
		gate, ended := admitStream(t, s, key, true)
		done := make(chan error, 1)
		go func() { done <- gate(t.Context(), event("write", "write")) }()
		deadline := time.After(5 * time.Second)
		for pending := (*record)(nil); pending == nil; {
			s.mu.Lock()
			pending, _ = s.records.Find(func(r *record) bool { return r.State == statePending })
			s.mu.Unlock()
			select {
			case <-deadline:
				t.Fatal("no pending approval")
			case <-time.After(time.Millisecond):
			}
		}
		edit(t, s, set(tc.level, "identities", "agent", "connections", "service", "level"))
		select {
		case err := <-done:
			if (err == nil) != tc.allowed {
				t.Fatalf("level %s: %v", tc.level, err)
			}
		case <-deadline:
			t.Fatalf("level %s did not re-decide the waiting request", tc.level)
		}
		if revoked(ended) == tc.allowed {
			t.Fatalf("level %s: wrong revocation", tc.level)
		}
	}
	if s.settings.Load().connections["service"] != installed {
		t.Fatal("an access change restaged an unchanged connection")
	}
}

func TestCredentialChangeRefusesStaleRefresh(t *testing.T) {
	s, _, _ := testState(t)
	edit(t, s, set([]any{map[string]any{"value": "TOKEN", "origin": "https://fixture.example", "header": "Authorization", "prefix": "Bearer "}},
		"connections", "service", "http", "slots"))
	id := format.SecretID{Connection: "service", Name: "TOKEN"}
	write := func(raw string) {
		s.writes.Lock()
		defer s.writes.Unlock()
		if err := s.writeSettings(t.Context(), settingsWrite{credentials: format.Secrets{"service": {"TOKEN": json.RawMessage(raw)}}}); err != nil {
			t.Fatal(err)
		}
	}
	write(`"one"`)
	stale, before := s.settings.Load().connections["service"].secrets["TOKEN"], s.doc.Credentials.Get(id)
	write(`"two"`)
	if err := s.replaceValue(t.Context(), id, stale, before, json.RawMessage(`"three"`)); err != errCredentialChanged {
		t.Fatalf("a stale refresh was saved: %v", err)
	}
	if got := string(s.doc.Credentials.Get(id)); got != `"two"` {
		t.Fatalf("stored credential %s", got)
	}
}

func TestRollbackAndEnrollmentRestoration(t *testing.T) {
	s, _, ownerKey := testState(t)
	generation := s.doc.Generation
	if !s.stale(generation+1) || s.stale(generation) {
		t.Fatal("stale generation check")
	}
	locked := newState(t.Context(), s.bucket)
	if _, err := locked.unlock(t.Context(), ownerKey, generation+1); err == nil {
		t.Fatal("unlocked state older than a saved generation")
	}
	public, _, _ := ed25519.GenerateKey(rand.Reader)
	pk, _ := ssh.NewPublicKey(public)
	device := map[string]identityEnrollment{"device": {Key: string(ssh.MarshalAuthorizedKey(pk))}}
	if err := s.enroll(t.Context(), device); err != nil {
		t.Fatal(err)
	}
	edit(t, s, format.Change{Path: []string{"identities", "device"}, Delete: true})
	if err := s.enroll(t.Context(), device); err == nil {
		t.Fatal("a removed identity returned without restore")
	}
	restore := device["device"]
	restore.Restore = true
	if err := s.enroll(t.Context(), map[string]identityEnrollment{"device": restore}); err != nil {
		t.Fatal(err)
	}
	routes := device["device"]
	routes.Operator = true
	if err := s.enroll(t.Context(), map[string]identityEnrollment{"device": routes}); err == nil {
		t.Fatal("route access returned without restore")
	}
	routes.Restore = true
	if err := s.enroll(t.Context(), map[string]identityEnrollment{"device": routes}); err != nil || !s.settings.Load().Identities["device"].Operator {
		t.Fatalf("route access not restored: %v", err)
	}
}
