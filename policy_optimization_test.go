package main

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"net/http"
	"net/http/httptest"
	"reflect"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/open-policy-agent/opa/v1/ast"
	"github.com/tinfoilsh/monitor/connector"
	"github.com/tinfoilsh/monitor/connector/web"
	"github.com/tinfoilsh/monitor/facts"
)

func TestPrivatePatternValidation(t *testing.T) {
	for _, pattern := range []string{"owner/[", "owner/[abc"} {
		t.Run(pattern, func(t *testing.T) {
			raw := fmt.Sprintf(`{"accounts":{"github":{"preset":"github","contents":"me","sends":"me","policy_options":{"private":[%q]}}}}`, pattern)
			if _, _, err := parse([]byte(raw)); err == nil || !strings.Contains(err.Error(), "account github") || !strings.Contains(err.Error(), pattern) {
				t.Fatalf("invalid pattern was not rejected with its account and pattern: %v", err)
			}
			cfg := &config{Accounts: map[string]account{"github": {PolicyOptions: connector.PolicyOptions{Private: []string{pattern}}}}}
			if _, err := compileTestPolicy(t.Context(), cfg); err == nil {
				t.Fatal("programmatic configuration accepted an invalid private pattern")
			}
		})
	}
}

func TestInvalidPrivatePatternPatchPreservesVisibility(t *testing.T) {
	f := newMonitorFixture(t)
	if err := f.patch(t, `{"accounts":{"github":{"preset":"github","contents":"me","sends":"me","policy_options":{"private":["owner/*"]}}}}`); err != nil {
		t.Fatal(err)
	}
	before, st := f.m.doc, f.m.live.Load()
	err := f.patch(t, `{"accounts":{"github":{"policy_options":{"private":["owner/["]}}}}`)
	if err == nil || !strings.Contains(err.Error(), "owner/[") {
		t.Fatalf("invalid pattern patch was accepted: %v", err)
	}
	if f.m.live.Load() != st || !reflect.DeepEqual(f.m.doc, before) || !sourceEqualJSON(f.disk(t), before) {
		t.Fatal("rejected patch changed the active or stored configuration")
	}
	d, err := st.decideFixture(t.Context(), fixtureInput{Account: fixtureAccount(namedAccount{Name: "github", account: st.cfg.Accounts["github"]}),
		Access: access{Level: "allow"}, Label: cleanLabel,
		Request: &web.Request{HTTP: &facts.HTTP{Method: "GET", Origin: "https://api.github.com", Path: "/repos/owner/repo", BodyKind: "none", Headers: map[string][]string{"X-Github-Api-Version": {"2022-11-28"}}}},
	})
	if err != nil || d.Facts.Operation == nil || len(d.Deny) != 0 || d.Next.Audience != "me" {
		t.Fatalf("private resource lost its label after rejected patch: %+v, %v", d, err)
	}
}

func TestOwnerPolicyOnlyAddsDenials(t *testing.T) {
	for _, owner := range []struct {
		name, source string
		data         map[string]any
		extra        string
	}{
		{name: "none"},
		{name: "unrelated data", data: map[string]any{"note": "configured"}},
		{name: "undefined deny", source: "package example\nhelper := true"},
		{name: "nonmatching deny", source: `package sentinel
 deny contains "other account" if input.facts.account == "other"`},
		{name: "empty deny", source: "package sentinel\ndeny := []"},
		{name: "additional deny", extra: "owner denial", source: `package sentinel
 deny contains "owner denial"
 deny contains "this agent may not do this on the account" if input.authorization.access.level == "off"`},
		{name: "static deny", extra: "owner denial", data: map[string]any{"sentinel": map[string]any{"deny": []any{"owner denial", "owner denial"}}}},
	} {
		t.Run(owner.name, func(t *testing.T) {
			cfg := &config{Lattices: latticeOptions{true, true}, Data: owner.data}
			if owner.source != "" {
				cfg.Policies = map[string]string{"owner.rego": owner.source}
			}
			q, err := compileTestPolicy(t.Context(), cfg)
			if err != nil {
				t.Fatal(err)
			}
			for _, tc := range []struct {
				name, level string
				kind        facts.Kind
				label       facts.Label
				deny, gaps  []string
				observes    string
			}{
				{"allowed", "allow", facts.KindOperation, cleanLabel, nil, nil, "team"},
				{"access denied", "off", facts.KindOperation, cleanLabel, []string{"this agent may not do this on the account"}, []string{"ask"}, "team"},
				{"approval gaps", "ask", facts.KindOperation, facts.Label{Audience: "me", Trust: "untrusted"}, nil, []string{"ask", "audience", "trust"}, "me"},
				{"admission", "allow", facts.KindAdmission, facts.Label{Audience: "me", Trust: "untrusted"}, nil, nil, "me"},
			} {
				t.Run(tc.name, func(t *testing.T) {
					f := facts.Facts{Kind: tc.kind, Operation: &facts.Operation{Action: "send", Effects: []string{"send"}},
						Context: facts.Context{}}
					if tc.kind == facts.KindAdmission {
						f.Operation = &facts.Operation{Action: "session.admit", Effects: []string{"session"}}
					}
					in := fixtureInput{Account: fixtureAccount(namedAccount{Name: "account", account: account{Contents: "team", Sends: "anyone"}}),
						Access: access{Level: tc.level}, Label: tc.label, Request: fixedDescription{f}}
					d, err := q.decideFixture(t.Context(), in)
					if err != nil {
						t.Fatal(err)
					}
					want := slices.Clone(tc.deny)
					if owner.extra != "" {
						want = append(want, owner.extra)
					}
					slices.Sort(want)
					if !slices.Equal(d.Deny, want) || !slices.Equal(d.Requirements.IDs(), tc.gaps) || d.Next.Audience != tc.observes || d.Next.Trust != tc.label.Trust {
						t.Fatalf("deny=%v gaps=%v next=%+v; want deny=%v gaps=%v audience=%s trust=%s", d.Deny, d.Requirements.IDs(), d.Next, want, tc.gaps, tc.observes, tc.label.Trust)
					}
				})
			}
		})
	}
}

func TestOwnerPolicyReadsApprovalGaps(t *testing.T) {
	cfg := &config{Lattices: latticeOptions{true, true}, Policies: map[string]string{"owner.rego": `package sentinel
 deny contains "review restricted observation" if {
  "ask" in data.monitor.gaps
  input.facts.context.observes.audience == "team"
  input.facts.context.observes.trust == "trusted"
  input.authorization.access.level == "ask"
  input.facts.operation.effects[_] == "write"
  data.lattices.confidentiality
 }`}}
	q, err := compileTestPolicy(t.Context(), cfg)
	if err != nil {
		t.Fatal(err)
	}
	in := fixtureInput{Account: fixtureAccount(namedAccount{Name: "account", account: account{Contents: "team", Sends: "me"}}),
		Access: access{Level: "ask"}, Label: cleanLabel,
		Request: fixedDescription{facts.Facts{Operation: &facts.Operation{Action: "write", Effects: []string{"write"}}}}}
	d, err := q.decideFixture(t.Context(), in)
	if err != nil || !slices.Equal(d.Deny, []string{"review restricted observation"}) || !slices.Equal(d.Requirements.IDs(), []string{"ask"}) || d.Next.Audience != "team" {
		t.Fatalf("approval gaps and observations were not exposed to owner policy: %+v, %v", d, err)
	}
}

func TestOwnerPolicyErrorsRefuse(t *testing.T) {
	for _, source := range []string{
		`deny := true`, `deny := "blocked"`, `deny := null`, `deny := {"blocked": true}`,
		`deny := ["blocked", 123]`, `deny := [null]`,
		`deny contains "blocked" if to_number(input.facts.parameters.value) > 0`,
	} {
		t.Run(source, func(t *testing.T) {
			q, err := compileTestPolicy(t.Context(), &config{Policies: map[string]string{"owner.rego": "package sentinel\n" + source}})
			if err != nil {
				t.Fatal(err)
			}
			in := fixtureInput{Account: fixtureAccount(namedAccount{Name: "account", account: account{Contents: "team", Sends: "me"}}),
				Access: access{Level: "allow"}, Label: cleanLabel,
				Request: fixedDescription{facts.Facts{Operation: &facts.Operation{Action: "read", Effects: []string{"read"}}, Parameters: map[string]any{"value": "not a number"}}}}
			d, err := q.decideFixture(t.Context(), in)
			if err == nil && !slices.Contains(d.Deny, "owner policy deny must be a set or array of strings") {
				t.Fatalf("invalid owner denial did not refuse: %+v, %v", d, err)
			}
		})
	}
}

func TestSavedApprovalCannotWaiveOwnerDenial(t *testing.T) {
	q, err := compileTestPolicy(t.Context(), &config{Policies: map[string]string{"owner.rego": "package sentinel\ndeny contains \"owner denial\""}})
	if err != nil {
		t.Fatal(err)
	}
	in := fixtureInput{Account: fixtureAccount(namedAccount{Name: "account", account: account{Contents: "team", Sends: "me"}}),
		Access: access{Level: "ask"}, Label: cleanLabel,
		Request: fixedDescription{facts.Facts{Operation: &facts.Operation{Action: "write", Effects: []string{"write"}}}}}
	d, err := q.decideFixture(t.Context(), in)
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(d.Requirements.IDs(), []string{"ask"}) {
		t.Fatalf("expected approval gap: %+v", d)
	}
	in.Rules = map[string]rule{"0": {Account: d.Facts.Account, Action: d.Facts.Operation.Action, Operation: d.Facts.Operation.ID, Definition: d.Definition, Scope: d.Grant, Requirements: d.Requirements}}
	d, err = q.decideFixture(t.Context(), in)
	if err != nil || len(d.Requirements.IDs()) != 0 || !slices.Equal(d.Deny, []string{"owner denial"}) {
		t.Fatalf("saved approval changed owner denial: %+v, %v", d, err)
	}
}

func TestCustomDataUsesRego(t *testing.T) {
	q, err := compileTestPolicy(t.Context(), &config{Data: map[string]any{"sentinel": map[string]any{"deny": []any{"blocked by data"}}}})
	if err != nil {
		t.Fatal(err)
	}
	in := fixtureInput{Account: fixtureAccount(namedAccount{Name: "account", account: account{Contents: "team", Sends: "me"}}), Access: access{Level: "allow"}, Label: cleanLabel,
		Request: fixedDescription{facts.Facts{Operation: &facts.Operation{Action: "read", Effects: []string{"read"}}}}}
	d, err := q.decideFixture(t.Context(), in)
	if err != nil || !slices.Contains(d.Deny, "blocked by data") {
		t.Fatalf("%+v %v", d, err)
	}
}

func TestOwnerPolicyCannotReplaceMonitorRules(t *testing.T) {
	for _, source := range []string{
		`package monitor
decision := {"deny": [], "gaps": []}`,
		`package monitor.labels
flows_to(from, to) := true`,
		`package lattices
confidentiality := false`,
	} {
		if _, err := compileTestPolicy(t.Context(), &config{Policies: map[string]string{"owner.rego": source}}); err == nil || !strings.Contains(err.Error(), "reserved") {
			t.Fatalf("accepted a replacement monitor rule: %v", err)
		}
	}
	for _, name := range []string{"monitor", "lattices"} {
		data := map[string]any{name: map[string]any{"decision": map[string]any{"deny": []any{}, "gaps": []any{}}}}
		if _, err := compileTestPolicy(t.Context(), &config{Data: data}); err == nil {
			t.Fatalf("accepted reserved data.%s", name)
		}
		raw, _ := json.Marshal(map[string]any{"data": data})
		if _, _, err := parse(raw); err == nil {
			t.Fatalf("parsed reserved data.%s", name)
		}
	}
}

func TestPolicyFactsPreserveJSON(t *testing.T) {
	body := map[string]any{"amount": json.Number("9007199254740993"), "null": nil, "empty": []any{}, "array": []any{json.Number("0.125")}}
	for _, f := range []facts.Facts{
		{},
		{Operation: &facts.Operation{}, Parameters: map[string]any{}, Context: facts.Context{Label: facts.Label{Because: map[string]string{}}}},
		{Version: facts.Version, Kind: facts.KindOperation, Principal: facts.Principal{Key: "key", Name: "agent"},
			Account: "account", Service: "web", Connection: "connection", Title: "request",
			Operation: &facts.Operation{ID: "id", Action: "write", Effects: []string{"write"}}, Parameters: body,
			Context: facts.Context{Label: facts.Label{Audience: "me", Trust: "untrusted", Because: map[string]string{"audience": "private"}},
				Observes: cleanLabel, Sends: "anyone", Cause: "account"},
			Details: facts.Details{HTTP: &facts.HTTP{Method: "POST", Body: body, Query: map[string][]string{"q": {"one", "two"}}},
				MCP: &facts.MCP{Tool: "tool", Arguments: body}, MQTT: &facts.MQTT{Payload: []byte{0, 128, 255}},
				GraphQL: &facts.GraphQL{Fields: []facts.GraphQLField{{Name: "field", Arguments: body}}}}},
	} {
		_, policy, err := f.Snapshot()
		if err != nil {
			t.Fatal(err)
		}
		reference, err := facts.JSON[map[string]any](f)
		if err != nil {
			t.Fatal(err)
		}
		got := ast.LazyObject(policy)
		want, err := ast.InterfaceToValue(reference)
		if err != nil {
			t.Fatal(err)
		}
		if got.Compare(want) != 0 {
			t.Fatalf("Rego input differs from audit facts:\ngot: %v\nwant: %v", got, want)
		}
	}
}

func TestOwnerPolicyReadsExactProtocolValues(t *testing.T) {
	q, err := compileTestPolicy(t.Context(), &config{Policies: map[string]string{"owner.rego": `package sentinel
deny contains "body visible" if {
 input.facts.details.http.body.amount == 9007199254740993
 input.facts.details.http.body.amount != 9007199254740992
 input.facts.details.http.body.nothing == null
 count(input.facts.details.http.body.payload) == 1048576
 not "channel" in object.keys(input.facts.context)
 not "because" in object.keys(input.facts.context.label)
 not "actions" in object.keys(input.authorization.access)
}`}})
	if err != nil {
		t.Fatal(err)
	}
	in := fixtureInput{Account: fixtureAccount(namedAccount{Name: "account", account: account{Contents: "team", Sends: "me"}}),
		Access: access{Level: "allow"}, Label: cleanLabel,
		Request: fixedDescription{facts.Facts{Operation: &facts.Operation{Action: "read", Effects: []string{"read"}},
			Details: facts.Details{HTTP: &facts.HTTP{Body: map[string]any{"amount": json.Number("9007199254740993"), "nothing": nil, "payload": strings.Repeat("x", 1<<20)}}}}}}
	d, err := q.decideFixture(t.Context(), in)
	if err != nil || !slices.Equal(d.Deny, []string{"body visible"}) {
		t.Fatalf("owner policy lost protocol values: %+v, %v", d, err)
	}
}

func TestPreparedPolicyConcurrentRequests(t *testing.T) {
	q, err := compileTestPolicy(t.Context(), &config{Policies: map[string]string{"owner.rego": `package sentinel
deny contains sprintf("%s/%s", [input.facts.principal.name, input.facts.parameters.id])`}})
	if err != nil {
		t.Fatal(err)
	}
	for i := range 16 {
		t.Run(fmt.Sprint(i), func(t *testing.T) {
			t.Parallel()
			name := fmt.Sprint(i)
			in := fixtureInput{Principal: principal{Name: name}, Account: fixtureAccount(namedAccount{Name: "account", account: account{Contents: "team", Sends: "me"}}),
				Access: access{Level: "allow"}, Label: cleanLabel,
				Request: fixedDescription{facts.Facts{Operation: &facts.Operation{Action: "read", Effects: []string{"read"}}, Parameters: map[string]any{"id": name}}}}
			for range 10 {
				d, err := q.decideFixture(t.Context(), in)
				if err != nil || !slices.Equal(d.Deny, []string{name + "/" + name}) {
					t.Fatalf("concurrent evaluation mixed requests: %+v, %v", d, err)
				}
			}
		})
	}
}

type fixedDescription struct{ facts.Facts }

func (r fixedDescription) Describe(connector.Context) (facts.Facts, error) {
	return r.Facts, nil
}

type waitingDescription struct {
	once    sync.Once
	entered chan struct{}
	release chan struct{}
}

func (r *waitingDescription) Describe(connector.Context) (facts.Facts, error) {
	r.once.Do(func() { close(r.entered); <-r.release })
	return facts.Facts{Operation: &facts.Operation{Action: "read", Effects: []string{"read"}}}, nil
}

func TestGateSerializesConcurrentChanges(t *testing.T) {
	for _, change := range []string{"permission", "identity", "label"} {
		t.Run(change, func(t *testing.T) {
			cfg := &config{Accounts: map[string]account{"web": {Contents: "anyone", Sends: "me"}}, Policies: map[string]string{"guard.rego": `package sentinel
 deny contains "label changed" if input.facts.context.label.audience == "me"`}}
			q, err := compileTestPolicy(t.Context(), cfg)
			if err != nil {
				t.Fatal(err)
			}
			p := principal{Key: "key", Name: "agent", identity: identity{Accounts: map[string]access{"web": {Level: "allow"}}}}
			st := &state{cfg: fixtureConfig(cfg), connections: map[string]*connection{"web": {name: "web", account: "web"}}, decision: q.decision, principals: map[string]principal{p.Key: p}}
			m := &monitor{streams: map[string]map[*connector.Stream]struct{}{}, running: map[string]*connection{}, doc: sealed{Labels: map[string]facts.Label{"key": cleanLabel}}}
			m.live.Store(st)
			request := &waitingDescription{entered: make(chan struct{}), release: make(chan struct{})}
			var release sync.Once
			unblock := func() { release.Do(func() { close(request.release) }) }
			defer unblock()
			done := make(chan error, 1)
			go func() { done <- m.gate(t.Context(), (fixtureInput{Principal: p, Request: request}).gateInput("web")) }()
			select {
			case <-request.entered:
			case <-time.After(3 * time.Second):
				t.Fatal("request never started")
			}
			changed := make(chan struct{})
			go func() {
				m.mu.Lock()
				defer m.mu.Unlock()
				next := *st
				next.principals = maps.Clone(st.principals)
				switch change {
				case "permission":
					p.Accounts = map[string]access{"web": {Level: "off"}}
					next.principals[p.Key] = p
					m.live.Store(&next)
				case "identity":
					delete(next.principals, p.Key)
					m.live.Store(&next)
				case "label":
					m.doc.Labels[p.Key] = facts.Label{Audience: "me", Trust: "trusted"}
				}
				close(changed)
			}()
			select {
			case <-changed:
				t.Fatal("authority changed during evaluation")
			case <-time.After(20 * time.Millisecond):
			}
			unblock()
			select {
			case err := <-done:
				if err != nil {
					t.Fatal(err)
				}
			case <-time.After(3 * time.Second):
				t.Fatal("gate did not finish")
			}
			<-changed
			if err := m.gate(t.Context(), (fixtureInput{Principal: st.principals["key"], Request: request}).gateInput("web")); err == nil {
				t.Fatal("new request ignored changed authority")
			}
		})
	}
}

func TestTypedSnapshotOwnsRequestValues(t *testing.T) {
	body := map[string]any{"amount": json.Number("9007199254740993"), "items": []any{"original"}}
	h := &facts.HTTP{Method: "POST", Query: map[string][]string{"q": {"original"}}, Headers: map[string][]string{"X-Test": {"original"}}, Body: body}
	source := facts.Facts{Parameters: map[string]any{"body": body}, Details: facts.Details{HTTP: h, GraphQL: &facts.GraphQL{Fields: []facts.GraphQLField{{Name: "one", Arguments: body}}}, MQTT: &facts.MQTT{Payload: []byte("original")}, SSH: &facts.SSH{Env: &facts.SSHEnv{Value: "original"}}}}
	before, _ := json.Marshal(source)
	frozen, _, err := source.Snapshot()
	if err != nil {
		t.Fatal(err)
	}
	after, _ := json.Marshal(frozen)
	if string(before) != string(after) {
		t.Fatalf("snapshot changed JSON:\n%s\n%s", before, after)
	}
	h.Method = "DELETE"
	h.Headers["X-Test"][0] = "changed"
	h.Query["q"][0] = "changed"
	body["items"].([]any)[0] = "changed"
	source.Details.MQTT.Payload[0] = 'x'
	source.Details.SSH.Env.Value = "changed"
	after, _ = json.Marshal(frozen)
	if string(before) != string(after) {
		t.Fatal("snapshot aliases mutable request data")
	}
	if !reflect.DeepEqual(frozen.Details.HTTP.Body.(map[string]any)["amount"], json.Number("9007199254740993")) {
		t.Fatal("number rounded")
	}
}

func BenchmarkMonitorEvaluation(b *testing.B) {
	all, err := presets()
	if err != nil {
		b.Fatal(err)
	}
	q, err := compileTestPolicy(b.Context(), &config{resolved: all, Lattices: latticeOptions{true, true}})
	if err != nil {
		b.Fatal(err)
	}
	cases := []struct {
		name, preset, origin, path string
		size                       int
	}{
		{"generic_web", "web", "https://example.com", "/", 0},
		{"generic_web_1MiB", "web", "https://example.com", "/", 1 << 20},
		{"github", "github", "https://github.com", "/acme/widgets.git/info/refs", 0},
		{"custom_api_empty", "custom_api", "https://example.com", "/api/items", 0},
		{"custom_api_64KiB", "custom_api", "https://example.com", "/api/items", 64 << 10},
		{"custom_api_1MiB", "custom_api", "https://example.com", "/api/items", 1 << 20},
	}
	for _, tc := range cases {
		b.Run(tc.name, func(b *testing.B) {
			h := &facts.HTTP{Method: "GET", Origin: tc.origin, Host: strings.TrimPrefix(tc.origin, "https://"), Path: tc.path, BodyKind: "none"}
			if tc.size > 0 {
				h.Method, h.BodyKind = "POST", "json"
				h.Body = map[string]any{"payload": strings.Repeat("x", tc.size)}
			}
			if tc.preset == "github" {
				h.Query = map[string][]string{"service": {"git-upload-pack"}}
			}
			req := &web.Request{HTTP: h}
			connectionConfig := json.RawMessage(`{"slots":[{"origin":"https://example.com","path":"/api"}]}`)
			live := &web.HTTP{Credentials: web.Credentials{Slots: []web.Slot{{Origin: "https://example.com", Path: "/api"}}}}
			c := connector.Context{Title: tc.preset, Config: live, Spec: nil}
			if all[tc.preset].http != nil {
				c.Spec = all[tc.preset].http
			}
			in := fixtureInput{Account: fixtureAccount(namedAccount{Name: "test", account: account{Preset: tc.preset, Contents: "team", Sends: "me"}}), Access: access{Level: "allow"}, Label: cleanLabel, Request: req, ConnectionConfig: connectionConfig, Connector: live}
			b.Run("describe", func(b *testing.B) {
				for b.Loop() {
					f, err := req.Describe(c)
					if err != nil {
						b.Fatal(err)
					}
					if f.Operation == nil {
						b.Fatal("operation was not recognized")
					}
				}
			})
			b.Run("evaluate", func(b *testing.B) {
				for b.Loop() {
					d, err := q.decideFixture(b.Context(), in)
					if err != nil {
						b.Fatal(err)
					}
					if d.Facts.Operation == nil || len(d.Deny) > 0 {
						b.Fatalf("unexpected decision: %+v", d)
					}
				}
			})
		})
	}
}

type failingDescription struct{ facts.Facts }

func (r failingDescription) Describe(connector.Context) (facts.Facts, error) {
	return r.Facts, errors.New("cannot describe request")
}

func TestPolicyReadsResolvedFactsAndGoDeniesDescriptionErrors(t *testing.T) {
	q, err := compileTestPolicy(t.Context(), &config{Policies: map[string]string{"resolved.rego": `package sentinel
 deny contains "missing resolved facts" if not resolved
 deny contains "description errors leaked" if "errors" in object.keys(input.authorization)
 resolved if {
  input.facts.operation.lineage == ["objects.files.publish", "objects.files", "objects"]
  input.facts.operation.obligations == {"change": true, "trust": true, "ask": true, "discloses": true}
  data.levels.audiences == ["me", "team", "anyone"]
  data.levels.trusts == ["untrusted", "trusted"]
 }`}})
	if err != nil {
		t.Fatal(err)
	}
	in := factInput(facts.Facts{Operation: &facts.Operation{Action: "objects.files.publish", Effects: []string{"publish"}}})
	in.Access.Level = "allow"
	in.Request = failingDescription{facts.Facts(in.Request.(fixedRequest))}
	d, err := q.decideFixture(t.Context(), in)
	if err != nil || !slices.Equal(d.Deny, []string{"cannot describe request"}) || !reflect.DeepEqual(d.Next, cleanLabel) {
		t.Fatalf("description error or resolved facts: %+v, %v", d, err)
	}
}

func TestRemovedConnectionRefusesGateAndApprovalRecheck(t *testing.T) {
	cfg, st := policyFixture(t, "")
	p := principal{Key: "key", Name: "agent", identity: identity{Accounts: map[string]access{"web": {Level: "allow"}}}}
	c := &connection{name: "web", account: "web", protocol: "http"}
	st.principals, st.connections = map[string]principal{p.Key: p}, map[string]*connection{c.name: c}
	m := &monitor{}
	m.live.Store(st)
	in := input{Key: p.Key, Connection: c.name, Request: fixedRequest(facts.Facts{Operation: &facts.Operation{Action: "read", Effects: []string{"read"}}})}
	if err := m.gate(t.Context(), in); err != nil {
		t.Fatal(err)
	}
	r := m.records[0]
	delete(st.connections, c.name)
	if _, ok := cfg.Accounts["web"]; !ok {
		t.Fatal("fixture removed the account")
	}
	if err := m.gate(t.Context(), in); err == nil || err.Error() != "connection removed" {
		t.Fatalf("removed connection admitted: %v", err)
	}
	err := m.transact(func(tx *transaction) error {
		_, err := tx.recheck(t.Context(), stateApproved, r, in)
		return err
	})
	if err == nil || err.Error() != "connection removed" || len(m.records) != 1 {
		t.Fatalf("removed connection rechecked: %v, records=%d", err, len(m.records))
	}
}

func TestPresetMergePatchDeletesNullAndDoesNotPinVersion(t *testing.T) {
	base := `{"catalog":{"actions":{"remove":{"effects":["write"]},"keep":{"effects":["read"]}}}}`
	hash := contentHash(base)
	doc := &policyDocument{Source: fmt.Sprintf("[monitor.presets]\nexample = %q\n[presets.example.catalog.actions]\nremove = { '$json' = 'null' }\n", hash), Bases: map[string]json.RawMessage{hash: json.RawMessage(base)}}
	cfg, _, err := compileSource(doc, nil)
	if err != nil {
		t.Fatal(err)
	}
	actions := cfg.resolved["example"].Catalog.Actions
	if _, ok := actions["remove"]; ok || len(actions) != 1 || !slices.Equal(actions["keep"].Effects, []string{"read"}) {
		t.Fatalf("null override did not delete only its key: %+v", actions)
	}
	if err := pinPresets(cfg, doc); err != nil {
		t.Fatal(err)
	}
	if cfg.Monitor.Version != 1 || strings.Contains(doc.Source, "version") {
		t.Fatalf("default version was pinned: %s", doc.Source)
	}
}

func TestCompileLeavesSecretsUntilActivation(t *testing.T) {
	f := sourceFixture(t)
	orphan := secretID{"removed", "", "token"}
	f.m.doc.Secrets.set(orphan, json.RawMessage(`"orphan"`))
	before, _ := json.Marshal(f.m.doc.Secrets)
	if _, _, err := compileSource(f.m.doc.Policy, f.m.doc.Secrets); err != nil {
		t.Fatal(err)
	}
	after, _ := json.Marshal(f.m.doc.Secrets)
	if string(after) != string(before) {
		t.Fatal("compilation mutated credentials")
	}
	candidate, err := f.m.policyCandidate(t.Context(), f.m.doc.Policy.Source)
	if err != nil {
		t.Fatal(err)
	}
	if candidate.doc.Secrets.get(orphan) == nil || f.m.doc.Secrets.get(orphan) == nil {
		t.Fatal("preparation pruned credentials")
	}
	if _, err := f.m.applyCandidate(t.Context(), candidate); err != nil {
		t.Fatal(err)
	}
	if f.m.doc.Secrets.get(orphan) != nil || f.disk(t).Secrets.get(orphan) != nil || candidate.doc.Secrets.get(orphan) == nil {
		t.Fatal("activation failed to prune its own credential copy")
	}
}

func TestCatalogSuppliesUnsetSecretsForCustomConnections(t *testing.T) {
	for _, preset := range []string{"redis", "custom"} {
		cfg, connections, err := parse([]byte(fmt.Sprintf(`{"accounts":{"cache":{"preset":%q,"contents":"me","sends":"me","connections":{"named":{"redis":{"url":"rediss://example.com"}}}}}}`, preset)))
		if err != nil {
			t.Fatal(err)
		}
		_, fields, err := configView(sealed{}, &state{cfg: cfg, connections: connections})
		if err != nil || len(fields["cache"]) != 1 || fields["cache"][0].Kind != "unset" || !slices.Equal(fields["cache"][0].Path, []string{"connections", "named", "redis", "secrets", "password"}) {
			t.Fatalf("%s credential editor: %+v, %v", preset, fields, err)
		}
	}
}

func TestJSONEndpointsPreserveNumbersAndShareErrors(t *testing.T) {
	m := &monitor{owner: make([]byte, ownerKeyBytes)}
	m.live.Store(&state{principals: map[string]principal{"key": {Key: "key"}}})
	type payload struct {
		Amount any `json:"amount"`
	}
	var responseErr error
	read := func(_ *http.Request, value payload) (any, error) { return value, responseErr }
	for name, handler := range map[string]http.Handler{
		"owner": owned(m, read),
		"agent": agentJSON(m, "key", func(r *http.Request, value payload, _ policyBase, _ principal) (any, error) { return read(r, value) }),
	} {
		t.Run(name, func(t *testing.T) {
			for _, tc := range []struct {
				err    error
				status int
			}{
				{nil, http.StatusOK}, {errNoAgent, http.StatusForbidden}, {errPolicyConflict, http.StatusConflict}, {errLocked, http.StatusLocked}, {errOwner, http.StatusUnauthorized},
			} {
				responseErr = tc.err
				r := httptest.NewRequest("POST", "/", strings.NewReader(`{"amount":9007199254740993}`))
				r.Header.Set("Authorization", "Bearer "+base64.StdEncoding.EncodeToString(m.owner))
				w := httptest.NewRecorder()
				handler.ServeHTTP(w, r)
				if w.Code != tc.status || tc.err == nil && w.Body.String() != `{"amount":9007199254740993}` {
					t.Fatalf("HTTP %d: %s", w.Code, w.Body.String())
				}
			}
		})
	}
}

func TestUnknownApprovalStillBindsDisclosure(t *testing.T) {
	_, q := policyFixture(t, "")
	in := factInput(facts.Facts{})
	in.Access.Level = "allow"
	one, err := q.decideFixture(t.Context(), in)
	if err != nil {
		t.Fatal(err)
	}
	in.Account.Sends = "anyone"
	two, err := q.decideFixture(t.Context(), in)
	if err != nil || one.authority() == two.authority() {
		t.Fatalf("unknown approval lost disclosure binding: %v", err)
	}
}
