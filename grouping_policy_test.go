package main

import (
	"encoding/json"
	"maps"
	"reflect"
	"slices"
	"testing"

	"github.com/tinfoilsh/monitor/connector"
	"github.com/tinfoilsh/monitor/connector/email"
	"github.com/tinfoilsh/monitor/facts"
)

func TestGroupedPermissionInheritance(t *testing.T) {
	all, err := presets()
	if err != nil {
		t.Fatal(err)
	}
	q, err := compileTestPolicy(t.Context(), &config{resolved: all})
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		path, action string
		actions      map[string]string
		denied       bool
	}{
		{"/user/emails", "user.emails.read", map[string]string{"user": "off", "user.emails": "allow"}, false},
		{"/user/keys", "user.keys.read", map[string]string{"user": "off", "user.emails": "allow"}, true},
		{"/repos/acme/project/hooks", "repos.hooks.read", map[string]string{"repos.hooks": "off"}, true},
		{"/orgs/acme/hooks", "orgs.hooks.read", map[string]string{"repos.hooks": "off"}, false},
		{"/repos/acme/project/hooks", "repos.hooks.read", map[string]string{"repos": "off", "repos.hooks.read": "allow"}, false},
	} {
		t.Run(tc.path, func(t *testing.T) {
			in := map[string]any{
				"account": map[string]any{"name": "github", "preset": "github", "policy_options": map[string]any{}, "contents": "me", "sends": "me", "strangers": false},
				"access":  map[string]any{"level": "allow", "actions": tc.actions},
				"label":   map[string]any{"audience": "me", "trust": "trusted"}, "rules": map[string]any{},
				// Pagination disambiguates the list endpoints from the existing
				// /user/{account_id} record, which accepts no query parameters.
				"http": map[string]any{"origin": "https://api.github.com", "method": "GET", "path": tc.path, "body_kind": "none", "headers": map[string]any{}, "query": map[string]any{"per_page": []string{"10"}}},
			}
			d, err := evaluateFixture(t, q, in)
			if err != nil {
				t.Fatal(err)
			}
			if d.Facts.Operation == nil || d.Facts.Operation.Action != tc.action || (len(d.Deny) > 0) != tc.denied {
				t.Fatalf("unexpected grouped permission decision: %+v", d)
			}
		})
	}
}

// Descriptions must travel with preset data when the owner renames a service.
func TestPresetNamesDoNotSelectDescriptions(t *testing.T) {
	all, err := presets()
	if err != nil {
		t.Fatal(err)
	}
	renamed := maps.Clone(all)
	for name, p := range all {
		renamed["renamed_"+name] = p
	}
	q, err := compileTestPolicy(t.Context(), &config{resolved: renamed, Lattices: latticeOptions{true, true}})
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct{ preset, event string }{
		{"ssh", `{"ssh":{"request":"exec","command":"ls"}}`},
		{"sftp", `{"sftp":{"command":"open","path":"/report","read":true,"write":true}}`},
		{"postgres", `{"postgres":{"sql":"SELECT 1"}}`},
		{"redis", `{"redis":{"command":"GET","argv":["GET","key"]}}`},
		{"mqtt", `{"mqtt":{"command":"publish","topic":"lights/set","retain":true}}`},
		{"nats", `{"nats":{"command":"publish","subject":"$JS.API.STREAM.DELETE.orders"}}`},
		{"email", `{"smtp":{"to":["friend@example.com"]}}`},
		{"email", `{"imap":{"command":"FETCH","mailbox":"inbox"}}`},
		{"browser", `{"browser":{"command":"navigate","host":"example.com","url":"https://example.com"}}`},
		{"web", `{"http":{"method":"GET","host":"example.com","path":"/"}}`},
		{"mcp", `{"mcp":{"tool":"list_items","read_only":true,"arguments":{}}}`},
		{"custom_api", `{"connection_config":{"slots":[{"origin":"https://example.com","path":"/api"}]},"http":{"method":"POST","origin":"https://example.com","path":"/api/items"}}`},
		{"github", `{"http":{"method":"POST","origin":"https://github.com","path":"/owner/repo.git/git-receive-pack"}}`},
		{"github", `{"http":{"method":"POST","origin":"https://api.github.com","path":"/graphql","body_kind":"json"},"graphql":{"kind":"mutation","fields":[{"name":"createIssue"},{"name":"updateIssue"}]}}`},
		{"github", `{"mcp":{"tool":"create_issue","read_only":false,"arguments":{"owner":"owner","repo":"repo"}}}`},
		{"github", `{"http":{"method":"POST","origin":"https://api.github.com","path":"/repos/owner/repo/issues/1/comments","headers":{"X-Github-Api-Version":["2022-11-28"]},"body_kind":"json","body":{"body":"hello"}}}`},
	} {
		t.Run(tc.preset+tc.event, func(t *testing.T) {
			for _, private := range [][]string{nil, {"owner/*"}} {
				in := descriptionInput(tc.preset, tc.event)
				account := in["account"].(map[string]any)
				account["policy_options"] = map[string]any{"private": private}
				before := descriptionDecision(t, q, in)
				account["preset"] = "renamed_" + tc.preset
				after := descriptionDecision(t, q, in)
				if before.Facts.Operation == nil || len(before.Deny) != 0 || !reflect.DeepEqual(before.Facts.Operation, after.Facts.Operation) || !reflect.DeepEqual(before.Facts.Parameters, after.Facts.Parameters) || !reflect.DeepEqual(before.Facts.Context, after.Facts.Context) || !reflect.DeepEqual(before.Deny, after.Deny) {
					t.Fatalf("renaming changed description: before=%+v after=%+v", before, after)
				}
			}
		})
	}
}

func TestGraphQLRecordsRequireOneAction(t *testing.T) {
	all, err := presets()
	if err != nil {
		t.Fatal(err)
	}
	q, err := compileTestPolicy(t.Context(), &config{resolved: all})
	if err != nil {
		t.Fatal(err)
	}
	for _, fields := range []string{`[{"name":"createIssue"},{"name":"mergePullRequest"}]`, `[{"name":"createIssue"},{"name":"unknownMutation"}]`, `[]`} {
		in := descriptionInput("github", `{"http":{"method":"POST","origin":"https://api.github.com","path":"/graphql","body_kind":"json"},"graphql":{"kind":"mutation","fields":`+fields+`}}`)
		if d := descriptionDecision(t, q, in); d.Facts.Operation != nil {
			t.Fatalf("mixed or empty mutation matched: %+v", d)
		}
	}
}

func descriptionInput(name, event string) map[string]any {
	var in map[string]any
	if err := json.Unmarshal([]byte(event), &in); err != nil {
		panic(err)
	}
	in["account"] = map[string]any{"name": "test", "preset": name, "contents": "team", "sends": "me"}
	in["label"] = map[string]any{"audience": "me", "trust": "trusted"}
	in["access"] = map[string]any{"level": "allow"}
	return in
}

func descriptionDecision(t *testing.T, q *state, in map[string]any) *decision {
	t.Helper()
	d, err := evaluateFixture(t, q, in)
	if err != nil {
		t.Fatal(err)
	}
	return d
}

func TestDescriptionDoesNotMutateRequestsOrPresets(t *testing.T) {
	record := &presetRecord{Catalog: &presetCatalog{Actions: map[string]presetAction{"send": {Effects: []string{"send", "read", "read"}}}}}
	presets := map[string]*presetRecord{"renamed_email": record}
	in := fixtureInput{Account: fixtureAccount(namedAccount{Name: "work", account: account{Preset: "renamed_email", Contents: "team", Sends: "me"}}),
		Label: cleanLabel, Request: &email.SMTPRequest{SMTP: &facts.SMTP{To: []string{"z@example.com", "a@example.com"}}}}
	before, _ := json.Marshal([]any{record, in.Request})
	one, err := describeFixture(presets, in)
	if err != nil {
		t.Fatal(err)
	}
	two, err := describeFixture(presets, in)
	if err != nil {
		t.Fatal(err)
	}
	after, _ := json.Marshal([]any{record, in.Request})
	if string(before) != string(after) || !reflect.DeepEqual(one, two) {
		t.Fatal("description mutated its inputs or depended on previous calls")
	}
	if one.Operation == nil || !reflect.DeepEqual(one.Operation.Effects, []string{"read", "send"}) {
		t.Fatal("effects were not normalized")
	}
	one.Operation.Effects[0] = "admin"
	if !reflect.DeepEqual(two.Operation.Effects, []string{"read", "send"}) || record.Catalog.Actions["send"].Effects[0] != "send" {
		t.Fatal("operation aliases preset effects or another result")
	}
}

// A connector description independent of protocol parsers exercises the common boundary.
type fixedRequest facts.Facts

func (r fixedRequest) Describe(connector.Context) (facts.Facts, error) {
	return facts.Facts(r), nil
}

func factInput(f facts.Facts) fixtureInput {
	return fixtureInput{Principal: principal{Key: "agent-key", Name: "agent"},
		Account: fixtureAccount(namedAccount{Name: "test", account: account{Preset: "custom", Contents: "team", Sends: "me"}}),
		Access:  access{Level: "read"}, Label: cleanLabel, Request: fixedRequest(f)}
}

func TestUnknownFactsRemainConservative(t *testing.T) {
	_, q := policyFixture(t, "")
	q.cfg.resolved = map[string]*presetRecord{"custom": {Catalog: &presetCatalog{}, PublicScope: []string{"repo"}}}
	for _, operation := range []*facts.Operation{nil, {Action: "unconfigured"}} {
		in := factInput(facts.Facts{Operation: operation, Parameters: map[string]any{"repo": "public"}})
		in.Access.Level = "allow"
		d, err := q.decideFixture(t.Context(), in)
		if err != nil {
			t.Fatal(err)
		}
		if d.Facts.Operation != nil || len(d.Deny) != 0 || !slices.Contains(d.Requirements.IDs(), "ask") {
			t.Fatalf("unknown description was not held for approval: %+v", d)
		}
		if d.Next.Audience != "me" || d.Next.Trust != "untrusted" {
			t.Fatalf("public scope weakened unknown observation: %+v", d.Next)
		}
	}
}

func TestRequestKindsControlAuthorizationIndependentlyOfDetails(t *testing.T) {
	q := presetQuery(t, nil, nil)
	for _, tc := range []struct {
		name    string
		kind    facts.Kind
		details facts.Details
		current facts.Label
		ask     bool
		deny    bool
	}{
		{"ordinary TCP details", facts.KindOperation, facts.Details{TCP: &facts.TCP{}}, cleanLabel, true, false},
		{"admission without details", facts.KindAdmission, facts.Details{}, cleanLabel, false, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			in := factInput(facts.Facts{Kind: tc.kind, Operation: &facts.Operation{Action: "write", Effects: []string{"write"}},
				Details: tc.details})
			in.Access.Level, in.Label = "ask", tc.current
			d, err := q.decideFixture(t.Context(), in)
			if err != nil {
				t.Fatal(err)
			}
			if slices.Contains(d.Requirements.IDs(), "ask") != tc.ask || (len(d.Deny) > 0) != tc.deny {
				t.Fatalf("kind did not control authorization: %+v", d)
			}
			if tc.kind == facts.KindOperation && d.Next.Audience != "team" {
				t.Fatal("protocol details suppressed the observation")
			}
		})
	}
}

func TestPolicyAndAuditSeeCurrentPrincipal(t *testing.T) {
	_, q := policyFixture(t, `package sentinel
deny contains "restricted agent" if {
 input.facts.principal.key == "agent-key"
 input.facts.principal.name == "agent"
}`)
	in := factInput(facts.Facts{Principal: facts.Principal{Key: "spoofed", Name: "spoofed"},
		Operation: &facts.Operation{Action: "read", Effects: []string{"read"}}})
	for _, restricted := range []bool{true, false} {
		if !restricted {
			in.Principal = principal{Key: "other-key", Name: "other-agent"}
		}
		d, err := q.decideFixture(t.Context(), in)
		if err != nil {
			t.Fatal(err)
		}
		if slices.Contains(d.Deny, "restricted agent") != restricted {
			t.Fatalf("policy did not distinguish agents: %+v", d)
		}
		if d.Facts.Principal.Key != in.Principal.Key || d.Facts.Principal.Name != in.Principal.Name {
			t.Fatalf("audit lost the requesting principal: %+v", d.Facts.Principal)
		}
	}
}

func TestRequestObservationsPreserveLabelProvenance(t *testing.T) {
	for _, enabled := range []bool{false, true} {
		q, err := compileTestPolicy(t.Context(), &config{Lattices: latticeOptions{enabled, enabled}})
		if err != nil {
			t.Fatal(err)
		}
		for _, tc := range []struct {
			current, observed, want facts.Label
		}{
			{cleanLabel, facts.Label{Audience: "team", Trust: "untrusted"}, facts.Label{Audience: "team", Trust: "untrusted", Because: map[string]string{"audience": "test", "trust": "test"}}},
			{facts.Label{Audience: "me", Trust: "trusted", Because: map[string]string{"audience": "history"}}, facts.Label{Audience: "team", Trust: "untrusted"}, facts.Label{Audience: "me", Trust: "untrusted", Because: map[string]string{"audience": "history", "trust": "test"}}},
			{facts.Label{Audience: "me", Trust: "untrusted", Because: map[string]string{"audience": "history", "trust": "mailbox"}}, cleanLabel, facts.Label{Audience: "me", Trust: "untrusted", Because: map[string]string{"audience": "history", "trust": "mailbox"}}},
		} {
			in := factInput(facts.Facts{Operation: &facts.Operation{Action: "read", Effects: []string{"read"}},
				Context: facts.Context{Observes: tc.observed}})
			in.Label = tc.current
			before, _ := json.Marshal(in.Label)
			d, err := q.decideFixture(t.Context(), in)
			if err != nil {
				t.Fatal(err)
			}
			after, _ := json.Marshal(in.Label)
			if len(d.Deny) != 0 || !reflect.DeepEqual(d.Next, tc.want) || string(before) != string(after) {
				t.Fatalf("label update, enforcement=%v: got %+v, want %+v; deny=%v", enabled, d.Next, tc.want, d.Deny)
			}
		}
	}
}

func TestPolicyProgramInvalidatesSavedApproval(t *testing.T) {
	_, q := policyFixture(t, "")
	in := factInput(facts.Facts{Operation: &facts.Operation{Action: "write", Effects: []string{"write"}}})
	in.Access.Level = "ask"
	before, err := q.decideFixture(t.Context(), in)
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(before.Requirements.IDs(), []string{"ask"}) {
		t.Fatalf("fixture did not require approval: %+v", before)
	}
	in.Rules = map[string]rule{"0": {Account: "test", Action: "write", Operation: "write", Definition: before.Definition, Scope: before.Grant, Requirements: before.Requirements}}
	approved, err := q.decideFixture(t.Context(), in)
	if err != nil || len(approved.Requirements.IDs()) != 0 {
		t.Fatalf("saved approval did not apply: %+v, %v", approved, err)
	}
	q.program += ".changed"
	after, err := q.decideFixture(t.Context(), in)
	if err != nil {
		t.Fatal(err)
	}
	if after.Definition == before.Definition || !slices.Equal(after.Requirements.IDs(), []string{"ask"}) {
		t.Fatalf("changed compiled semantics reused approval: %+v", after)
	}
	if !reflect.DeepEqual(after.Facts, before.Facts) {
		t.Fatal("semantics version changed the public snapshot")
	}
}
