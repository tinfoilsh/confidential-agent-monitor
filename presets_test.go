package main

import (
	"encoding/json"
	"maps"
	"slices"
	"testing"

	"github.com/open-policy-agent/opa/v1/rego"
)

func presetQuery(t *testing.T, owned map[string]map[string]any, policies map[string]string) rego.PreparedEvalQuery {
	t.Helper()
	all, err := withOwned(owned)
	if err != nil {
		t.Fatal(err)
	}
	q, _, err := preparePolicies(t.Context(), &config{resolved: all, Policies: policies, Lattices: latticeOptions{true, true}})
	if err != nil {
		t.Fatal(err)
	}
	return q
}

func presetInput(name, event string) map[string]any {
	var in map[string]any
	if err := json.Unmarshal([]byte(event), &in); err != nil {
		panic(err)
	}
	in["account"] = map[string]any{"name": "test", "preset": name, "policy_options": map[string]any{}, "contents": "team", "strangers": false, "sends": "me"}
	in["access"] = map[string]any{"level": "allow"}
	in["label"] = map[string]any{"audience": "me", "trust": "trusted"}
	in["rules"] = []any{}
	return in
}

func presetDecision(t *testing.T, q rego.PreparedEvalQuery, in map[string]any) *decision {
	t.Helper()
	d, err := evaluateDecision(t.Context(), q, in)
	if err != nil {
		t.Fatal(err)
	}
	return d
}

func TestPresetModules(t *testing.T) {
	q := presetQuery(t, nil, nil)
	for _, tc := range []struct {
		preset, event, action, effect string
	}{
		{"browser", `{"browser":{"command":"navigate","host":"example.com","url":"https://example.com"}}`, "browse", "read"},
		{"web", `{"http":{"method":"POST","host":"example.com","path":"/"}}`, "submit", "send"},
		{"ssh", `{"ssh":{"request":"exec","command":"ls"},"connection_config":{"host":"example.com"}}`, "run", "execute"},
		{"postgres", `{"postgres":{"sql":"SELECT 1"}}`, "read", "read"},
		{"redis", `{"redis":{"command":"SET","argv":["SET","key","value"]}}`, "write", "write"},
		{"email", `{"smtp":{"to":["friend@example.com"]}}`, "send", "send"},
		{"mcp", `{"mcp":{"tool":"list_repos","read_only":true,"arguments":{}}}`, "read.list_repos", "read"},
		{"github", `{"mcp":{"tool":"list_repos","read_only":true,"arguments":{}}}`, "read.list_repos", "read"},
	} {
		t.Run(tc.preset, func(t *testing.T) {
			d := presetDecision(t, q, presetInput(tc.preset, tc.event))
			if d.Action == nil || *d.Action != tc.action || !slices.Contains(d.Effects, tc.effect) || len(d.Deny) != 0 || d.Title == "" {
				t.Fatalf("unexpected recognition: %+v", d)
			}
		})
	}
}

const recordRequest = `{"http":{"method":"GET","origin":"https://example.com","host":"example.com","path":"/items/one","query":{},"headers":{},"body_kind":"none"}}`

func recordPreset() map[string]any {
	var p map[string]any
	json.Unmarshal([]byte(`{"title":"Example","catalog":{"fields":[],"actions":{}},"operations":[{"id":"items.get","action":"read","effects":["read"],"method":"GET","origin":"https://example.com","path":"/items/{id}","scope":{"id":{"from":"path","at":"id"}}}]}`), &p)
	return p
}

func TestPresetRecognizerOwnsUnknownRequests(t *testing.T) {
	// A matching record must not take over when the selected custom module has no operation.
	q := presetQuery(t, map[string]map[string]any{"custom": recordPreset(), "example": recordPreset()}, nil)
	unknown := presetDecision(t, q, presetInput("custom", recordRequest))
	if unknown.Action != nil || len(unknown.Deny) != 0 || !slices.Contains(unknown.Gaps, "ask") {
		t.Fatalf("custom module fell through: %+v", unknown)
	}
	d := presetDecision(t, q, presetInput("example", recordRequest))
	if d.Operation != "items.get" || d.Title != "Example: items.get" || len(d.Deny) != 0 || d.Scope["id"] != "one" {
		t.Fatalf("generic recognition: %+v", d)
	}
	// A non-HTTP module must not inherit the generic matcher's HTTP-only denial.
	d = presetDecision(t, q, presetInput("custom", `{"ssh":{"request":"shell"}}`))
	if len(d.Deny) != 0 {
		t.Fatalf("custom inherited generic denials: %+v", d)
	}
	d = presetDecision(t, q, presetInput("example", `{"ssh":{"request":"shell"}}`))
	if !slices.Contains(d.Deny, "only HTTP requests reach a service") {
		t.Fatalf("generic denial lost: %+v", d)
	}
	q = presetQuery(t, nil, map[string]string{"custom.rego": `package sentinel
operation := {"id":"run","action":"run","effects":["execute"],"scope":{}}`})
	d = presetDecision(t, q, presetInput("custom", `{"ssh":{"request":"shell"}}`))
	if d.Operation != "run" || len(d.Deny) != 0 {
		t.Fatalf("owner recognition lost: %+v", d)
	}
}

func TestPresetRecordDenials(t *testing.T) {
	for _, tc := range []struct {
		name, deny string
		edit       func(map[string]any)
	}{
		{"ambiguous", "the request matches more than one reviewed operation", func(p map[string]any) {
			o := maps.Clone(p["operations"].([]any)[0].(map[string]any))
			o["id"] = "also.get"
			p["operations"] = append(p["operations"].([]any), o)
		}},
		{"missing scope", "the request has no id of the expected type", func(p map[string]any) {
			p["operations"].([]any)[0].(map[string]any)["scope"] = map[string]any{"id": map[string]any{"from": "query", "at": "missing"}}
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p := recordPreset()
			tc.edit(p)
			d := presetDecision(t, presetQuery(t, map[string]map[string]any{"example": p}, nil), presetInput("example", recordRequest))
			if !slices.Contains(d.Deny, tc.deny) {
				t.Fatalf("lost record denial: %+v", d)
			}
		})
	}
}

func TestPresetValidation(t *testing.T) {
	for _, raw := range []string{`{}`, `{"operations":[]}`} {
		var p map[string]any
		json.Unmarshal([]byte(raw), &p)
		p["catalog"] = map[string]any{}
		if _, err := withOwned(map[string]map[string]any{"empty": p}); err != nil {
			t.Fatalf("empty operations rejected: %v", err)
		}
	}
	for _, raw := range []string{
		`{"catalog":{},"operations":null}`,
		`{"catalog":{},"operations":{}}`,
		`{"catalog":{},"operations":"bad"}`,
		`{"catalog":{"actions":[]}}`,
		`{"catalog":{"actions":{"read":{"effects":[]}}}}`,
		`{"catalog":{"actions":{"read":{"effects":["typo"]}}}}`,
		`{"catalog":{"actions":{"read":{"effects":"read"}}}}`,
	} {
		var p map[string]any
		json.Unmarshal([]byte(raw), &p)
		if _, err := withOwned(map[string]map[string]any{"bad": p}); err == nil {
			t.Fatalf("malformed preset accepted: %s", raw)
		}
	}
	for _, name := range []string{"web", "slack", "custom"} {
		if _, _, err := parse([]byte(`{"accounts":{"test":{"preset":"` + name + `","contents":"me","sends":"me"}}}`)); err != nil {
			t.Fatal(err)
		}
	}
	if _, _, err := parse([]byte(`{"accounts":{"test":{"preset":"missing","contents":"me","sends":"me"}}}`)); err == nil {
		t.Fatal("unknown preset accepted")
	}
}

func TestPresetApprovalDefinitions(t *testing.T) {
	in := presetInput("web", `{"http":{"method":"GET","host":"example.com","path":"/"}}`)
	base := presetDecision(t, presetQuery(t, nil, nil), in)
	shipped, err := presets()
	if err != nil {
		t.Fatal(err)
	}
	copyRecord := func() map[string]any {
		raw, _ := json.Marshal(shipped["web"].record)
		var p map[string]any
		json.Unmarshal(raw, &p)
		return p
	}
	for _, tc := range []struct {
		name    string
		edit    func(map[string]any)
		changed bool
	}{
		{"display", func(p map[string]any) { p["title"] = "Renamed" }, false},
		{"effects", func(p map[string]any) {
			p["catalog"].(map[string]any)["actions"].(map[string]any)["browse"].(map[string]any)["effects"] = []any{"send"}
		}, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p := copyRecord()
			tc.edit(p)
			d := presetDecision(t, presetQuery(t, map[string]map[string]any{"web": p}, nil), in)
			if (d.Definition != base.Definition) != tc.changed || d.Operation != base.Operation {
				t.Fatalf("approval definition changed incorrectly: %+v", d)
			}
		})
	}
	p := recordPreset()
	q := presetQuery(t, map[string]map[string]any{"example": p}, nil)
	base = presetDecision(t, q, presetInput("example", recordRequest))
	p["operations"].([]any)[0].(map[string]any)["open_params"] = true
	d := presetDecision(t, presetQuery(t, map[string]map[string]any{"example": p}, nil), presetInput("example", recordRequest))
	if d.Definition == base.Definition {
		t.Fatal("changed record kept its approval definition")
	}
}

func TestPresetActionEffectInheritance(t *testing.T) {
	shipped, err := presets()
	if err != nil {
		t.Fatal(err)
	}
	raw, _ := json.Marshal(shipped["mcp"].record)
	var p map[string]any
	json.Unmarshal(raw, &p)
	p["catalog"].(map[string]any)["actions"].(map[string]any)["read.special"] = map[string]any{"effects": []any{"execute"}}
	q := presetQuery(t, map[string]map[string]any{"mcp": p}, nil)
	for tool, effect := range map[string]string{"special": "execute", "ordinary": "read"} {
		d := presetDecision(t, q, presetInput("mcp", `{"mcp":{"tool":"`+tool+`","read_only":true,"arguments":{}}}`))
		if !slices.Equal(d.Effects, []string{effect}) {
			t.Fatalf("%s inherited the wrong effects: %+v", tool, d)
		}
	}
}

func TestGitHubRecognition(t *testing.T) {
	q := presetQuery(t, nil, nil)
	for _, tc := range []struct {
		name, event, operation, action, deny string
	}{
		{"REST", `{"http":{"origin":"https://api.github.com","method":"GET","path":"/repos/owner/repo","query":{},"headers":{"X-Github-Api-Version":["2022-11-28"]},"body_kind":"none"}}`, "repos.get", "read", ""},
		{"REST missing version", `{"http":{"origin":"https://api.github.com","method":"GET","path":"/repos/owner/repo","query":{},"headers":{},"body_kind":"none"}}`, "", "", ""},
		{"REST unknown", `{"http":{"origin":"https://api.github.com","method":"GET","path":"/unlisted","query":{},"headers":{},"body_kind":"none"}}`, "", "", ""},
		{"git discovery", `{"http":{"origin":"https://github.com","method":"GET","path":"/owner/repo.git/info/refs","query":{"service":["git-upload-pack"]}}}`, "read", "read", ""},
		{"git fetch", `{"http":{"origin":"https://github.com","method":"POST","path":"/owner/repo.git/git-upload-pack"}}`, "read", "read", ""},
		{"git push", `{"http":{"origin":"https://github.com","method":"POST","path":"/owner/repo.git/git-receive-pack"}}`, "push", "push", ""},
		{"git wrong method", `{"http":{"origin":"https://github.com","method":"GET","path":"/owner/repo.git/git-receive-pack"}}`, "", "", ""},
		{"GraphQL", `{"http":{"origin":"https://api.github.com","method":"POST","path":"/graphql"},"graphql":{"kind":"mutation","fields":[{"name":"createIssue"}]}}`, "open.issues", "open.issues", ""},
		{"GraphQL unknown", `{"http":{"origin":"https://api.github.com","method":"POST","path":"/graphql"},"graphql":{"kind":"mutation","fields":[{"name":"unknownMutation"}]}}`, "", "", ""},
		{"GraphQL malformed", `{"http":{"origin":"https://api.github.com","method":"POST","path":"/graphql"}}`, "", "", "the GraphQL document could not be decoded"},
		{"MCP", `{"mcp":{"tool":"create_issue","read_only":false,"arguments":{"owner":"owner","repo":"repo"}}}`, "use.create_issue", "use.create_issue", ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			d := presetDecision(t, q, presetInput("github", tc.event))
			if d.Operation != tc.operation || tc.action != "" && (d.Action == nil || *d.Action != tc.action) || tc.action == "" && d.Action != nil {
				t.Fatalf("wrong GitHub recognition: %+v", d)
			}
			if tc.deny != "" && !slices.Contains(d.Deny, tc.deny) || tc.deny == "" && len(d.Deny) != 0 {
				t.Fatalf("wrong GitHub denial: %+v", d)
			}
			if d.Action == nil && !slices.Contains(d.Gaps, "ask") {
				t.Fatalf("unknown operation did not ask: %+v", d)
			}
		})
	}
	for _, private := range []bool{false, true} {
		in := presetInput("github", `{"http":{"origin":"https://api.github.com","method":"POST","path":"/repos/owner/repo/issues/1/comments","query":{},"headers":{"X-Github-Api-Version":["2022-11-28"]},"body_kind":"json","body":{"body":"hello"}}}`)
		in["label"].(map[string]any)["audience"] = "anyone"
		if private {
			in["account"].(map[string]any)["policy_options"] = map[string]any{"private": []string{"owner/*"}}
		}
		d := presetDecision(t, q, in)
		wantSends, wantContents := "anyone", "anyone"
		if private {
			wantSends, wantContents = "me", "team"
		}
		if d.Operation != "issues.comments.create" || *d.Action != "comment" || !slices.Equal(d.Effects, []string{"send"}) ||
			d.Scope["owner"] != "owner" || d.Scope["repo"] != "repo" || d.Grant["comment"] != "hello" ||
			d.Sends != wantSends || d.Next.Audience != wantContents || d.Title != "GitHub: issues.comments.create" {
			t.Fatalf("lost record or repository semantics, private=%v: %+v", private, d)
		}
	}
}

func TestGitHubDelegationDenials(t *testing.T) {
	p := recordPreset()
	o := p["operations"].([]any)[0].(map[string]any)
	other := maps.Clone(o)
	other["id"] = "duplicate"
	p["operations"] = append(p["operations"].([]any), other)
	d := presetDecision(t, presetQuery(t, map[string]map[string]any{"github": p}, nil), presetInput("github", recordRequest))
	if !slices.Contains(d.Deny, "the request matches more than one reviewed operation") {
		t.Fatalf("GitHub lost REST denial: %+v", d)
	}
	// A REST record for /graphql cannot absorb a malformed GraphQL request.
	p = recordPreset()
	o = p["operations"].([]any)[0].(map[string]any)
	o["method"], o["origin"], o["path"], o["scope"] = "POST", "https://api.github.com", "/graphql", map[string]any{}
	d = presetDecision(t, presetQuery(t, map[string]map[string]any{"github": p}, nil), presetInput("github", `{"http":{"method":"POST","origin":"https://api.github.com","path":"/graphql","query":{},"headers":{},"body_kind":"none"}}`))
	if d.Operation != "" || !slices.Contains(d.Deny, "the GraphQL document could not be decoded") {
		t.Fatalf("GraphQL fell through to REST: %+v", d)
	}
}
