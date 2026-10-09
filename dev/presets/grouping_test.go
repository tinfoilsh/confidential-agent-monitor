package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"reflect"
	"testing"
)

func TestResourceGroupsSeparateAuthorityAndReads(t *testing.T) {
	for _, tc := range []struct{ path, want string }{
		{"/repos/{owner}/{repo}/hooks", "repos.hooks"},
		{"/orgs/{org}/hooks", "orgs.hooks"},
		{"/repos/{owner}/{repo}/statuses/{sha}", "repos.statuses"},
		{"/repos/{owner}/{repo}/deployments/{id}/statuses", "repos.deployments.statuses"},
		{"/user/emails", "user.emails"},
		{"/user/keys", "user.keys"},
		{"/v1/customers/{id}/subscriptions/{subscription}/cancel", "customers.subscriptions"},
		{"/rest/api/3/projects/{id}/settings", "projects.settings"},
		{"/api/admin.conversations.archive", "admin.conversations"},
		{"/bot{token}/sendMessage", "message"},
		{"/2010-04-01/Accounts/{account}/Messages.json", "accounts.messages"},
	} {
		t.Run(tc.path, func(t *testing.T) {
			d := draftOps(parsed{Ops: []specOp{{Method: "GET", Path: tc.path, Body: "none"}}}, false)[0]
			if d.action != tc.want+".read" {
				t.Fatalf("got %q, want %q", d.action, tc.want+".read")
			}
		})
	}
}

func TestGraphQLResourcesGroupQueriesAndMutations(t *testing.T) {
	const schema = `type Query { issues: IssueConnection! issue(id: ID!): Issue! }
type Mutation { issueCreate: IssuePayload! issueArchive(id: ID!): IssuePayload! }
type IssueConnection { nodes: [Issue!]! }
type IssuePayload { issue: Issue }
type Issue { id: ID! }`
	p, err := parseGraphQL([]byte(schema), "https://example.com", "/graphql")
	if err != nil {
		t.Fatal(err)
	}
	for _, d := range draftOps(p, false) {
		want := "issue.write"
		if d.op.GraphQL[0] == "query" {
			want = "issue.read"
		}
		if d.action != want {
			t.Fatalf("%s grouped as %q, want %q", d.op.ID, d.action, want)
		}
	}
}

func TestGroupingPreservesContractsAndIsIdempotent(t *testing.T) {
	record := map[string]any{
		"catalog": map[string]any{"actions": map[string]any{
			"pay": map[string]any{"title": "Pay"},
			"use": map[string]any{"title": "Use tools", "effects": []any{"write"}},
		}},
		"http": map[string]any{"operations": map[string]any{"payments.create": map[string]any{
			"id": "payments.create", "action": "pay", "effects": []any{"pay", "send"},
			"method": "POST", "path": "/v1/payments", "body": "json",
			"fields": map[string]any{"/live": false}, "scope": map[string]any{"request": map[string]any{"from": "body", "at": "", "type": "object"}},
			"grant": []any{"request"}, "sends": "team",
		}}},
	}
	before, _ := json.Marshal(record)
	if n := groupRecord(record, nil); n != 1 {
		t.Fatalf("regrouped %d operations", n)
	}
	ops := httpSection(record)["operations"].(map[string]any)
	if ops["payments.create"].(map[string]any)["action"] != "payments.pay" {
		t.Fatalf("wrong action: %v", ops["payments.create"].(map[string]any)["action"])
	}
	var original map[string]any
	json.Unmarshal(before, &original)
	expected := httpSection(original)["operations"].(map[string]any)["payments.create"].(map[string]any)
	expected["action"] = "payments.pay"
	if !reflect.DeepEqual(ops["payments.create"].(map[string]any), expected) {
		t.Fatal("grouping changed the request or its effects")
	}
	actions := record["catalog"].(map[string]any)["actions"].(map[string]any)
	if actions["pay"] != nil || actions["payments"] == nil || actions["payments.pay"] == nil || actions["use"] == nil {
		t.Fatalf("wrong catalog: %v", actions)
	}
	first, _ := json.Marshal(record)
	if n := groupRecord(record, nil); n != 0 {
		t.Fatalf("second run renamed %d operations", n)
	}
	second, _ := json.Marshal(record)
	if string(first) != string(second) {
		t.Fatal("second grouping changed output")
	}
}

func TestGroupHintsPreferOperationIdentityOnSharedRoutes(t *testing.T) {
	ops := []map[string]any{{"id": "getFlow", "method": "GET", "path": "/{node}", "body": "none"}}
	p := parsed{Ops: []specOp{
		{ID: "getAccount", Method: "GET", Path: "/{id}", Body: "none", Tags: []string{"accounts"}},
		{ID: "getFlow", Method: "GET", Path: "/{flow}", Body: "none", Tags: []string{"flows"}},
	}}
	if got := actionResource(groupHints(ops, p, "test")["getFlow"]); got != "flows" {
		t.Fatalf("selected unrelated source group: %s", got)
	}
	if got := actionResource(specOp{Path: "/ambiguous", Resource: "account.keys"}); got != "account.keys" {
		t.Fatalf("lost explicit source grouping: %s", got)
	}
}

func TestSourceGroupingOverridesAreValidated(t *testing.T) {
	toolDirectory(t)
	const raw = `{"openapi":"3.0.3","info":{"title":"test","version":"1"},"paths":{"/items":{"get":{"operationId":"listItems","responses":{}}}}}`
	sum := sha256.Sum256([]byte(raw))
	hash := hex.EncodeToString(sum[:])
	if err := os.WriteFile(cached(hash), []byte(raw), 0o644); err != nil {
		t.Fatal(err)
	}
	ref := specRef{Format: "openapi", URL: "https://example.com/spec.json"}
	src := source{Specs: []specRef{ref}, Groups: map[string]string{"listItems": "library.items"}}
	lock := lockFile{"test": {{Source: ref.source(), URL: ref.URL, SHA256: hash}}}
	p, err := specOps("test", src, lock)
	if err != nil || len(p.Ops) != 1 || actionResource(p.Ops[0]) != "library.items" {
		t.Fatalf("source override lost: %+v, %v", p, err)
	}
	for _, groups := range []map[string]string{{"missing": "items"}, {"listItems": "invalid..group"}} {
		src.Groups = groups
		if _, err := specOps("test", src, lock); err == nil {
			t.Fatalf("invalid grouping accepted: %v", groups)
		}
	}
}
