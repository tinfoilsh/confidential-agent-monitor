package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"testing"
	"time"
)

func TestRequestVariants(t *testing.T) {
	const raw = `{"openapi":"3.0.3","info":{"title":"test","version":"1"},"servers":[{"url":"https://example.com/v1"}],"paths":{"/messages?beta=true":{"post":{"operationId":"messages","parameters":[{"name":"channel","in":"query","schema":{"type":"string"}}],"requestBody":{"content":{"application/json":{"schema":{"type":"object","required":["channel"],"properties":{"channel":{"type":"string"},"users":{"type":"array","items":{"type":"string"}}}}},"application/x-www-form-urlencoded":{"schema":{"type":"object","properties":{"channel":{"type":"string"}}}}}},"responses":{"200":{"description":"ok"}}}}}}`
	p, err := parseOpenAPI([]byte(raw), false, "https://example.com/spec.json")
	if err != nil {
		t.Fatal(err)
	}
	if len(p.Ops) != 3 {
		t.Fatalf("want no-body, JSON and form variants, got %+v", p.Ops)
	}
	for _, o := range p.Ops {
		if o.Path != "/v1/messages" || o.Query["beta"] != "true" || o.SourceID != "messages" {
			t.Fatalf("lost request identity: %+v", o)
		}
		if o.Body == "json" && !slices.Contains(o.Required, param{"users", "body", "array", true}) {
			t.Fatalf("optional array resource lost: %+v", o)
		}
		if o.Body == "form" && !slices.Contains(o.Required, param{"channel", "form", "string", true}) {
			t.Fatalf("form selector lost: %+v", o)
		}
	}
}

func TestRequestOnlySpecAndDiagnostics(t *testing.T) {
	const raw = `{"openapi":"3.0.3","info":{"title":"test","version":"1"},"paths":{"/items":{"post":{"requestBody":{"required":true,"content":{"application/json":{"schema":{"type":"object","properties":{"custom":{"$ref":"#/components/schemas/Missing"}}}}}},"responses":{"200":{"$ref":"#/components/responses/Broken"}}}}},"components":{"responses":{"Broken":{"description":"test","content":{"application/json":{"schema":{"$ref":"#/components/schemas/AlsoMissing"}}}}}}}`
	p, err := parseOpenAPI([]byte(raw), false, "https://example.com/spec.json")
	if err != nil {
		t.Fatal(err)
	}
	if len(p.Ops) != 1 || len(p.Warnings) != 1 {
		t.Fatalf("want request plus visible unresolved request schema, got %+v", p)
	}
	d := draftOps(p, false)[0]
	if d.scope["request"] == nil {
		t.Fatal("unknown request members must remain bound in the approval")
	}
}

func TestYAMLNamesAreNotBooleans(t *testing.T) {
	const raw = "openapi: 3.0.3\ninfo: {title: test, version: '1'}\npaths:\n  /items:\n    get:\n      parameters:\n        - name: on\n          in: query\n          schema: {type: string}\n      responses: {}\n"
	p, err := parseOpenAPI([]byte(raw), false, "https://example.com/spec.yaml")
	if err != nil {
		t.Fatal(err)
	}
	if len(p.Ops) != 1 || !slices.Contains(p.Ops[0].Params, "on") {
		t.Fatalf("YAML changed parameter spelling: %+v", p.Ops)
	}
}

func TestUnpinnedRequestReferenceFailsWithoutNetwork(t *testing.T) {
	const raw = `{"openapi":"3.0.3","paths":{"/items":{"post":{"requestBody":{"$ref":"https://example.com/mutable-body.json"}}}}}`
	_, err := parseOpenAPI([]byte(raw), false, "https://example.com/spec.json")
	if err == nil || !strings.Contains(err.Error(), "unpinned external references") {
		t.Fatalf("unlocked network dependency was accepted: %v", err)
	}
}

func TestMissingEncodingRemainsInInventory(t *testing.T) {
	const raw = `{"openapi":"3.0.3","info":{"title":"test","version":"1"},"paths":{"/items":{"post":{"requestBody":{"required":true,"content":{}},"responses":{}}}}}`
	p, err := parseOpenAPI([]byte(raw), false, "https://example.com/spec.json")
	if err != nil || len(p.Ops) != 1 || p.Ops[0].Unsupported == "" {
		t.Fatalf("request with unknown encoding disappeared: %+v, %v", p, err)
	}
}

func TestTemplatedServerKeepsBasePath(t *testing.T) {
	origin, base := splitServer("https://{tenant}.example.com/api/v2")
	if origin != "{origin}" || base != "/api/v2" {
		t.Fatalf("lost tenant API prefix: %s %s", origin, base)
	}
}

func TestGraphQLArgumentsAreBoundAndDeterministic(t *testing.T) {
	const schema = "type Query { item(id: ID!): String } type Mutation { move(project: Int!, input: MoveInput!): String } input MoveInput { destination: String! }"
	first, err := parseGraphQL([]byte(schema), "https://example.com", "/graphql")
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 8; i++ {
		p, err := parseGraphQL([]byte(schema), "https://example.com", "/graphql")
		if err != nil {
			t.Fatal(err)
		}
		if !reflect.DeepEqual(p, first) {
			t.Fatal("GraphQL inventory ordering changed")
		}
	}
	i := slices.IndexFunc(first.Ops, func(o specOp) bool { return o.ID == "move" })
	if i < 0 {
		t.Fatal("mutation missing")
	}
	d := draftOps(first, false)[i]
	if d.scope["arguments"] == nil {
		t.Fatal("mutation input object is absent from approval scope")
	}
	if !slices.Contains(first.Ops[i].Required, param{"project", "argument", "number", false}) {
		t.Fatal("numeric GraphQL resource became a string")
	}
}

func TestDraftKeepsOverlappingOperationsAndEffects(t *testing.T) {
	p := parsed{Ops: []specOp{
		{ID: "payment", Method: "POST", Origin: "https://example.com", Path: "/items/{id}", Body: "json", Effects: []string{"pay", "send"}},
		{ID: "message", Method: "POST", Origin: "https://example.com", Path: "/items/send", Body: "json", Effects: []string{"send"}},
	}}
	ds := draftOps(p, false)
	if len(ds) != 2 || !slices.Equal(ds[0].effects, []string{"pay", "send"}) {
		t.Fatalf("operations or effects lost: %+v", ds)
	}
	a, b := operationObj(ds[0], "payment"), operationObj(ds[1], "message")
	if !recordOverlap(a, b) {
		t.Fatal("overlap must be reported, not merged")
	}
	if _, ok := a["grant"]; ok {
		t.Fatal("generated approval must bind all scope fields")
	}
}

func TestGeneratedConditionsUseJSONContainers(t *testing.T) {
	operations := draftOps(parsed{Ops: []specOp{
		{Method: "GET", Origin: "https://example.com", Path: "/", Body: "none", Headers: map[string]string{"Accept": "one"}, Query: map[string]any{"mode": "one"}},
		{Method: "GET", Origin: "https://example.com", Path: "/", Body: "none", Headers: map[string]string{"Accept": "two"}, Params: []string{"mode"}},
	}}, false)
	a, b := operationObj(operations[0], "a"), operationObj(operations[1], "b")
	if recordOverlap(a, b) {
		t.Fatal("different header conditions overlap")
	}
	b["headers"] = a["headers"]
	if !recordOverlap(a, b) {
		t.Fatal("query parameter was lost from the generated record")
	}
}

func TestGeneratedApprovalBindsQueryAndPayloadDespiteNameCollisions(t *testing.T) {
	o := specOp{ID: "write", Method: "POST", Path: "/items/{request}/{query}", Body: "json", Params: []string{"destination"}}
	d := draftOps(parsed{Ops: []specOp{o}}, false)[0]
	for _, key := range []string{"request", "query", "request.request", "request.query"} {
		if d.scope[key] == nil {
			t.Fatalf("scope %s was dropped: %+v", key, d.scope)
		}
	}
	if got := d.scope["request.query"].(map[string]any)["at"]; got != "" {
		t.Fatalf("approval does not bind the whole query: %v", got)
	}
}

func TestFreshnessRequiresRecentSuccessfulCheck(t *testing.T) {
	now := time.Date(2026, 10, 7, 12, 0, 0, 0, time.UTC)
	for _, tc := range []struct {
		checked string
		wantErr bool
	}{
		{"", true},
		{now.Add(-25 * time.Hour).Format(time.RFC3339), true},
		{now.Add(-time.Hour).Format(time.RFC3339), false},
		{now.Add(time.Hour).Format(time.RFC3339), true},
	} {
		err := checkFreshness([]lockEntry{{Source: "test", CheckedAt: tc.checked}}, 24*time.Hour, now)
		if (err != nil) != tc.wantErr {
			t.Fatalf("checked_at=%q: %v", tc.checked, err)
		}
	}
}

func TestQueryConditionsDisambiguateVariants(t *testing.T) {
	a := map[string]any{"id": "stable", "method": "POST", "origin": "https://example.com", "path": "/messages", "body": "json"}
	b := mapsForTest(a)
	b["id"] = "beta"
	b["query"] = map[string]any{"beta": "true"}
	if recordOverlap(a, b) {
		t.Fatal("stable variant refuses undocumented beta query")
	}
	a["params"] = []any{"beta"}
	if !recordOverlap(a, b) {
		t.Fatal("open beta parameter must expose an ambiguity")
	}
	a["fields"] = map[string]any{"/values": []any{"a"}}
	b["fields"] = map[string]any{"/values": []any{"b"}}
	if recordOverlap(a, b) {
		t.Fatal("different structured field conditions must disambiguate")
	}
}

func mapsForTest(m map[string]any) map[string]any {
	out := map[string]any{}
	for k, v := range m {
		out[k] = v
	}
	return out
}

func TestAirtableExtractionDoesNotPersistPageState(t *testing.T) {
	raw := []byte(`<script>window.initData = {"browserId":"private-browser","csrfToken":"private-token","openApi":{"openapi":"3.1.0","paths":{}}}</script>`)
	out, err := airtableDocument(raw)
	if err != nil {
		t.Fatal(err)
	}
	var doc map[string]any
	if err = json.Unmarshal(out, &doc); err != nil {
		t.Fatal(err)
	}
	if len(doc) != 2 || doc["openapi"] != "3.1.0" {
		t.Fatalf("persisted non-spec page state: %s", out)
	}
}

func TestSlackDocumentationEncodings(t *testing.T) {
	raw := "---\nmethod_name: chat.postMessage\nhttp_method: POST\nsummary: Sends a message.\n---\n## Facts\napplication/json\napplication/x-www-form-urlencoded\n## Arguments\n**`channel`**`string`Required\n**`user`**`string`Optional\n**`token`**`string`Required\n## Usage info\n"
	ops, err := parseSlackMethod([]byte(raw), "https://docs.slack.dev/reference/methods/chat.postMessage.md")
	if err != nil {
		t.Fatal(err)
	}
	if len(ops) != 2 {
		t.Fatalf("missing documented encoding: %+v", ops)
	}
	for _, op := range ops {
		if len(op.Required) != 2 || op.SourceHash == "" {
			t.Fatalf("lost selectors or provenance: %+v", op)
		}
	}
}

func toolDirectory(t *testing.T) {
	t.Helper()
	root := t.TempDir()
	work := filepath.Join(root, "dev", "presets")
	if err := os.MkdirAll(work, 0o755); err != nil {
		t.Fatal(err)
	}
	t.Chdir(work)
	if err := os.MkdirAll(cacheDir, 0o755); err != nil {
		t.Fatal(err)
	}
	parsedCache = map[string]parsed{}
}

func TestGenerationUsesShippedBaseline(t *testing.T) {
	toolDirectory(t)
	op := map[string]any{"id": "messages.create", "action": "generate", "effects": []any{"generate", "pay", "send"}, "method": "POST", "origin": "https://api.anthropic.com", "path": "/v1/messages", "body": "json", "params": []any{"beta"}, "fields": map[string]any{"/mcp_servers": nil}, "scope": map[string]any{"request": map[string]any{"from": "body", "at": "", "type": "object"}}, "grant": []any{}, "sends": "me"}
	record := map[string]any{"title": "Anthropic", "catalog": map[string]any{"actions": map[string]any{}}, "http": map[string]any{"operations": map[string]any{op["id"].(string): op}}}
	if err := writeJSON(filepath.Join(shippedDir, "anthropic.json"), record); err != nil {
		t.Fatal(err)
	}
	const raw = `{"openapi":"3.0.3","info":{"title":"test","version":"1"},"servers":[{"url":"https://api.anthropic.com"}],"paths":{"/v1/messages":{"post":{"operationId":"messages_post","requestBody":{"required":true,"content":{"application/json":{"schema":{"type":"object"}}}},"responses":{}}},"/v1/messages?beta=true":{"post":{"operationId":"beta_messages_post","requestBody":{"required":true,"content":{"application/json":{"schema":{"type":"object"}}}},"responses":{}}}}}`
	sum := sha256.Sum256([]byte(raw))
	sha := hex.EncodeToString(sum[:])
	if err := os.WriteFile(cached(sha), []byte(raw), 0o644); err != nil {
		t.Fatal(err)
	}
	ref := specRef{Format: "openapi", URL: "https://example.com/spec.json"}
	src := source{Preset: "anthropic", Specs: []specRef{ref}}
	lock := lockFile{"anthropic": {{Source: ref.source(), URL: ref.URL, SHA256: sha}}}
	for round := 0; round < 2; round++ {
		r, err := generateService("anthropic", src, lock)
		if err != nil {
			t.Fatal(err)
		}
		if r.Counts["shipped_override"] != 2 || r.Counts["descriptors"] != 1 {
			t.Fatalf("lost override mapping: %+v", r.Counts)
		}
		r.GeneratorSHA256 = "test-generator"
		if err := checkReport(r, src, lock["anthropic"], "test-generator", true); err != nil {
			t.Fatal(err)
		}
		r.Counts["unsupported"] = 1
		if err := checkReport(r, src, lock["anthropic"], "test-generator", false); err == nil {
			t.Fatal("invented coverage count passed accounting")
		}
		r.Counts["unsupported"] = 0
		got, err := load[map[string]any](filepath.Join(candidatesDir, "anthropic.json"))
		if err != nil {
			t.Fatal(err)
		}
		expected := mapsForTest(op)
		delete(expected, "id")
		expected["action"] = "messages.generate"
		if !reflect.DeepEqual(httpSection(got)["operations"].(map[string]any)[op["id"].(string)], expected) {
			t.Fatalf("reviewed semantics changed: %+v", httpSection(got)["operations"])
		}
		got["title"] = "edited candidate"
		tampered, _ := json.Marshal(got)
		if err := os.WriteFile(filepath.Join(candidatesDir, "anthropic.json"), tampered, 0o644); err != nil {
			t.Fatal(err)
		}
		if err := checkReport(r, src, lock["anthropic"], "test-generator", false); err == nil {
			t.Fatal("changed candidate passed freshness check")
		}
		// The shipped preset is the baseline; changing it invalidates the report.
		op["action"] = "generate.updated"
		if err := writeJSON(filepath.Join(shippedDir, "anthropic.json"), record); err != nil {
			t.Fatal(err)
		}
		if round == 0 {
			if err := checkReport(r, src, lock["anthropic"], "test-generator", false); err == nil || !strings.Contains(err.Error(), "shipped presets changed") {
				t.Fatalf("shipped edit did not invalidate report: %v", err)
			}
		}
		if _, err := os.Stat("reviewed"); !os.IsNotExist(err) {
			t.Fatalf("generation created a duplicate baseline: %v", err)
		}
	}
	delete(op, "params")
	if err := writeJSON(filepath.Join(shippedDir, "anthropic.json"), map[string]any{"title": "Anthropic", "catalog": map[string]any{"actions": map[string]any{}}, "http": map[string]any{"operations": map[string]any{op["id"].(string): op}}}); err != nil {
		t.Fatal(err)
	}
	r, err := generateService("anthropic", src, lock)
	if err != nil || r.Counts["parameter_gaps"] != 1 || !slices.Equal(r.Operations[1].MissingParams, []string{"beta"}) {
		t.Fatalf("reviewed override hid an unsupported beta query: %+v, %v", r, err)
	}
}

func TestFailedRefreshPreservesLock(t *testing.T) {
	toolDirectory(t)
	oldTransport := http.DefaultTransport
	t.Cleanup(func() { http.DefaultTransport = oldTransport })
	http.DefaultTransport = roundTripFunc(func(r *http.Request) (*http.Response, error) {
		return &http.Response{StatusCode: http.StatusServiceUnavailable, Body: io.NopCloser(strings.NewReader("unavailable")), Request: r}, nil
	})
	ref := specRef{Format: "openapi", URL: "https://example.com/spec.json"}
	old := lockEntry{Source: ref.source(), URL: ref.URL, SHA256: "old"}
	lock := lockFile{"test": {old}}
	if err := update(map[string]source{"test": {Specs: []specRef{ref}}}, lock, []string{"test"}); err == nil {
		t.Fatal("failed refresh reported success")
	}
	if !reflect.DeepEqual(lock["test"], []lockEntry{old}) {
		t.Fatal("failed refresh replaced previous lock")
	}
}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }
