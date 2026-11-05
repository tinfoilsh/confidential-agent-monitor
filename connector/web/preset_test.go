package web

import (
	"encoding/json"
	"net/url"
	"strings"
	"testing"

	"github.com/tinfoilsh/monitor/facts"
)

func patternPreset(t *testing.T, pattern string) *Preset {
	t.Helper()
	raw, err := json.Marshal(map[string]any{"operations": map[string]any{
		"by-id":  map[string]any{"action": "read", "effects": []string{"read"}, "method": "GET", "origin": "https://example.invalid", "path": "/releases/{id}", "path_patterns": map[string]string{"id": pattern}, "scope": map[string]any{"id": map[string]string{"from": "path", "at": "id"}}},
		"latest": map[string]any{"action": "latest.read", "effects": []string{"read"}, "method": "GET", "origin": "https://example.invalid", "path": "/releases/latest", "scope": map[string]any{}},
	}})
	if err != nil {
		t.Fatal(err)
	}
	var p Preset
	if err := json.Unmarshal(raw, &p); err != nil {
		t.Fatal(err)
	}
	return &p
}

func patternRequest(path string) *Request {
	return &Request{HTTP: &HTTPFacts{Method: "GET", Origin: "https://example.invalid", Host: "example.invalid", Path: path, Query: url.Values{}, BodyKind: "none"}}
}

func TestPathPatternsDisambiguateBeforeSelection(t *testing.T) {
	p := patternPreset(t, "[0-9]+")
	for _, tc := range []struct{ path, id string }{
		{"/releases/latest", "latest"}, {"/releases/123", "by-id"},
		{"/releases/0001", "by-id"}, {"/releases/999999999999999999999999999999", "by-id"},
		{"/releases/not-an-id", ""}, {"/releases/123latest", ""},
		{"/releases/latest123", ""}, {"/releases/-1", ""}, {"/releases/1.0", ""},
		{"/releases/١٢٣", ""}, {"/releases/123/extra", ""}, {"/releases/", ""},
	} {
		t.Run(tc.path, func(t *testing.T) {
			f, err := patternRequest(tc.path).Describe(&Setup{Preset: p})
			if err != nil {
				t.Fatal(err)
			}
			if tc.id == "" {
				if f.Operation != nil {
					t.Fatalf("unexpected match: %+v", f.Operation)
				}
			} else if f.Operation == nil || f.Operation.ID != tc.id {
				t.Fatalf("wanted %s, got %+v", tc.id, f.Operation)
			}
			if tc.id == "by-id" && f.Parameters["id"] != strings.TrimPrefix(tc.path, "/releases/") {
				t.Fatal("path parameter changed")
			}
		})
	}
}

func TestPathPatternsRemainAnchored(t *testing.T) {
	for _, pattern := range []string{"[0-9]+|version-[0-9]+", "(?m)[0-9]+$"} {
		p := patternPreset(t, pattern)
		for _, value := range []string{"x123", "123x", "123\nother", "other\n123"} {
			f, err := patternRequest("/releases/" + value).Describe(&Setup{Preset: p})
			if err != nil || f.Operation != nil {
				t.Fatalf("pattern %q unexpectedly matched %q: %+v, %v", pattern, value, f.Operation, err)
			}
		}
	}
}

func TestPathPatternsCompileValidation(t *testing.T) {
	for _, tc := range []struct{ path, name, pattern string }{
		{"/releases/{id}", "missing", "[0-9]+"},
		{"/releases/{id}", "", "[0-9]+"},
		{"/releases/{id}", "id", "["},
		{"*", "id", "[0-9]+"},
		{"/releases/{id}/{id}", "id", "[0-9]+"},
	} {
		t.Run(tc.path+tc.name+tc.pattern, func(t *testing.T) {
			raw, err := json.Marshal(map[string]any{"operations": map[string]any{"read": map[string]any{
				"action": "read", "effects": []string{"read"}, "method": "GET", "origin": "https://example.invalid",
				"path": tc.path, "path_patterns": map[string]string{tc.name: tc.pattern}, "scope": map[string]any{},
			}}})
			if err != nil {
				t.Fatal(err)
			}
			var p Preset
			if err := json.Unmarshal(raw, &p); err == nil {
				t.Fatal("invalid path constraint compiled")
			}
		})
	}
}

func TestPathPatternsDoNotIntroduceRoutePrecedence(t *testing.T) {
	p := patternPreset(t, ".+")
	_, err := patternRequest("/releases/latest").Describe(&Setup{Preset: p})
	if err == nil || !strings.Contains(err.Error(), "more than one") {
		t.Fatalf("genuine overlap must remain an error: %v", err)
	}
	p = patternPreset(t, "[0-9]+")
	delete(p.Operations["by-id"].PathPatterns, "id")
	if err := p.compile(); err != nil {
		t.Fatal(err)
	}
	if _, err := patternRequest("/releases/latest").Describe(&Setup{Preset: p}); err == nil {
		t.Fatal("unconstrained existing definitions must still overlap")
	}
}

func TestPathPatternsBindApprovalDefinition(t *testing.T) {
	definitions := map[string]bool{}
	for _, pattern := range []string{"[0-9]+", "[1-9][0-9]*"} {
		p := patternPreset(t, pattern)
		f, err := p.Match(patternRequest("/releases/123"), &Setup{Preset: p}, facts.Facts{})
		if err != nil || f.Operation == nil {
			t.Fatal("numeric route did not match", err)
		}
		definition, err := json.Marshal(f.Definition)
		if err != nil {
			t.Fatal(err)
		}
		definitions[string(definition)] = true
	}
	if len(definitions) != 2 {
		t.Fatal("changing a path constraint must invalidate old approvals")
	}
}
