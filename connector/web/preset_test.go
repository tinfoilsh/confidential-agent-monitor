package web

import (
	"encoding/json"
	"fmt"
	"maps"
	"net/http"
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"slices"
	"strings"
	"testing"

	"github.com/tinfoilsh/monitor/connector"
	"github.com/tinfoilsh/monitor/facts"
)

func TestHTTPSelectorsUseFactsSchema(t *testing.T) {
	for _, h := range []*facts.HTTP{
		{},
		{Method: "POST", Origin: "https://example.com", Query: map[string][]string{"q": {"one", "two"}, "null": nil}, Headers: http.Header{"X-Test": {"one"}}, Secrets: []string{}, Body: map[string]any{"number": json.Number("9007199254740993"), "items": []any{"one", nil}}, Form: map[string][]string{"value": {"one"}}, HeaderJSON: map[string]any{"X-Arg": map[string]any{"id": "one"}}},
	} {
		raw, _ := json.Marshal(h)
		var reference any
		if err := facts.DecodeNumbers(raw, &reference); err != nil {
			t.Fatal(err)
		}
		for _, at := range []string{"", "/method", "/origin", "/path", "/missing", "/query", "/query/q/0", "/query/q/01", "/query/null", "/headers/X-Test/0", "/secrets", "/body", "/body/number", "/body/items/1", "/form", "/header_json/X-Arg/id"} {
			reader, err := compileSelector(Selector{From: "http", At: at})
			if err != nil {
				t.Fatal(err)
			}
			fields, _ := facts.JSON[map[string]any](h)
			got, present := reader.value(&Request{HTTP: h}, nil, fields)
			want, exists := testPointer(reference, at)
			if present != exists {
				t.Fatalf("%s presence: got %v want %v", at, present, exists)
			}
			if present && connector.JSONType(got) != connector.JSONType(want) {
				t.Fatalf("%s type: got %T want %T", at, got, want)
			}
			frozen, err := facts.JSON[any](got)
			if err != nil {
				t.Fatal(err)
			}
			if !reflect.DeepEqual(frozen, want) {
				t.Fatalf("%s: got %#v want %#v", at, frozen, want)
			}
		}
	}

}

func TestIndexedMatchingMatchesLinear(t *testing.T) {
	files, err := filepath.Glob("../../presets/*.json")
	if err != nil {
		t.Fatal(err)
	}
	capture := regexp.MustCompile(`\{[^{}]+\}`)
	checked := 0
	for _, file := range files {
		raw, err := os.ReadFile(file)
		if err != nil {
			t.Fatal(err)
		}
		var record struct {
			HTTP *Preset `json:"http"`
		}
		if err := json.Unmarshal(raw, &record); err != nil {
			t.Fatal(err)
		}
		p := record.HTTP
		if p == nil {
			continue
		}
		compiled, err := p.Compile()
		if err != nil {
			t.Fatal(file, err)
		}
		names := slices.Sorted(maps.Keys(p.Operations))
		for i := 0; i < len(names); i += max(1, len(names)/24) {
			o := p.Operations[names[i]]
			origin, method, path := o.Origin, o.Method, capture.ReplaceAllString(o.Path, "one")
			if origin == "*" || origin == "{origin}" {
				origin = "https://example.com"
			}
			if method == "*" {
				method = "GET"
			}
			if path == "*" {
				path = "/one"
			}
			r := Request{HTTP: &facts.HTTP{Origin: origin, Method: method, Path: path, Query: map[string][]string{}, Headers: http.Header{}, BodyKind: o.Body}}
			if r.HTTP.BodyKind == "" {
				r.HTTP.BodyKind = "none"
			}
			if o.Body == "json" {
				r.HTTP.Body = map[string]any{}
			}
			for key, value := range o.Query {
				if value != nil {
					r.HTTP.Query[key] = []string{value.(string)}
				}
			}
			for key, value := range o.Headers {
				if value != nil {
					r.HTTP.Headers[key] = []string{value.(string)}
				}
			}
			if o.GraphQL != nil {
				r.HTTP.BodyKind = "json"
				r.GraphQL = &facts.GraphQL{Kind: o.GraphQL.Operation}
				names := o.GraphQL.Fields
				if o.GraphQL.Field != "" {
					names = []string{o.GraphQL.Field}
				}
				for _, name := range names {
					r.GraphQL.Fields = append(r.GraphQL.Fields, facts.GraphQLField{Name: name})
				}
			}
			for _, suffix := range []string{"", "/", "/unmatched"} {
				r.HTTP.Path = path + suffix
				expected := ""
				var referenceErr error
				for id, op := range p.Operations {
					match, err := legacyMatch(op, r, "https://example.com")
					if err != nil {
						referenceErr = err
						break
					}
					if match {
						if expected != "" {
							referenceErr = fmt.Errorf("the request matches more than one reviewed operation")
							break
						}
						expected = id
					}
				}
				config := &HTTP{Credentials: Credentials{Slots: []Slot{{Origin: origin, Path: "/"}}}}
				f, gotErr := compiled.Match(&r, connector.Context{Config: config, Options: connector.PolicyOptions{Origin: "https://example.com"}}, facts.Facts{})
				if referenceErr != nil {
					if gotErr == nil || gotErr.Error() != referenceErr.Error() {
						t.Fatalf("%s %s: index error %v, linear %v", file, r.HTTP.Path, gotErr, referenceErr)
					}
				} else {
					actual := ""
					if f.Operation != nil {
						actual = f.Operation.ID
					}
					if actual != expected {
						t.Fatalf("%s %s: index %q (%v), linear %q", file, r.HTTP.Path, actual, gotErr, expected)
					}
				}
				checked++
			}
		}
	}
	if checked < 1000 {
		t.Fatalf("only compared %d requests", checked)
	}
}

func legacyMatch(o Operation, r Request, originOption string) (bool, error) {
	h := r.HTTP
	origin := o.Origin
	if origin == "{origin}" {
		origin = originOption
	}
	if (o.Method != "*" && h.Method != o.Method) || (origin != "*" && h.Origin != origin) {
		return false, nil
	}
	caps, err := legacyCaptures(o.Path, h.Path)
	if err != nil || caps == nil {
		return false, nil
	}
	for k, v := range o.Query {
		if !condition(h.Query, k, v) {
			return false, nil
		}
	}
	headers := map[string][]string{}
	for k, v := range h.Headers {
		headers[strings.ToLower(k)] = append(headers[strings.ToLower(k)], v...)
	}
	for k, v := range o.Headers {
		if !condition(headers, strings.ToLower(k), v) {
			return false, nil
		}
	}
	for k := range h.Query {
		if _, ok := o.Query[k]; !ok && !o.OpenParams && !slices.Contains(o.Params, k) {
			return false, nil
		}
	}
	body := o.Body
	if body == "" {
		body = "none"
	}
	for k, v := range o.Fields {
		switch body {
		case "form":
			if !condition(h.Form, k, v) {
				return false, nil
			}
		case "json":
			got, present := testPointer(h.Body, k)
			if v == nil {
				if present {
					return false, nil
				}
			} else if !present || !connector.EqualJSON(got, v) {
				return false, nil
			}
		default:
			return false, nil
		}
	}
	if body == "any" {
		return true, nil
	}
	if body == "graphql" {
		g, spec := r.GraphQL, o.GraphQL
		if g == nil {
			return false, fmt.Errorf("the GraphQL document could not be decoded")
		}
		if h.BodyKind != "json" || g.Kind != spec.Operation || len(g.Fields) == 0 {
			return false, nil
		}
		if spec.Field != "" {
			return spec.Field == "*" || len(g.Fields) == 1 && g.Fields[0].Name == spec.Field, nil
		}
		return !slices.ContainsFunc(g.Fields, func(f facts.GraphQLField) bool { return !slices.Contains(spec.Fields, f.Name) }), nil
	}
	return h.BodyKind == body, nil
}

func legacyCaptures(pattern, value string) (map[string]string, error) {
	pp, vv := strings.Split(pattern, "/"), strings.Split(value, "/")
	out := map[string]string{}
	if pattern == "*" {
		return out, nil
	}
	for i, part := range pp {
		if i >= len(vv) {
			return nil, nil
		}
		if strings.HasPrefix(part, "{") && strings.HasSuffix(part, "*}") && i == len(pp)-1 {
			name := part[1 : len(part)-2]
			if name == "" {
				return nil, fmt.Errorf("empty path capture")
			}
			rest := strings.Join(vv[i:], "/")
			if rest == "" {
				return nil, nil
			}
			out[name] = rest
			return out, nil
		}
		prefix, rest, has := strings.Cut(part, "{")
		if !has {
			if part != vv[i] {
				return nil, nil
			}
			continue
		}
		name, suffix, ok := strings.Cut(rest, "}")
		if !ok || name == "" || strings.ContainsAny(name+suffix, "{}*") {
			return nil, fmt.Errorf("invalid path capture %s", part)
		}
		if !strings.HasPrefix(vv[i], prefix) || !strings.HasSuffix(vv[i], suffix) || len(vv[i]) <= len(prefix)+len(suffix) {
			return nil, nil
		}
		out[name] = vv[i][len(prefix) : len(vv[i])-len(suffix)]
	}
	if len(pp) != len(vv) {
		return nil, nil
	}
	return out, nil
}

func TestCompiledPresetKeepsReplacedOperations(t *testing.T) {
	raw := &Preset{Operations: map[string]Operation{"read": {ID: "read", Action: "read", Effects: []string{"read"}, Method: "GET", Origin: "*", Path: "/items/{id}", Scope: map[string]Selector{"id": {From: "path", At: "id"}}}}}
	compiled, err := raw.Compile()
	if err != nil {
		t.Fatal(err)
	}
	raw.Operations["read"] = Operation{ID: "read", Path: "/other", Effects: []string{"delete"}, Scope: map[string]Selector{"id": {From: "body", At: "/changed"}}}
	f, err := compiled.Match(&Request{HTTP: &facts.HTTP{Method: "GET", Origin: "https://example.com", Path: "/items/one", BodyKind: "none"}}, connector.Context{}, facts.Facts{})
	if err != nil || f.Operation == nil || !slices.Equal(f.Operation.Effects, []string{"read"}) || f.Parameters["id"] != "one" {
		t.Fatalf("raw edit changed compiled preset: %+v, %v", f, err)
	}
}

func testPointer(doc any, at string) (any, bool) {
	read, err := connector.CompilePointer(at)
	if err != nil {
		return nil, false
	}
	return read(doc)
}

// Compare the route index with a flat scan of the same compiled paths.
func BenchmarkPresetRouting(b *testing.B) {
	files, _ := filepath.Glob("../../presets/*.json")
	var largest *Preset
	var name string
	for _, file := range files {
		raw, err := os.ReadFile(file)
		if err != nil {
			b.Fatal(err)
		}
		var record struct {
			HTTP *Preset `json:"http"`
		}
		if err := json.Unmarshal(raw, &record); err != nil {
			b.Fatal(err)
		}
		if record.HTTP != nil && (largest == nil || len(record.HTTP.Operations) > len(largest.Operations)) {
			largest, name = record.HTTP, filepath.Base(file)
		}
	}
	p, err := largest.Compile()
	if err != nil {
		b.Fatal(err)
	}
	type route struct {
		key routeKey
		op  *compiledOperation
	}
	var all []route
	var collect func(routeKey, *routeNode)
	collect = func(key routeKey, node *routeNode) {
		if node == nil {
			return
		}
		for _, op := range append(slices.Clone(node.exact), node.rest...) {
			all = append(all, route{key, op})
		}
		collect(key, node.capture)
		for _, child := range node.literal {
			collect(key, child)
		}
	}
	for key, node := range p.routes {
		collect(key, node)
	}
	slices.SortFunc(all, func(a, c route) int { return strings.Compare(a.op.operation.ID, c.op.operation.ID) })
	selected := all[len(all)/2]
	path := strings.Split(regexp.MustCompile(`\{[^{}]+\}`).ReplaceAllString(selected.op.operation.Path, "one"), "/")
	for _, indexed := range []bool{true, false} {
		mode := "linear"
		if indexed {
			mode = "indexed"
		}
		b.Run(fmt.Sprintf("%s/%d/%s", name, len(all), mode), func(b *testing.B) {
			var candidates []*compiledOperation
			b.ReportAllocs()
			for b.Loop() {
				candidates = candidates[:0]
				if indexed {
					candidates = p.routes[selected.key].candidates(path, candidates)
				} else {
					for _, route := range all {
						if route.key == selected.key {
							candidates = append(candidates, route.op)
						}
					}
				}
				matched := 0
				for _, op := range candidates {
					if _, ok := pathCaptures(op.path, path); ok {
						matched++
					}
				}
				if matched == 0 {
					b.Fatal("benchmark route was not found")
				}
			}
		})
	}
}

func TestNamedOperations(t *testing.T) {
	p := &Preset{Operations: map[string]Operation{
		"read": {Action: "read", Effects: []string{"read"}, Method: "GET", Origin: "*", Path: "/", Scope: map[string]Selector{}},
	}}
	compiled, err := p.Compile()
	if err != nil {
		t.Fatal(err)
	}
	r := &Request{HTTP: &facts.HTTP{Method: "GET", Origin: "https://example.com", Path: "/", BodyKind: "none"}}
	f, err := compiled.Match(r, connector.Context{}, facts.Facts{})
	if err != nil || f.Operation == nil || f.Operation.ID != "read" {
		t.Fatalf("operation ID did not come from its name: %+v, %v", f, err)
	}
	disabled := false
	p = &Preset{Operations: map[string]Operation{"read": {Enabled: &disabled}}}
	compiled, err = p.Compile()
	if err != nil {
		t.Fatal(err)
	}
	if len(p.Operations) != 1 {
		t.Fatal("compilation mutated the source operations")
	}
	f, err = compiled.Match(r, connector.Context{}, facts.Facts{})
	if err != nil || f.Operation != nil {
		t.Fatalf("disabled operation matched: %+v, %v", f, err)
	}
}
