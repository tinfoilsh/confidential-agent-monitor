package main

import (
	"context"
	"encoding/json"
	"fmt"
	"net/url"
	"regexp"
	"slices"
	"strings"

	"github.com/getkin/kin-openapi/openapi3"
	"github.com/oasdiff/yaml"
)

func requestDocument(src []byte, swagger, pinned bool) ([]byte, error) {
	var doc map[string]any
	if err := json.Unmarshal(src, &doc); err != nil {
		if _, err := yaml.Unmarshal(src, &doc, yaml.DecodeOpts{DisableTimestamps: true}); err != nil {
			return nil, err
		}
	}
	delete(doc, "webhooks")
	var unresolved []string
	paths, _ := doc["paths"].(map[string]any)
	for _, value := range paths {
		item, _ := value.(map[string]any)
		for method, value := range item {
			if !httpMethods.MatchString(method) {
				continue
			}
			if op, ok := value.(map[string]any); ok {
				delete(op, "responses")
				delete(op, "callbacks")
			}
		}
	}
	used := map[string]bool{}
	missing := map[string]bool{}
	external := map[string]bool{}
	var walk func(any, string)
	walk = func(v any, name string) {
		switch x := v.(type) {
		case map[string]any:
			if ref, _ := x["$ref"].(string); ref != "" && !strings.HasPrefix(ref, "#") {
				external[ref] = true
			}
			if ref, _ := x["$ref"].(string); missing[ref] {
				delete(x, "$ref")
			}
			if ref, ok := x["$ref"].(string); ok && strings.HasPrefix(ref, "#/") && !used[ref] {
				used[ref] = true
				var target any = doc
				for _, segment := range strings.Split(ref[2:], "/") {
					key := strings.ReplaceAll(strings.ReplaceAll(segment, "~1", "/"), "~0", "~")
					m, _ := target.(map[string]any)
					target = m[key]
				}
				if target == nil {
					missing[ref] = true
					unresolved = append(unresolved, ref)
					delete(x, "$ref")
				}
				walk(target, "")
			}
			for key, child := range x {
				if annotation(name, key) {
					delete(x, key)
					continue
				}
				walk(child, key)
			}
		case []any:
			for _, child := range x {
				walk(child, "")
			}
		}
	}
	walk(paths, "")
	if len(external) > 0 && !pinned {
		return nil, fmt.Errorf("request schemas contain unpinned external references; run update to lock relative ones: %s", strings.Join(sortedKeys(external), ", "))
	}
	if len(unresolved) > 0 {
		slices.Sort(unresolved)
		doc["x-monitor-unresolved-refs"] = unresolved
	}
	prune := func(values map[string]any, prefix string) {
		for name := range values {
			ref := prefix + strings.ReplaceAll(strings.ReplaceAll(name, "~", "~0"), "/", "~1")
			keep := false
			for usedRef := range used {
				if usedRef == ref || strings.HasPrefix(usedRef, ref+"/") {
					keep = true
					break
				}
			}
			if !keep {
				delete(values, name)
			}
		}
	}
	if swagger {
		for _, key := range []string{"definitions", "parameters", "responses"} {
			values, _ := doc[key].(map[string]any)
			prune(values, "#/"+key+"/")
		}
	} else if components, ok := doc["components"].(map[string]any); ok {
		for key, value := range components {
			if key == "securitySchemes" {
				continue
			}
			values, _ := value.(map[string]any)
			prune(values, "#/components/"+key+"/")
		}
	}
	return json.Marshal(doc)
}

// annotation reports whether key holds examples or extensions, which requests never need, rather than a property of that name.
func annotation(parent, key string) bool {
	return parent != "properties" && (key == "example" || key == "examples" || strings.HasPrefix(key, "x-"))
}

var colonParam = regexp.MustCompile(`(^|/):([A-Za-z_][A-Za-z0-9_]*)`)

// requestPath splits a path key into its route, query conditions, and fragment, which may name a query variant.
func requestPath(raw string) (string, map[string]any, map[string]any, error) {
	target, fragment, _ := strings.Cut(strings.TrimSpace(raw), "#")
	path, query, _ := strings.Cut(target, "?")
	var sets [2]map[string]any
	for i, part := range []string{query, fragment} {
		if part == "" {
			continue
		}
		values, err := url.ParseQuery(part)
		if err != nil {
			return "", nil, nil, fmt.Errorf("path %q: %w", raw, err)
		}
		sets[i] = map[string]any{}
		for key, value := range values {
			if len(value) != 1 {
				return "", nil, nil, fmt.Errorf("path %q repeats query parameter %q", raw, key)
			}
			sets[i][key] = value[0]
		}
	}
	return colonParam.ReplaceAllString(path, "$1{$2}"), sets[0], sets[1], nil
}

func bundle(src []byte, location string, files map[string][]byte) ([]byte, error) {
	base, err := url.Parse(location)
	if err != nil {
		return nil, err
	}
	loader := openapi3.NewLoader()
	loader.ReadFromURIFunc = func(_ *openapi3.Loader, u *url.URL) ([]byte, error) {
		if src, ok := files[u.String()]; ok {
			return src, nil
		}
		return nil, fmt.Errorf("%s is not locked; run update", u)
	}
	doc, err := loader.LoadFromDataWithPath(src, base)
	if err != nil {
		return nil, err
	}
	doc.InternalizeRefs(context.Background(), nil)
	return doc.MarshalJSON()
}
