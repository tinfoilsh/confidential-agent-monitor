package main

import (
	"encoding/json"
	"fmt"
	"net/url"
	"slices"
	"strings"

	"github.com/oasdiff/yaml"
)

// requestDocument retains only schemas reachable from requests. A broken
// response example must not prevent us from inventorying a provider's requests.
func requestDocument(src []byte, swagger bool) ([]byte, error) {
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
	// Start from paths, following local references before pruning components.
	used := map[string]bool{}
	missing := map[string]bool{}
	external := map[string]bool{}
	var walk func(any)
	walk = func(v any) {
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
				walk(target)
			}
			for _, child := range x {
				walk(child)
			}
		case []any:
			for _, child := range x {
				walk(child)
			}
		}
	}
	walk(paths)
	if len(external) > 0 {
		return nil, fmt.Errorf("request schemas contain unpinned external references; vendor them into the locked specification: %s", strings.Join(sortedKeys(external), ", "))
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

func requestPath(raw string) (string, map[string]any, error) {
	path, query, hasQuery := strings.Cut(raw, "?")
	if !hasQuery {
		return path, nil, nil
	}
	values, err := url.ParseQuery(query)
	if err != nil {
		return "", nil, fmt.Errorf("path %q: %w", raw, err)
	}
	conditions := map[string]any{}
	for key, value := range values {
		if len(value) != 1 {
			return "", nil, fmt.Errorf("path %q repeats query parameter %q", raw, key)
		}
		conditions[key] = value[0]
	}
	return path, conditions, nil
}
