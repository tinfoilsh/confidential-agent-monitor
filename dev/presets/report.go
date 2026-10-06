package main

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
)

// A result is one service's row in the report.
type result struct {
	Service string         `json:"service"`
	Sources []string       `json:"sources"`
	Ops     int            `json:"ops"`
	Merged  int            `json:"merged"`
	Matched []string       `json:"matched"`
	Missing []string       `json:"missing"`
	Status  string         `json:"status"`
	Note    string         `json:"note,omitempty"`
	Adds    []string       `json:"adds,omitempty"`
	Effects map[string]int `json:"effects"`
}

var templateVar = regexp.MustCompile(`\$\{[^}]*\}`)

// endpointMatches says whether an n8n endpoint, relative to some base path, is one of the operation's routes.
func endpointMatches(endpoint string, d drafted) bool {
	method, path, ok := strings.Cut(endpoint, " ")
	if !ok || d.op.GraphQL != nil {
		return false
	}
	if !strings.Contains(method, "$") && method != d.op.Method {
		return false
	}
	path, _, _ = strings.Cut(path, "?")
	path = strings.TrimPrefix(templateVar.ReplaceAllStringFunc(strings.TrimSpace(path), func(string) string { return "{x}" }), "{x}")
	want := strings.Split(strings.Trim(path, "/"), "/")
	have := strings.Split(strings.Trim(d.op.Path, "/"), "/")
	if len(want) == 0 || len(want) > len(have) && !strings.HasSuffix(d.op.Path, "*}") {
		return false
	}
	if len(want) > len(have) {
		return true
	}
	have = have[len(have)-len(want):]
	for i := range want {
		if !strings.Contains(want[i], "{") && !strings.Contains(have[i], "{") && want[i] != have[i] {
			return false
		}
		if strings.Contains(want[i], "{") != strings.Contains(have[i], "{") && !strings.Contains(have[i], "{") {
			return false
		}
	}
	return true
}

func crossCheck(s *service, ops []drafted) (matched, missing []string) {
	var endpoints []string
	for _, n := range s.Nodes {
		for _, e := range n.Endpoints {
			if !slices.Contains(endpoints, e) {
				endpoints = append(endpoints, e)
			}
		}
	}
	for _, e := range endpoints {
		if slices.ContainsFunc(ops, func(d drafted) bool { return endpointMatches(e, d) }) {
			matched = append(matched, e)
		} else {
			missing = append(missing, e)
		}
	}
	return matched, missing
}

var paramSeg = regexp.MustCompile(`\{[^}]*\}`)

func routeShape(method, path string, graphql any) string {
	if g, ok := graphql.(map[string]any); ok {
		return fmt.Sprintf("graphql %v %v", g["operation"], g["field"])
	}
	return method + " " + paramSeg.ReplaceAllString(path, "{}")
}

// shippedAdds lists the drafted routes a shipped preset has no operation for.
func shippedAdds(name string, ops []drafted) ([]string, error) {
	var shipped struct {
		Operations []struct {
			Method, Path string
			GraphQL      any `json:"graphql"`
		}
	}
	have := map[string]bool{}
	// One service can span several shipped presets, such as Jira and Confluence.
	for _, file := range strings.Split(name, ",") {
		src, err := os.ReadFile(filepath.Join(shippedDir, file+".json"))
		if err == nil {
			err = json.Unmarshal(src, &shipped)
		}
		if err != nil {
			return nil, err
		}
		for _, o := range shipped.Operations {
			have[routeShape(o.Method, o.Path, o.GraphQL)] = true
		}
	}
	var adds []string
	for _, d := range ops {
		var g any
		if d.op.GraphQL != nil {
			g = map[string]any{"operation": d.op.GraphQL[0], "field": d.op.GraphQL[1]}
		}
		if shape := routeShape(d.op.Method, d.op.Path, g); !have[shape] {
			adds = append(adds, fmt.Sprintf("%s %s (%s)", d.op.ID, shape, d.effect))
		}
	}
	return adds, nil
}
