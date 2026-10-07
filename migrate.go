package main

import (
	"encoding/json"
	"fmt"
	"maps"
	"reflect"
	"strings"

	"github.com/tinfoilsh/monitor/connector"
)

// migratePresets rewrites legacy account selectors before validation. It preserves
// connections and owner records; saved approvals expire with the policy digest.
func migratePresets(raw json.RawMessage) (json.RawMessage, bool, error) {
	var cfg map[string]any
	if err := connector.DecodeNumbers(raw, &cfg); err != nil {
		return nil, false, err
	}
	object := func(v any) map[string]any { m, _ := v.(map[string]any); return m }
	changed := false
	github := map[string]bool{}
	owned := object(cfg["presets"])
	for name, value := range object(cfg["accounts"]) {
		a := object(value)
		options := object(a["policy_options"])
		if template, ok := a["template"].(string); ok {
			preset := template
			if template == "api" {
				preset, _ = options["preset"].(string)
				if preset == "" {
					return nil, false, fmt.Errorf("account %s: legacy api account has no preset", name)
				}
			} else if options["preset"] != nil {
				return nil, false, fmt.Errorf("account %s: a legacy preset requires template api", name)
			}
			if current, exists := a["preset"]; exists && current != preset {
				return nil, false, fmt.Errorf("account %s: preset conflicts with legacy template", name)
			}
			a["preset"] = preset
			delete(a, "template")
			delete(options, "preset")
			changed = true
		}
		// An owner-defined github_api remains an independent, data-only preset.
		if a["preset"] == "github_api" && owned["github_api"] == nil {
			if owned["github"] != nil {
				return nil, false, fmt.Errorf("account %s: owner github preset conflicts with legacy github_api", name)
			}
			a["preset"] = "github"
			github[name], changed = true, true
		}
	}
	for _, value := range object(cfg["identities"]) {
		for name, value := range object(object(value)["accounts"]) {
			if !github[name] {
				continue
			}
			access := object(value)
			actions := object(access["actions"])
			next := maps.Clone(actions)
			for _, old := range []string{"write", "write.issues", "write.pulls", "write.contents", "admin", "admin.merge"} {
				delete(next, old)
			}
			for old, replacements := range map[string][]string{
				"write.issues": {"open.issues", "comment"}, "write.pulls": {"open.pulls"},
				"write.contents": {"push"}, "admin.merge": {"merge"},
			} {
				mode, ok := actions[old]
				if !ok {
					mode, ok = actions[strings.Split(old, ".")[0]]
				}
				if !ok {
					continue
				}
				for _, action := range replacements {
					if current, exists := next[action]; exists && !reflect.DeepEqual(current, mode) {
						return nil, false, fmt.Errorf("account %s: conflicting permissions for %s", name, action)
					}
					next[action] = mode
				}
			}
			if actions != nil {
				access["actions"] = next
			}
		}
	}
	if !changed {
		return raw, false, nil
	}
	raw, err := json.Marshal(cfg)
	return raw, true, err
}
