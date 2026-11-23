package migrate

import (
	"encoding/json"
	"fmt"
	"maps"
	"slices"
	"strings"

	"github.com/tinfoilsh/confidential-agent-monitor/cmd/perimeter/config"
	"github.com/tinfoilsh/confidential-agent-monitor/core/tomledit"
)

const (
	version4    = 4
	version5    = 5
	legacyFacts = 14
	// The owner policy onboarding wrote before admissions stopped carrying an operation.
	legacyAllowKnown = "package sentinel\n\nallow if input.facts.operation != null\n"
	operationHint    = "admissions carry no operation; test input.facts.kind"
)

// Migration keeps the policy as it was before the upgrade, so the first unlock can report what changed.
type Migration struct {
	Policy  string
	Notices []Notice
}

type Notice struct {
	Path string `json:"path"`
	Hint string `json:"hint"`
}

// An effects table outside an access block was a grant a more specific one could widen; it is a limit now.
func upgradeV4(plain []byte) ([]byte, *Migration, error) {
	var v4 struct {
		Version int    `json:"version"`
		Policy  string `json:"policy"`
	}
	if err := json.Unmarshal(plain, &v4); err != nil {
		return nil, nil, err
	}
	if v4.Version >= version5 {
		return plain, nil, nil
	}
	var doc map[string]json.RawMessage
	if err := json.Unmarshal(plain, &doc); err != nil {
		return nil, nil, err
	}
	source, err := tomledit.Read(v4.Policy)
	if err != nil {
		return nil, nil, err
	}
	migration, policy := Migration{Policy: v4.Policy}, v4.Policy
	changes := ruleChanges(source)
	move := func(table map[string]any, hint func(effect string) string, at ...string) {
		effects, _ := table["effects"].(map[string]any)
		from := slices.Concat(at, []string{"effects"})
		kept := 0
		for _, effect := range slices.Sorted(maps.Keys(effects)) {
			if effects[effect] != "allow" {
				kept++
				continue
			}
			// An allow would cap nothing as a limit, so the upgrade drops it.
			changes = append(changes, tomledit.Change{Path: slices.Concat(from, []string{effect}), Delete: true})
			migration.Notices = append(migration.Notices, Notice{Path: tomledit.Path(slices.Concat(from, []string{effect})...), Hint: hint(effect)})
		}
		switch {
		case kept != 0:
			changes = append(changes, tomledit.Change{Path: slices.Concat(at, []string{"limits", "effects"}), From: from})
		case table["effects"] != nil:
			changes = append(changes, tomledit.Change{Path: from, Delete: true})
		}
	}
	move(source, func(e string) string {
		return fmt.Sprintf("%s was allowed for every identity; grant it per connection with default_access.<C>.effects.%s = \"allow\"", e, e)
	})
	for _, kind := range []string{"connections", "identities"} {
		for _, name := range slices.Sorted(maps.Keys(tomledit.Table(source, kind))) {
			hint := func(e string) string {
				return fmt.Sprintf("%s was allowed on %s for every identity; grant it with %s.effects.%s = \"allow\"", e, name, tomledit.Path("default_access", name), e)
			}
			if kind == "identities" {
				hint = func(e string) string {
					return fmt.Sprintf("%s was allowed for %s on every connection; grant it per connection with %s.<C>.effects.%s = \"allow\"", e, name, tomledit.Path("identities", name, "connections"), e)
				}
			}
			move(tomledit.Table(source, kind, name), hint, kind, name)
		}
	}
	for _, name := range slices.Sorted(maps.Keys(tomledit.Table(source, "identities"))) {
		routes, set := tomledit.Table(source, "identities", name)["routes"]
		if set {
			changes = append(changes, tomledit.Change{Path: []string{"identities", name, "routes"}, Delete: true})
		}
		if routes == true {
			changes = append(changes, tomledit.Change{Path: []string{"identities", name, "connections", config.PerimeterConnection}, Value: map[string]any{"actions": config.DeviceActions()}})
		}
	}
	policies := tomledit.Table(source, "policies")
	for _, name := range slices.Sorted(maps.Keys(policies)) {
		switch text, _ := policies[name].(string); {
		case text == legacyAllowKnown:
			changes = append(changes, tomledit.Change{Path: []string{"policies", name}, Value: allowKnown})
		case text != allowKnown && strings.Contains(text, "input.facts.operation"):
			migration.Notices = append(migration.Notices, Notice{Path: tomledit.Path("policies", name), Hint: operationHint})
		}
	}
	if len(changes) != 0 {
		if policy, err = tomledit.Edit(policy, changes); err != nil {
			return nil, nil, err
		}
	}
	doc["version"], _ = json.Marshal(version5)
	doc["policy"], _ = json.Marshal(policy)
	plain, err = json.Marshal(doc)
	return plain, &migration, err
}

// A version 14 rule's ask waived the level's ask, never an effects table's, so it waives each effect those tables allowed.
func ruleChanges(source map[string]any) []tomledit.Change {
	var changes []tomledit.Change
	for _, identity := range slices.Sorted(maps.Keys(tomledit.Table(source, "identities"))) {
		rules := tomledit.Table(source, "identities", identity, "rules")
		for _, id := range slices.Sorted(maps.Keys(rules)) {
			rule := tomledit.Table(rules, id)
			if version, _ := rule["version"].(int64); version != legacyFacts {
				continue
			}
			connection, _ := rule["connection"].(string)
			requirements := []config.Requirement{}
			add := func(r config.Requirement) {
				if !slices.Contains(requirements, r) {
					requirements = append(requirements, r)
				}
			}
			listed, _ := rule["requirements"].([]any)
			for _, value := range listed {
				r, _ := value.(map[string]any)
				id, _ := r["id"].(string)
				message, _ := r["message"].(string)
				if id != "ask" {
					add(config.Requirement{ID: id, Message: message})
					continue
				}
				for _, e := range slices.Sorted(maps.Keys(config.Vocabulary)) {
					if legacyEffect(source, identity, connection, e) == config.ModeAllow {
						add(config.Requirement{ID: "effect." + e, Message: fmt.Sprintf("The %s effect requires approval (Ask).", e)})
					}
				}
			}
			at := []string{"identities", identity, "rules", id}
			changes = append(changes, tomledit.Change{Path: slices.Concat(at, []string{"requirements"}), Value: requirements},
				tomledit.Change{Path: slices.Concat(at, []string{"version"}), Value: config.FactsVersion})
		}
	}
	return changes
}

// An access block with a level replaced default_access whole; the most specific effects table that set the effect won.
func legacyEffect(source map[string]any, identity, connection, effect string) config.Mode {
	own := tomledit.Table(source, "identities", identity, "connections", connection)
	scopes := []map[string]any{tomledit.Table(own, "effects")}
	if level, _ := own["level"].(string); level == "" {
		scopes = append(scopes, tomledit.Table(source, "default_access", connection, "effects"))
	}
	scopes = append(scopes, tomledit.Table(source, "identities", identity, "effects"), tomledit.Table(source, "connections", connection, "effects"), tomledit.Table(source, "effects"))
	for _, scope := range scopes {
		if mode, set := scope[effect].(string); set {
			return config.Mode(mode)
		}
	}
	if config.Vocabulary[effect].Ask {
		return config.ModeAsk
	}
	return config.ModeAllow
}
