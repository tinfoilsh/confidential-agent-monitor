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

// An effects entry in an access block beats its level, so each block takes what its level and every table in scope made of each effect.
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
	defaults, identities, connections := tomledit.Table(source, "default_access"), tomledit.Table(source, "identities"), tomledit.Table(source, "connections")
	reaches := func(level string, actions map[string]any) bool {
		return level != "" && level != "off" || slices.ContainsFunc(slices.Collect(maps.Values(actions)), func(mode any) bool { return mode != string(config.ModeOff) })
	}
	rewrite := func(at []string, identity, block map[string]any, connection, level string, inherits bool) {
		d := tomledit.Table(defaults, connection)
		effects, actions, inherited := map[string]any{}, tomledit.Table(block, "actions"), tomledit.Table(d, "actions")
		reachable := actions
		if inherits {
			reachable = map[string]any{}
			maps.Copy(reachable, inherited)
			maps.Copy(reachable, actions)
		}
		shared, _ := d["level"].(string)
		open, shares := reaches(level, reachable), reaches(shared, inherited)
		for e, o := range config.Vocabulary {
			mode, set := legacyEffect(source, identity, connection, e)
			beneath, under := legacyEffect(source, nil, connection, e)
			grant := config.ModeAllow
			switch {
			case level == "" || level == "off" || level == "read" && o.Change:
				grant = config.ModeOff
			case level == "ask" && o.Change:
				grant = config.ModeAsk
			}
			switch {
			case e == config.EffectUnknown:
			case e == "session":
				// Beneath an identity, default_access answers an admission with its session entry, and an operation too when the identity has no level.
				admit, operate := config.ModeAllow, grant
				if identity != nil && shares && under && beneath != config.ModeAllow {
					admit = beneath
					if inherits {
						operate = beneath
					}
				}
				if !open {
					admit, mode = config.ModeOff, config.ModeOff
				}
				if admit != mode || operate != max(grant, mode) {
					effects[e] = mode
				}
			case inherits && under && mode == beneath:
			// Modes sort from most to least permissive, so the greater is the stricter.
			case set && (inherits || grant != config.ModeOff):
				effects[e] = max(grant, mode)
			}
		}
		// The identity's own entries would hide the actions of default_access, which merged with its own.
		if inherits && (len(effects) != 0 || len(actions) != 0) {
			if len(reachable) != len(actions) {
				changes = append(changes, tomledit.Change{Path: slices.Concat(at, []string{"actions"}), Value: reachable})
			}
			actions = reachable
		}
		if len(effects) != 0 {
			changes = append(changes, tomledit.Change{Path: slices.Concat(at, []string{"effects"}), Value: effects})
		} else if block["effects"] != nil {
			changes = append(changes, tomledit.Change{Path: slices.Concat(at, []string{"effects"}), Delete: true})
		}
		var unasked []string
		for _, action := range slices.Sorted(maps.Keys(actions)) {
			allowed, _ := actions[action].(string)
			var lost []string
			for _, e := range slices.Sorted(maps.Keys(config.Vocabulary)) {
				switch mode, set := legacyEffect(source, identity, connection, e); {
				case e == config.EffectUnknown || string(mode) <= allowed:
				case set:
					lost = append(lost, fmt.Sprintf("%s (%s)", e, mode))
				case !slices.Contains(unasked, e):
					unasked = append(unasked, e)
				}
			}
			if lost != nil {
				migration.Notices = append(migration.Notices, Notice{Path: tomledit.Path(slices.Concat(at, []string{"actions", action})...), Hint: "this action is no longer restricted by effects " + strings.Join(lost, ", ")})
			}
		}
		if unasked != nil {
			migration.Notices = append(migration.Notices, Notice{Path: tomledit.Path(slices.Concat(at, []string{"actions"})...), Hint: "an action set to allow no longer asks for " + strings.Join(unasked, ", ")})
		}
	}
	for _, c := range slices.Sorted(maps.Keys(defaults)) {
		level, _ := tomledit.Table(defaults, c)["level"].(string)
		rewrite([]string{"default_access", c}, nil, tomledit.Table(defaults, c), c, level, false)
	}
	for _, name := range slices.Sorted(maps.Keys(identities)) {
		identity := tomledit.Table(identities, name)
		for _, c := range slices.Sorted(maps.Keys(connections)) {
			block, at := tomledit.Table(identity, "connections", c), []string{"identities", name, "connections", c}
			level, _ := block["level"].(string)
			switch inherited, inherits := tomledit.Table(defaults, c)["level"].(string); {
			case level == "" && inherits:
				rewrite(at, identity, block, c, inherited, true)
			case block != nil:
				rewrite(at, identity, block, c, level, false)
			}
		}
		changes = append(changes, tomledit.Change{Path: []string{"identities", name, "effects"}, Delete: true}, tomledit.Change{Path: []string{"identities", name, "routes"}, Delete: true})
		if groups, _ := identity["groups"].([]any); identity["routes"] == true && !slices.Contains(groups, any(config.DeviceGroup)) {
			changes = append(changes, tomledit.Change{Path: []string{"identities", name, "groups"}, Value: append(groups, config.DeviceGroup)})
		}
	}
	changes = append(changes, tomledit.Change{Path: []string{"effects"}, Delete: true})
	for _, c := range slices.Sorted(maps.Keys(connections)) {
		changes = append(changes, tomledit.Change{Path: []string{"connections", c, "effects"}, Delete: true})
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
	if policy, err = tomledit.Edit(policy, changes); err != nil {
		return nil, nil, err
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
					if mode, _ := legacyEffect(source, tomledit.Table(source, "identities", identity), connection, e); mode == config.ModeAllow {
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
func legacyEffect(source, identity map[string]any, connection, effect string) (config.Mode, bool) {
	own := tomledit.Table(identity, "connections", connection)
	scopes := []map[string]any{tomledit.Table(own, "effects")}
	if level, _ := own["level"].(string); level == "" {
		scopes = append(scopes, tomledit.Table(source, "default_access", connection, "effects"))
	}
	scopes = append(scopes, tomledit.Table(identity, "effects"), tomledit.Table(source, "connections", connection, "effects"), tomledit.Table(source, "effects"))
	for _, scope := range scopes {
		if mode, set := scope[effect].(string); set {
			return config.Mode(mode), true
		}
	}
	if config.Vocabulary[effect].Ask {
		return config.ModeAsk, false
	}
	return config.ModeAllow, false
}
