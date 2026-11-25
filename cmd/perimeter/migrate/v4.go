package migrate

import (
	"cmp"
	"encoding/json"
	"fmt"
	"maps"
	"slices"
	"strings"

	"github.com/tinfoilsh/confidential-agent-monitor/cmd/perimeter/config"
	"github.com/tinfoilsh/confidential-agent-monitor/cmd/perimeter/connections"
	"github.com/tinfoilsh/confidential-agent-monitor/connector/catalog"
	"github.com/tinfoilsh/confidential-agent-monitor/core/facts"
	"github.com/tinfoilsh/confidential-agent-monitor/core/tomledit"
)

const (
	version4    = 4
	version5    = 5
	legacyFacts = 14
	// The owner policy onboarding wrote before admissions stopped carrying an operation.
	legacyAllowKnown = "package sentinel\n\nallow if input.facts.operation != null\n"
	operationHint    = "admissions carry no operation; test input.facts.kind"
	paidInference    = "allow_paid_inference"
)

// Level allow asked for these unless an effects table set them; it now allows every effect.
var legacyAsks = []string{"publish", "pay", config.EffectUnknown}

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
	presets, err := catalog.Load(catalog.Shipped)
	if err == nil {
		err = catalog.Compose(presets)
	}
	if err != nil {
		return nil, nil, err
	}
	var inference map[string]map[string][]string
	paid, _ := source[paidInference].(bool)
	if paid {
		if inference, err = inferenceActions(presets); err != nil {
			return nil, nil, err
		}
	}
	defaults, identities, connections := tomledit.Table(source, "default_access"), tomledit.Table(source, "identities"), tomledit.Table(source, "connections")
	operations := map[string]map[string][][]string{}
	for c := range connections {
		if ops, err := connectionOperations(presets, c, tomledit.Table(connections, c)); err == nil {
			operations[c] = ops
		}
	}
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
		legacy := map[string]config.Mode{}
		for e, o := range config.Vocabulary {
			mode, set := legacyEffect(source, identity, connection, e)
			beneath, under := legacyEffect(source, nil, connection, e)
			grant := config.ModeAllow
			switch {
			case level == "" || level == "off" || level == "read" && o.Integrity:
				grant = config.ModeOff
			case level == "ask" && o.Integrity:
				grant = config.ModeAsk
			}
			legacy[e] = max(grant, mode)
			switch {
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
			// An identity that inherits takes these from default_access, which writes them.
			case !set && !inherits && max(grant, mode) != grant:
				effects[e] = mode
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
		ops, known := operations[connection]
		if !known && len(actions) != 0 {
			ops = map[string][][]string{}
			for action := range actions {
				ops[action] = [][]string{slices.DeleteFunc(slices.Collect(maps.Keys(config.Vocabulary)), func(e string) bool { return e == config.EffectUnknown })}
			}
			migration.Notices = append(migration.Notices, Notice{Path: tomledit.Path(slices.Concat(at, []string{"actions"})...), Hint: "each action keeps the strictest mode any effect had, since this connection's operations could not be listed"})
		}
		restrict := func(effects []string, mode config.Mode) config.Mode {
			for _, e := range effects {
				m, set := legacyEffect(source, identity, connection, e)
				if e == "pay" && paid && !set && slices.Contains(effects, "generate") {
					m = config.ModeAllow
				}
				mode = max(mode, m)
			}
			return mode
		}
		kept := keepRestrictions(actions, ops, restrict)
		for _, action := range slices.Sorted(maps.Keys(kept)) {
			changes = append(changes, tomledit.Change{Path: slices.Concat(at, []string{"actions", action}), Value: string(kept[action])})
		}
		// Paid inference waived the pay ask that level allow made, unless an effects table set pay.
		if _, set := legacyEffect(source, identity, connection, "pay"); !paid || inherits || level != "allow" || set {
			return
		}
		preset, _ := tomledit.Table(connections, connection)["preset"].(string)
		paidActions, shipped := inference[preset]
		if !shipped {
			migration.Notices = append(migration.Notices, Notice{Path: tomledit.Path(at...), Hint: "AI inference now asks here, since this preset is not built in and its model calls cannot be told apart from other payments"})
		}
		for _, action := range slices.Sorted(maps.Keys(paidActions)) {
			// An owner's entry on the action or an ancestor already decides it.
			if slices.ContainsFunc(catalog.Lineage(action), func(a string) bool { _, ok := actions[a]; return ok }) ||
				slices.ContainsFunc(paidActions[action], func(e string) bool { return e != "pay" && legacy[e] != config.ModeAllow }) {
				continue
			}
			changes = append(changes, tomledit.Change{Path: slices.Concat(at, []string{"actions", action}), Value: string(config.ModeAllow)})
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
	changes = append(changes, tomledit.Change{Path: []string{"effects"}, Delete: true}, tomledit.Change{Path: []string{paidInference}, Delete: true})
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
	if slices.Contains(legacyAsks, effect) {
		return config.ModeAsk, false
	}
	return config.ModeAllow, false
}

// Paid model calls carry both generate and pay. An action counts only if every operation at or under it does,
// since its access entry also covers them. Each maps to the effects those operations carry.
func inferenceActions(presets map[string]*catalog.Preset) (map[string]map[string][]string, error) {
	inference := map[string]map[string][]string{}
	for name, p := range presets {
		var definition struct {
			HTTP struct {
				Operations map[string]struct {
					Action  string   `json:"action"`
					Effects []string `json:"effects"`
				} `json:"operations"`
			} `json:"http"`
		}
		if err := json.Unmarshal(p.Source, &definition); err != nil {
			return nil, fmt.Errorf("preset %s: %w", name, err)
		}
		operations := map[string][][]string{}
		for _, op := range definition.HTTP.Operations {
			operations[op.Action] = append(operations[op.Action], op.Effects)
		}
		for action, a := range p.Catalog.Actions {
			if a.Effects != nil {
				operations[action] = append(operations[action], a.Effects)
			}
		}
		inference[name] = map[string][]string{}
		for action := range operations {
			var effects []string
			paid := action != ""
			for under, carried := range operations {
				if !slices.Contains(catalog.Lineage(under), action) {
					continue
				}
				for _, op := range carried {
					paid = paid && slices.Contains(op, "generate") && slices.Contains(op, "pay")
					effects = append(effects, op...)
				}
			}
			if paid {
				inference[name][action] = slices.Compact(slices.Sorted(slices.Values(effects)))
			}
		}
	}
	return inference, nil
}

// The effects of each operation a connection can carry, by action: those its connector lists, or else one per catalog action.
func connectionOperations(presets map[string]*catalog.Preset, name string, table map[string]any) (map[string][][]string, error) {
	table = maps.Clone(table)
	delete(table, "effects")
	conn, err := facts.JSON[config.Connection](table)
	if err != nil {
		return nil, err
	}
	spec, err := (&config.Config{Connections: map[string]config.Connection{name: conn}, Presets: presets}).Spec(name)
	if err != nil {
		return nil, err
	}
	listed, err := connections.Operations(spec)
	if err != nil {
		return nil, err
	}
	actions := presets[conn.Preset].Catalog
	ops := map[string][][]string{}
	for _, o := range listed {
		ops[o.Operation.Action] = append(ops[o.Operation.Action], actions.Resolve("", o.Operation.Action, o.Operation.Effects).Effects)
	}
	if listed == nil {
		for action := range actions.Actions {
			ops[action] = append(ops[action], actions.Resolve("", action, nil).Effects)
		}
	}
	return ops, nil
}

// An action entry used to leave each effect's own setting in force, but now decides every effect beneath it.
// So each action whose operations an effect held back gets the mode it had, and no operation is decided more loosely than before.
func keepRestrictions(entries map[string]any, operations map[string][][]string, restrict func([]string, config.Mode) config.Mode) map[string]config.Mode {
	modes := map[string]config.Mode{}
	for action, mode := range entries {
		s, _ := mode.(string)
		modes[action] = config.Mode(s)
	}
	decider := func(action string) (string, bool) {
		lineage := catalog.Lineage(action)
		i := slices.IndexFunc(lineage, func(a string) bool { _, ok := modes[a]; return ok })
		if i < 0 {
			return "", false
		}
		return lineage[i], true
	}
	held := map[string]config.Mode{}
	for action, carried := range operations {
		if entry, ok := decider(action); ok {
			for _, effects := range carried {
				held[action] = max(held[action], restrict(effects, modes[entry]))
			}
		}
	}
	kept := map[string]config.Mode{}
	// Shallower actions go first, so a deeper one compares with whichever entry decides it after they are written.
	for _, action := range slices.SortedFunc(maps.Keys(held), func(a, b string) int {
		return cmp.Or(cmp.Compare(len(catalog.Lineage(a)), len(catalog.Lineage(b))), strings.Compare(a, b))
	}) {
		if entry, _ := decider(action); modes[entry] != held[action] {
			modes[action], kept[action] = held[action], held[action]
		}
	}
	return kept
}
