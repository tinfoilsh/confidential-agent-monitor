package config

import (
	"fmt"
	"maps"
	"slices"
	"time"

	"github.com/tinfoilsh/confidential-agent-monitor/connector/catalog"
	"github.com/tinfoilsh/confidential-agent-monitor/core/tomledit"
)

type Mode string

const (
	ModeOff   Mode = "off"
	ModeAsk   Mode = "ask"
	ModeAllow Mode = "allow"
)

var modeRank = map[Mode]int{ModeOff: 0, ModeAsk: 1, ModeAllow: 2}

func (m Mode) valid() bool { _, ok := modeRank[m]; return ok }

func stricter(a, b Mode) bool { return modeRank[a] < modeRank[b] }

type Setting struct {
	Mode Mode   `json:"mode"`
	From string `json:"from"`
}

type Resolved struct {
	Reaches bool               `json:"reaches"`
	Level   string             `json:"level"`
	Effects map[string]Setting `json:"effects"`
	Actions map[string]Setting `json:"actions,omitempty"`
	Tree    []ResolvedNode     `json:"tree,omitempty"`
}

const accountAccess = "access"

// The first part may already be a path, so it is not quoted.
func tomlPath(path string, keys ...string) string { return path + "." + tomledit.Path(keys...) }

// Every effect, so a more specific level replaces a less specific one entirely.
// Read and up allow what needs no trust; read refuses the rest.
func levelMode(level, effect string) (Mode, bool) {
	t, known := Vocabulary[effect]
	switch {
	case !known || level == "":
		return "", false
	case level == "off":
		return ModeOff, true
	case !t.Integrity:
		return ModeAllow, true
	case level == "read":
		return ModeOff, true
	case level == "ask":
		return ModeAsk, true
	}
	return ModeAllow, true
}

func (c *Config) accessPath(identity, connection string) string {
	if _, declared := c.Identities[identity]; declared {
		return tomlPath("identities", identity, "connections", connection)
	}
	return tomlPath("default_access", connection)
}

type block struct {
	path   string
	access Access
}

func (b block) cover(lineage []string, effect string) (Setting, bool) {
	for _, a := range lineage {
		if m, ok := b.access.Actions[a]; ok {
			return Setting{Mode(m), tomlPath(b.path, "actions", a)}, true
		}
	}
	if m, ok := b.access.Effects[effect]; ok {
		return Setting{Mode(m), tomlPath(b.path, "effects", effect)}, true
	}
	m, ok := levelMode(b.access.Level, effect)
	// Only an operation has a lineage; a level never opens a session, which follows reach.
	return Setting{m, tomlPath(b.path, "level")}, ok && (len(lineage) != 0 || effect != "session")
}

type tiers struct {
	blocks  [][]block
	actions map[string]Setting
	unset   string
	reaches bool
}

func (t tiers) modes(lineage, effects []string) map[string]Setting {
	// An action with no known effects is decided as an unrecognized request is.
	if len(effects) == 0 {
		effects = []string{EffectUnknown}
	}
	modes := map[string]Setting{}
	for _, e := range effects {
		s, covered := Setting{ModeOff, t.unset}, false
		// Only the bare session effect follows reach; an operation no tier covers is off.
		if e == "session" && len(lineage) == 0 && t.reaches {
			s.Mode = ModeAllow
		}
		for _, tier := range t.blocks {
			// Within a tier the most permissive block decides; ties go to the first group by name.
			for _, b := range tier {
				if m, ok := b.cover(lineage, e); ok && (!covered || stricter(s.Mode, m.Mode)) {
					s, covered = m, true
				}
			}
			if covered {
				break
			}
		}
		modes[e] = s
	}
	return modes
}

// Ties go to the first effect in name order, so a report names the same cause every time.
func strictest(settings map[string]Setting) Setting {
	var lowest Setting
	for i, effect := range slices.Sorted(maps.Keys(settings)) {
		if s := settings[effect]; i == 0 || stricter(s.Mode, lowest.Mode) {
			lowest = s
		}
	}
	return lowest
}

// The effect only lets the catalog resolve the action, so every lineage is the catalog's own.
// A request for an action carries its compiled operations' effects where it has any, else the catalog's.
func (c *Config) ResolveAction(connection, action string) *catalog.Operation {
	presetName := c.Connections[connection].Preset
	preset := c.Presets[presetName]
	if preset == nil {
		return nil
	}
	var effects []string
	for _, op := range c.Operations[presetName] {
		if op.Action == action {
			effects = append(effects, op.Effects...)
		}
	}
	return preset.Catalog.Resolve("", action, effects)
}

// Reachability looks at every effect but session, so session can follow it.
func (c *Config) tiersFor(identity string, groups []string, connection string) tiers {
	t := tiers{unset: c.accessPath(identity, connection)}
	if a, ok := c.Identities[identity].Connections[connection]; ok {
		t.blocks = append(t.blocks, []block{{tomlPath("identities", identity, "connections", connection), a}})
	}
	var bundles []block
	for _, g := range slices.Sorted(slices.Values(groups)) {
		// A device is one by its declared groups, never by a certificate principal.
		if a, ok := c.Groups[g].Connections[connection]; ok && (g != DeviceGroup || slices.Contains(c.Identities[identity].Groups, g)) {
			bundles = append(bundles, block{tomlPath("groups", g, "connections", connection), a})
		}
	}
	t.blocks = append(t.blocks, bundles)
	if a, ok := c.DefaultAccess[connection]; ok {
		t.blocks = append(t.blocks, []block{{tomlPath("default_access", connection), a}})
	}
	if connection != PerimeterConnection {
		t.blocks = append(t.blocks, []block{{accountAccess, c.Access}})
	}
	for e := range Vocabulary {
		t.reaches = t.reaches || e != "session" && t.modes(nil, []string{e})[e].Mode != ModeOff
	}
	t.actions = c.actionSettings(t, connection)
	for _, s := range t.actions {
		t.reaches = t.reaches || s.Mode != ModeOff
	}
	return t
}

func (c *Config) actionSettings(t tiers, connection string) map[string]Setting {
	actions := map[string]Setting{}
	for _, tier := range t.blocks {
		for _, b := range tier {
			for a := range b.access.Actions {
				switch op := c.ResolveAction(connection, a); {
				case op != nil:
					actions[a] = strictest(t.modes(op.Lineage, op.Effects))
				// The account block names actions of every connection, so only those that resolve here are this one's.
				case b.path != accountAccess:
					actions[a] = strictest(t.modes(catalog.Lineage(a), nil))
				}
			}
		}
	}
	return actions
}

func (c *Config) Resolve(identity string, groups []string, connection string) Resolved {
	t := c.tiersFor(identity, groups, connection)
	r := Resolved{Reaches: t.reaches, Effects: map[string]Setting{}, Actions: t.actions, Tree: c.tree(connection, t)}
	for e := range Vocabulary {
		maps.Copy(r.Effects, t.modes(nil, []string{e}))
	}
	r.Level = r.level()
	return r
}

func (r Resolved) level() string {
	if !r.Reaches {
		return "off"
	}
	for _, level := range accessLevels[1:] {
		matches := true
		for e := range Vocabulary {
			m, _ := levelMode(level, e)
			matches = matches && (e == "session" || r.Effects[e].Mode == m)
		}
		if matches {
			return level
		}
	}
	return "custom"
}

func (c *Config) Reaches(identity string, groups []string, connection string) bool {
	return c.tiersFor(identity, groups, connection).reaches
}

func (c *Config) EffectModes(identity string, groups []string, connection string, op *catalog.Operation, kind string) map[string]Setting {
	t := c.tiersFor(identity, groups, connection)
	if kind == KindAdmission {
		// Only an explicit session entry or reach decides an admission, which never opens a connection the identity does not reach.
		if !t.reaches {
			return map[string]Setting{"session": {ModeOff, t.unset}}
		}
		return t.modes(nil, []string{"session"})
	}
	effects, lineage := []string{EffectUnknown}, []string(nil)
	if op != nil && len(op.Effects) != 0 {
		effects, lineage = op.Effects, op.Lineage
	}
	return t.modes(lineage, effects)
}

func (c *Config) ruleOperation(r Rule) *catalog.Operation {
	conn, ok := c.Connections[r.Connection]
	preset := c.Presets[conn.Preset]
	if !ok || preset == nil {
		return nil
	}
	if summary, compiled := c.Operations[conn.Preset][r.Operation]; compiled && summary.Action == r.Action {
		return preset.Catalog.Resolve(r.Operation, r.Action, summary.Effects)
	}
	if conn.MatchOnly && r.Action == CustomAction && r.Operation == CustomAction {
		return preset.Catalog.Resolve("", CustomAction, CustomEffects)
	}
	return preset.Catalog.Resolve(r.Operation, r.Action, nil)
}

func (c *Config) staleness(r Rule, now time.Time) string {
	conn, exists := c.Connections[r.Connection]
	expires, err := time.Parse(time.RFC3339, r.Expires)
	switch {
	case r.Version != FactsVersion:
		return fmt.Sprintf("saved at facts version %d; this Perimeter is at %d", r.Version, FactsVersion)
	case !exists:
		return fmt.Sprintf("connection %s no longer exists", r.Connection)
	case c.ruleOperation(r) == nil:
		return fmt.Sprintf("operation %s no longer resolves in preset %s", r.Operation, conn.Preset)
	case r.Expires != "" && err == nil && !now.Before(expires):
		return "expired at " + r.Expires
	}
	return ""
}

// Judged as staleRules judges them, so a rule the views report as stale never waives.
func (c *Config) LiveRules(identity string, now time.Time) []Rule {
	var live []Rule
	for _, r := range c.Identities[identity].Rules {
		if c.staleness(r, now) == "" {
			live = append(live, r)
		}
	}
	return live
}

func (c *Config) staleRules() map[string]map[string]string {
	now := time.Now()
	stale := map[string]map[string]string{}
	for name, id := range c.Identities {
		for rule, r := range id.Rules {
			if reason := c.staleness(r, now); reason != "" {
				if stale[name] == nil {
					stale[name] = map[string]string{}
				}
				stale[name][rule] = reason
			}
		}
	}
	return stale
}
