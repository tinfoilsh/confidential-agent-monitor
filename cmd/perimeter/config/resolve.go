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

func below(a, b Mode) bool { return modeRank[a] < modeRank[b] }

type Setting struct {
	Mode     Mode   `json:"mode"`
	From     string `json:"from"`
	Grant    Mode   `json:"grant"`
	Limit    Mode   `json:"limit"`
	CappedBy string `json:"capped_by,omitempty"`
}

type Resolved struct {
	Reaches bool               `json:"reaches"`
	Level   string             `json:"level"`
	Effects map[string]Setting `json:"effects"`
	Actions map[string]Setting `json:"actions,omitempty"`
	Tree    []ResolvedNode     `json:"tree,omitempty"`
}

const pathPaid = "allow_paid_inference"

// The first part may already be a path, so it is not quoted.
func tomlPath(path string, keys ...string) string { return path + "." + tomledit.Path(keys...) }

func changing(o Obligations) bool { return o.Change || o.Trust }

// Every effect but session, so a more specific level replaces a less specific one entirely.
func expand(level string) map[string]Mode {
	if level == "" {
		return nil
	}
	modes := map[string]Mode{}
	for e, o := range Vocabulary {
		switch {
		case e == "session":
		case level == "off":
			modes[e] = ModeOff
		case !changing(o):
			modes[e] = ModeAllow
		case level == "read":
			modes[e] = ModeOff
		case level == "ask" || o.Ask:
			modes[e] = ModeAsk
		default:
			modes[e] = ModeAllow
		}
	}
	return modes
}

func (c *Config) rolesOf(identity string, groups []string) []string {
	var roles []string
	add := func(role string) {
		if !slices.Contains(roles, role) {
			roles = append(roles, role)
		}
	}
	for _, role := range c.Identities[identity].Roles {
		add(role)
	}
	for _, role := range slices.Sorted(maps.Keys(c.Roles)) {
		if slices.ContainsFunc(c.Roles[role].Groups, func(g string) bool { return slices.Contains(groups, g) }) {
			add(role)
		}
	}
	return roles
}

func (c *Config) accessPath(identity, connection string) string {
	if _, declared := c.Identities[identity]; declared {
		return tomlPath("identities", identity, "connections", connection)
	}
	return tomlPath("default_access", connection)
}

type layer struct {
	path   string
	access Access
}

func (c *Config) layers(identity string, roles []string, connection string) []layer {
	var layers []layer
	add := func(path string, blocks map[string]Access) {
		if a, ok := blocks[connection]; ok {
			layers = append(layers, layer{tomlPath(path, connection), a})
		}
	}
	add("default_access", c.DefaultAccess)
	for _, role := range roles {
		add(tomlPath("roles", role, "connections"), c.Roles[role].Connections)
	}
	if id, declared := c.Identities[identity]; declared {
		add(tomlPath("identities", identity, "connections"), id.Connections)
	}
	return layers
}

type source struct {
	mode Mode
	from string
	// expanded marks a mode a level set, which paid inference may raise; base marks the base layer's.
	expanded, base bool
}

type grants struct{ effects, actions map[string]source }

func (c *Config) grants(identity string, roles []string, connection string, paid bool) grants {
	g := grants{effects: map[string]source{}, actions: map[string]source{}}
	for e := range Vocabulary {
		g.effects[e] = source{mode: ModeOff, from: c.accessPath(identity, connection), base: true}
	}
	for _, l := range c.layers(identity, roles, connection) {
		for e, m := range expand(l.access.Level) {
			g.effects[e] = source{mode: m, from: tomlPath(l.path, "level"), expanded: true}
		}
		for e, m := range l.access.Effects {
			g.effects[e] = source{mode: Mode(m), from: tomlPath(l.path, "effects", e)}
		}
		for a, m := range l.access.Actions {
			g.actions[a] = source{mode: Mode(m), from: tomlPath(l.path, "actions", a)}
		}
	}
	// Paid inference raises only what a level set; an explicit pay setting, or an action entry, wins.
	if paid && c.AllowPaidInference && g.effects["pay"].expanded {
		g.effects["pay"] = source{mode: ModeAllow, from: pathPaid}
	}
	return g
}

func first(entries map[string]source, lineage []string) (source, bool) {
	for _, a := range lineage {
		if s, ok := entries[a]; ok {
			return s, true
		}
	}
	return source{}, false
}

type scope struct {
	path   string
	limits Limits
}

func (c *Config) scopes(identity string, roles []string, connection string) []scope {
	scopes := []scope{{"limits", c.Limits}}
	if conn, ok := c.Connections[connection]; ok {
		scopes = append(scopes, scope{tomlPath("connections", connection, "limits"), conn.Limits})
	}
	for _, role := range roles {
		scopes = append(scopes, scope{tomlPath("roles", role, "limits"), c.Roles[role].Limits})
	}
	if id, declared := c.Identities[identity]; declared {
		scopes = append(scopes, scope{tomlPath("identities", identity, "limits"), id.Limits})
	}
	return scopes
}

func (s scope) limit(lineage []string, effect string) (source, bool) {
	for _, a := range lineage {
		if m, ok := s.limits.Actions[a]; ok {
			return source{mode: Mode(m), from: tomlPath(s.path, "actions", a)}, true
		}
	}
	m, ok := s.limits.Effects[effect]
	return source{mode: Mode(m), from: tomlPath(s.path, "effects", effect)}, ok
}

func (g grants) setting(scopes []scope, lineage []string, effect string) Setting {
	grant, ok := first(g.actions, lineage)
	if !ok {
		grant = g.effects[effect]
	}
	s := Setting{Mode: grant.mode, From: grant.from, Grant: grant.mode, Limit: ModeAllow}
	var capped string
	for _, sc := range scopes {
		if limit, ok := sc.limit(lineage, effect); ok && below(limit.mode, s.Limit) {
			s.Limit, capped = limit.mode, limit.from
		}
	}
	if below(s.Limit, s.Grant) {
		s.Mode, s.CappedBy = s.Limit, capped
	}
	return s
}

// Ties go to the first effect in name order, so a report names the same cause every time.
func strictest(settings map[string]Setting) Setting {
	var lowest Setting
	for i, effect := range slices.Sorted(maps.Keys(settings)) {
		if s := settings[effect]; i == 0 || below(s.Mode, lowest.Mode) {
			lowest = s
		}
	}
	return lowest
}

// The effect only lets the catalog resolve the action, so every lineage is the catalog's own.
// A request for an action carries its compiled operations' effects where it has any, else the catalog's.
func (c *Config) Operation(connection, action string) *catalog.Operation {
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
func (c *Config) access(identity string, groups []string, connection string, paid bool) (g grants, scopes []scope, reaches bool) {
	roles := c.rolesOf(identity, groups)
	g, scopes = c.grants(identity, roles, connection, paid), c.scopes(identity, roles, connection)
	for e := range Vocabulary {
		reaches = reaches || e != "session" && g.setting(scopes, nil, e).Mode != ModeOff
	}
	for _, s := range c.actionSettings(g, scopes, connection) {
		reaches = reaches || s.Mode != ModeOff
	}
	if g.effects["session"].base && reaches {
		g.effects["session"] = source{mode: ModeAllow, from: c.accessPath(identity, connection)}
	}
	return g, scopes, reaches
}

func (c *Config) actionSettings(g grants, scopes []scope, connection string) map[string]Setting {
	actions := map[string]Setting{}
	named := slices.Collect(maps.Keys(g.actions))
	for _, sc := range scopes {
		named = slices.AppendSeq(named, maps.Keys(sc.limits.Actions))
	}
	for _, a := range named {
		if op := c.Operation(connection, a); op != nil {
			settings := map[string]Setting{}
			for _, e := range op.Effects {
				settings[e] = g.setting(scopes, op.Lineage, e)
			}
			actions[a] = strictest(settings)
		} else if _, granted := g.actions[a]; granted {
			actions[a] = g.setting(scopes, catalog.Lineage(a), "")
		}
	}
	return actions
}

func (c *Config) Resolve(identity string, groups []string, connection string) Resolved {
	g, scopes, reaches := c.access(identity, groups, connection, false)
	r := Resolved{Reaches: reaches, Effects: map[string]Setting{}, Actions: c.actionSettings(g, scopes, connection)}
	for e := range Vocabulary {
		r.Effects[e] = g.setting(scopes, nil, e)
	}
	r.Level = r.level()
	unset := Setting{Mode: ModeOff, From: c.accessPath(identity, connection), Grant: ModeOff, Limit: ModeAllow}
	r.Tree = c.tree(connection, g, scopes, unset)
	return r
}

func (r Resolved) level() string {
	if !r.Reaches {
		return "off"
	}
	for _, level := range accessLevels[1:] {
		matches := true
		for e, m := range expand(level) {
			matches = matches && r.Effects[e].Mode == m
		}
		if matches {
			return level
		}
	}
	return "custom"
}

func (c *Config) Reaches(identity string, groups []string, connection string) bool {
	_, _, reaches := c.access(identity, groups, connection, false)
	return reaches
}

func (c *Config) Modes(identity string, groups []string, connection string, op *catalog.Operation, kind string) map[string]Setting {
	if kind == KindAdmission {
		// An admission resolves session like any effect, but never opens a connection the identity does not reach.
		g, scopes, reaches := c.access(identity, groups, connection, false)
		s := g.setting(scopes, nil, "session")
		if !reaches {
			s.Mode, s.Grant, s.From, s.CappedBy = ModeOff, ModeOff, c.accessPath(identity, connection), ""
		}
		return map[string]Setting{"session": s}
	}
	effects, lineage := []string{EffectUnknown}, []string(nil)
	if op != nil && len(op.Effects) != 0 {
		effects, lineage = op.Effects, op.Lineage
	}
	paid := slices.Contains(effects, "generate") && slices.Contains(effects, "pay")
	g, scopes, _ := c.access(identity, groups, connection, paid)
	modes := map[string]Setting{}
	for _, e := range effects {
		modes[e] = g.setting(scopes, lineage, e)
	}
	return modes
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
