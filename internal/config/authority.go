package config

import (
	"bytes"
	"encoding/json"
	"maps"
	"reflect"
	"slices"

	"github.com/tinfoilsh/monitor/facts"
	"github.com/tinfoilsh/monitor/presets"
)

func (p Principal) Reaches(account string) bool {
	level := p.Accounts[account].Level
	return level != "" && level != "off"
}

// More specific effect settings override broader ones. Access levels and action
// permissions remain independent restrictions on the request.
func (c *Config) EffectModes(agent, acct string, effects ...string) map[string]string {
	modes := make(map[string]string, len(facts.Effects))
	for effect, obligations := range facts.Effects {
		modes[effect] = "allow"
		if obligations.Ask {
			modes[effect] = "ask"
		}
	}
	// Paid model operations already carry both generate and pay. Change only the
	// default; explicit payment restrictions at any scope still take precedence.
	if c.AllowPaidInference && slices.Contains(effects, "generate") && slices.Contains(effects, "pay") {
		modes["pay"] = "allow"
	}
	id := c.Identities[agent]
	for _, overrides := range []map[string]string{c.Effects, c.Accounts[acct].Effects, id.Effects, id.Accounts[acct].Effects} {
		maps.Copy(modes, overrides)
	}
	return modes
}

// SameAuthority reports whether key, a principal of s, has the authority over account in s that it had in old.
func (s *Snapshot) SameAuthority(old *Snapshot, key, account string) bool {
	p, previous := s.Principals[key], old.Principals[key]
	if previous.Name != p.Name ||
		s.Config.Lattices != old.Config.Lattices || s.Engine.Program != old.Engine.Program ||
		s.Config.AllowPaidInference != old.Config.AllowPaidInference {
		return false
	}
	a, b := previous.Accounts[account], p.Accounts[account]
	if a.Level != b.Level || !maps.Equal(a.Actions, b.Actions) ||
		!maps.Equal(old.Config.EffectModes(previous.Name, account), s.Config.EffectModes(p.Name, account)) {
		return false
	}
	for _, pair := range [][2]map[string]Rule{{previous.Rules, p.Rules}, {p.Rules, previous.Rules}} {
		for name, rule := range pair[0] {
			if rule.Account == account && !reflect.DeepEqual(rule, pair[1][name]) {
				return false
			}
		}
	}
	before, after := old.Config.Accounts[account], s.Config.Accounts[account]
	if before.Preset != after.Preset || before.Contents != after.Contents || before.Sends != after.Sends || before.Strangers != after.Strangers {
		return false
	}
	ap, bp := old.Config.Resolved[before.Preset], s.Config.Resolved[after.Preset]
	// Compare protocol definitions without their compiled caches or setup/display metadata.
	left, _ := json.Marshal([]any{before.PolicyOptions, ap.PublicScope, ap.HTTP, ap.MCP})
	right, _ := json.Marshal([]any{after.PolicyOptions, bp.PublicScope, bp.HTTP, bp.MCP})
	return bytes.Equal(left, right) && maps.EqualFunc(ap.Catalog.Actions, bp.Catalog.Actions, func(a, b presets.Action) bool {
		return slices.Equal(a.Effects, b.Effects)
	})
}
