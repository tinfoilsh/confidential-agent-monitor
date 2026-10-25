package policy

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"maps"
	"reflect"
	"slices"

	"github.com/tinfoilsh/monitor/facts"
	"github.com/tinfoilsh/monitor/presets"
)

// Effective renders an already compiled configuration; reading it cannot compile
// or change policy. Configuration contains no credential values.
func (c *Config) Effective() (string, error) {
	v, err := facts.JSON[map[string]any](c)
	if err != nil {
		return "", err
	}
	ps := map[string]any{}
	for _, acc := range c.Accounts {
		if ps[acc.Preset], err = facts.JSON[map[string]any](c.Resolved[acc.Preset]); err != nil {
			return "", err
		}
	}
	v["presets"] = ps
	return RenderTOML(v)
}

// AgentView splits the configuration into the settings p may read and propose
// changing, and the rest, which a proposal must leave unchanged.
func (c *Config) AgentView(p Principal) (visible, rest map[string]any, err error) {
	if rest, err = facts.JSON[map[string]any](c); err != nil {
		return nil, nil, err
	}
	identities, _ := rest["identities"].(map[string]any)
	identity, _ := identities[p.Name].(map[string]any)
	accounts, _ := rest["accounts"].(map[string]any)
	reachable := map[string]any{}
	for name, a := range accounts {
		if p.Reaches(name) {
			reachable[name] = take(a.(map[string]any), "contents", "strangers", "sends", "policy_options")
		}
	}
	visible = map[string]any{"lattices": rest["lattices"], "identities": map[string]any{p.Name: take(identity, "accounts", "rules")}, "accounts": reachable}
	delete(rest, "lattices")
	return visible, rest, nil
}

// take moves the named fields out of m.
func take(m map[string]any, fields ...string) map[string]any {
	out := map[string]any{}
	for _, field := range fields {
		if value, ok := m[field]; ok {
			out[field] = value
			delete(m, field)
		}
	}
	return out
}

// A CatalogEntry exposes a preset's setup metadata and operations.
type CatalogEntry struct {
	*presets.Catalog
	Title      string                       `json:"title"`
	Operations *map[string]CatalogOperation `json:"operations,omitempty"`
}

type CatalogOperation struct {
	Action  string   `json:"action"`
	Effects []string `json:"effects,omitempty"`
}

// Catalog metadata belongs to the immutable policy snapshot. Only configured
// accounts need action metadata; operation definitions remain at /presets/{name}.
func catalog(cfg *Config) (map[string]CatalogEntry, string, error) {
	used := map[string]bool{}
	for _, a := range cfg.Accounts {
		used[a.Preset] = true
	}
	entries := map[string]CatalogEntry{}
	for name, p := range cfg.Resolved {
		metadata := *p.Catalog
		entry := CatalogEntry{Catalog: &metadata, Title: p.Title}
		if !used[name] {
			metadata.Actions = nil
		} else if p.HTTP != nil {
			operations := map[string]CatalogOperation{}
			for id, op := range p.HTTP.Operations {
				operations[id] = CatalogOperation{Action: op.Action, Effects: op.Effects}
			}
			entry.Operations = &operations
		}
		entries[name] = entry
	}
	raw, err := json.Marshal(entries)
	if err != nil {
		return nil, "", err
	}
	return entries, fmt.Sprintf("%x", sha256.Sum256(raw)), nil
}

func (p Principal) Reaches(account string) bool {
	level := p.Accounts[account].Level
	return level != "" && level != "off"
}

// More specific effect settings override broader ones. Access levels and action
// permissions remain independent restrictions on the request.
func (c *Config) EffectModes(agent, acct string, op *facts.Operation) map[string]string {
	modes := make(map[string]string, len(facts.Effects))
	for effect, obligations := range facts.Effects {
		modes[effect] = "allow"
		if obligations.Ask {
			modes[effect] = "ask"
		}
	}
	// Paid model operations already carry both generate and pay. Change only the
	// default; explicit payment restrictions at any scope still take precedence.
	if c.AllowPaidInference && op != nil && slices.Contains(op.Effects, "generate") && slices.Contains(op.Effects, "pay") {
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
		!maps.Equal(old.Config.EffectModes(previous.Name, account, nil), s.Config.EffectModes(p.Name, account, nil)) {
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
