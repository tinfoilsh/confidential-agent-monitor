package config

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"

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
