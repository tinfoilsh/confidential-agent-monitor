package config

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"slices"

	"github.com/tinfoilsh/monitor/facts"
	"github.com/tinfoilsh/monitor/presets"
)

// View expands the existing owner wire representation only while rendering it.
// No caller uses this presentation as settings or connector authority.
func (c *Config) View() (map[string]any, error) {
	v := *c
	v.Identities, v.Accounts = maps.Clone(c.Identities), maps.Clone(c.Accounts)
	for name, id := range v.Identities {
		id.Accounts = c.Accesses(name)
		v.Identities[name] = id
	}
	for name, account := range v.Accounts {
		specs, err := c.Connections(name)
		if err != nil {
			return nil, err
		}
		account.Connections = map[string]map[string]json.RawMessage{}
		for _, spec := range specs {
			account.Connections[spec.Key] = map[string]json.RawMessage{spec.Protocol: spec.Config}
		}
		v.Accounts[name] = account
	}
	return facts.JSON[map[string]any](v)
}

// Effective preserves the expanded TOML control view, never compiling policy.
func (c *Config) Effective() (string, error) {
	v, err := c.View()
	if err != nil {
		return "", err
	}
	ps := map[string]any{}
	for _, acc := range c.Accounts {
		p, err := c.Preset(acc.Preset)
		if err != nil {
			return "", err
		}
		if ps[acc.Preset], err = facts.JSON[map[string]any](p); err != nil {
			return "", err
		}
	}
	v["presets"] = ps
	return RenderTOML(v)
}

// agentFields is the single definition of what an agent may read and propose.
// A nil value omits an absent field from the view without forbidding its creation.
func (c *Config) agentFields(p Principal) ([]Change, error) {
	if name, ok := c.Principals[p.Fingerprint]; !ok || name != p.Name {
		return nil, errors.New("agent identity changed")
	}
	var rules any
	if len(c.Identities[p.Name].Rules) != 0 {
		rules = c.Identities[p.Name].Rules
	}
	fields := []Change{{Path: []string{"lattices"}, Value: c.Lattices},
		{Path: []string{"identities", p.Name, "accounts"}, Value: c.Accesses(p.Name)},
		{Path: []string{"identities", p.Name, "rules"}, Value: rules}}
	for name, a := range c.Accounts {
		if c.Reaches(p.Name, name) {
			for field, value := range map[string]any{"contents": a.Contents, "strangers": a.Strangers, "sends": a.Sends, "policy_options": a.PolicyOptions} {
				fields = append(fields, Change{Path: []string{"accounts", name, field}, Value: value})
			}
		}
	}
	return fields, nil
}

func (c *Config) AgentView(p Principal) (map[string]any, error) {
	fields, err := c.agentFields(p)
	if err != nil {
		return nil, err
	}
	view := map[string]any{"accounts": map[string]any{}}
	for _, field := range fields {
		if field.Value == nil {
			continue
		}
		at := view
		for _, key := range field.Path[:len(field.Path)-1] {
			if at[key] == nil {
				at[key] = map[string]any{}
			}
			at = at[key].(map[string]any)
		}
		at[field.Path[len(field.Path)-1]] = field.Value
	}
	return facts.JSON[map[string]any](view)
}

// AgentChanges checks original edit roots before the source editor normalizes
// table replacement. Permission for a descendant never permits deleting its parent.
func (c *Config) AgentChanges(p Principal, changes []Change) error {
	fields, err := c.agentFields(p)
	if err != nil {
		return err
	}
	for _, change := range changes {
		if !slices.ContainsFunc(fields, func(field Change) bool {
			return len(change.Path) >= len(field.Path) && slices.Equal(change.Path[:len(field.Path)], field.Path)
		}) {
			return errors.New("proposal may edit only your permissions, reachable accounts' policy settings, or lattice switches")
		}
	}
	return nil
}

// Catalog is a control presentation, never an authorization or runtime registry.
func (c *Config) Catalog() (map[string]presets.Entry, string, error) {
	shipped, err := presets.Shipped()
	if err != nil {
		return nil, "", err
	}
	used, names := map[string]bool{}, map[string]bool{}
	for name := range shipped {
		names[name] = true
	}
	for name := range c.Presets {
		names[name] = true
	}
	for _, a := range c.Accounts {
		used[a.Preset] = true
	}
	entries := map[string]presets.Entry{}
	for name := range names {
		p, err := c.Preset(name)
		if err != nil {
			return nil, "", err
		}
		if entries[name], err = p.Entry(used[name]); err != nil {
			return nil, "", err
		}
	}
	raw, err := json.Marshal(entries)
	return entries, fmt.Sprintf("%x", sha256.Sum256(raw)), err
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
	for _, overrides := range []map[string]string{c.Effects, c.Accounts[acct].Effects, id.Effects, c.Access(agent, acct).Effects} {
		maps.Copy(modes, overrides)
	}
	return modes
}

// SameAuthority compares the settings relevant to one admitted account stream.
// The caller must first compare prepared policy programs and connector setup;
// setup equality already covers preset protocol data, action effects and public scope.
func (c *Config) SameAuthority(old *Config, key, account string) bool {
	var authority [2][]byte
	for i, cfg := range []*Config{old, c} {
		name, a := cfg.Principals[key], cfg.Accounts[account]
		rules := map[string]Rule{}
		for ruleName, rule := range cfg.Identities[name].Rules {
			if rule.Account == account {
				rules[ruleName] = rule
			}
		}
		access := cfg.Access(name, account)
		// Compare current policy input; connector setup is checked by the caller.
		a.Effects, a.Connections, access.Effects = nil, nil, nil
		authority[i], _ = json.Marshal([]any{name, cfg.Lattices, cfg.AllowPaidInference, access,
			cfg.EffectModes(name, account, nil), rules, a})
	}
	return bytes.Equal(authority[0], authority[1])
}
