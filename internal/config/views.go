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

// agentFields defines the restricted configuration view returned to an agent.
// Proposals may request broader changes, but never reveal owner-only state.
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

// ProposalTarget names the connection whose setup or access path changes.
func ProposalTarget(path []string) (string, bool) {
	switch {
	case len(path) >= 2 && (path[0] == "accounts" || path[0] == "default_access") && path[1] != "":
		return path[1], true
	case len(path) >= 4 && path[0] == "identities" && path[1] != "" && path[2] == "accounts" && path[3] != "":
		return path[3], true
	}
	return "", false
}

// ProposalChanges groups p's edits by connection. Credentials are refused because
// approval stores them as secrets, unlike the source edit the owner previews.
func (c *Config) ProposalChanges(p Principal, changes []Change) (map[string][]Change, error) {
	groups := map[string][]Change{}
	var leaves []Change
	for _, change := range changes {
		target, ok := ProposalTarget(change.Path)
		if !ok {
			return nil, errors.New("proposals may change only connection setup and access")
		}
		if !c.Identities[p.Name].Routes && (change.Path[0] == "default_access" || change.Path[0] == "identities" && change.Path[1] != p.Name) {
			return nil, errors.New("a sandbox may propose only connection setup and its own access")
		}
		groups[target] = append(groups[target], change)
		if table, ok := change.Value.(map[string]any); ok && len(table) > 0 && table["$json"] == nil {
			leaves = append(leaves, fragmentChanges(table, change.Path)...)
		} else {
			leaves = append(leaves, change)
		}
	}
	for _, leaf := range leaves {
		if _, credential := presets.ParseCredentialPath(leaf.Path[2:]); credential && leaf.Path[0] == "accounts" {
			return nil, fmt.Errorf("proposals cannot change %v; only the owner sets credentials", leaf.Path)
		}
	}
	return groups, nil
}

// ProposalScope digests the settings one connection's proposal was reviewed against.
// The proposer and edited identities also bind their keys and route access, so a
// pending proposal cannot outlive its authority or move to a replacement principal.
func (c *Config) ProposalScope(proposer string, changes []Change) string {
	connection, _ := ProposalTarget(changes[0].Path)
	targeted := map[string]bool{proposer: true}
	for _, change := range changes {
		if change.Path[0] == "identities" {
			targeted[change.Path[1]] = true
		}
	}
	identities := map[string]any{}
	for name, identity := range c.Identities {
		access := c.Access(name, connection)
		rules := map[string]Rule{}
		for id, rule := range identity.Rules {
			if rule.Account == connection {
				rules[id] = rule
			}
		}
		if access.Level != "" || len(rules) != 0 || targeted[name] {
			key := ""
			if targeted[name] {
				key = identity.Key
			}
			identities[name] = []any{key, identity.Routes, access, identity.Effects, rules}
		}
	}
	account, accountExists := c.Accounts[connection]
	fallback, fallbackExists := c.DefaultAccess[connection]
	// Global settings change this connection's effective behavior too.
	raw, _ := json.Marshal([]any{accountExists, account, fallbackExists, fallback, identities,
		c.Effects, c.AllowPaidInference, c.Lattices, c.AllowNetworks, c.Policies, c.Data})
	return fmt.Sprintf("%x", sha256.Sum256(raw))
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
