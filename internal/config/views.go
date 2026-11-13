package config

import (
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
	v.Identities, v.Connections = maps.Clone(c.Identities), maps.Clone(c.Connections)
	for name, id := range v.Identities {
		id.Connections = c.Accesses(name)
		v.Identities[name] = id
	}
	for name, connection := range v.Connections {
		spec, err := c.Spec(name)
		if err != nil {
			return nil, err
		}
		connection.Setup = map[string]json.RawMessage{spec.Protocol: spec.Config}
		v.Connections[name] = connection
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
	for _, connection := range c.Connections {
		p, err := presets.Lookup(connection.Preset)
		if err != nil {
			return "", err
		}
		if ps[connection.Preset], err = facts.JSON[map[string]any](p); err != nil {
			return "", err
		}
	}
	v["presets"] = ps
	return RenderTOML(v)
}

// AgentView is the restricted configuration returned to an agent. Proposals may
// request broader changes, but never reveal owner-only state.
func (c *Config) AgentView(p Principal) (map[string]any, error) {
	if name, ok := c.Principals[p.Key]; !ok || name != p.Name {
		return nil, errors.New("agent identity changed")
	}
	identity := map[string]any{"connections": c.Accesses(p.Name)}
	if rules := c.Identities[p.Name].Rules; len(rules) != 0 {
		identity["rules"] = rules
	}
	connections := map[string]any{}
	for name, connection := range c.Connections {
		if c.Reaches(p.Name, name) {
			connections[name] = map[string]any{"contents": connection.Contents, "strangers": connection.Strangers, "sends": connection.Sends, "policy_options": connection.PolicyOptions}
		}
	}
	return facts.JSON[map[string]any](map[string]any{"lattices": c.Lattices, "identities": map[string]any{p.Name: identity}, "connections": connections})
}

// ProposalTarget names the connection whose setup or access path changes.
func ProposalTarget(path []string) (string, bool) {
	switch {
	case len(path) >= 2 && (path[0] == "connections" || path[0] == "default_access") && path[1] != "":
		return path[1], true
	case len(path) >= 4 && path[0] == "identities" && path[1] != "" && path[2] == "connections" && path[3] != "":
		return path[3], true
	}
	return "", false
}

func (c *Config) ProposalChanges(p Principal, changes []Change) (map[string][]Change, error) {
	groups := map[string][]Change{}
	for _, change := range changes {
		target, ok := ProposalTarget(change.Path)
		if !ok {
			return nil, errors.New("proposals may change only service setup and access")
		}
		if !c.Identities[p.Name].Operator && (change.Path[0] == "default_access" || change.Path[0] == "identities" && change.Path[1] != p.Name) {
			return nil, errors.New("a bunker may propose only service setup and its own access")
		}
		groups[target] = append(groups[target], change)
	}
	return groups, nil
}

// Catalog is a control presentation, never an authorization or runtime registry.
func (c *Config) Catalog() (map[string]presets.Entry, string, error) {
	shipped, err := presets.Shipped()
	if err != nil {
		return nil, "", err
	}
	used := map[string]bool{}
	for _, connection := range c.Connections {
		used[connection.Preset] = true
	}
	entries := map[string]presets.Entry{}
	for name, p := range shipped {
		if entries[name], err = p.Entry(used[name]); err != nil {
			return nil, "", err
		}
	}
	raw, err := json.Marshal(entries)
	return entries, fmt.Sprintf("%x", sha256.Sum256(raw)), err
}

// More specific effect settings override broader ones. Access levels and action
// permissions remain independent restrictions on the request.
func (c *Config) EffectModes(agent, connection string, op *facts.Operation) map[string]string {
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
	for _, overrides := range []map[string]string{c.Effects, c.Connections[connection].Effects, id.Effects, c.Access(agent, connection).Effects} {
		maps.Copy(modes, overrides)
	}
	return modes
}
