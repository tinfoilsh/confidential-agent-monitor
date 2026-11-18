package config

import (
	"cmp"
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"net/netip"
	"reflect"
	"slices"

	jsonpatch "github.com/evanphx/json-patch/v5"
	"github.com/tinfoilsh/confidential-agent-monitor/connector/catalog"
	"github.com/tinfoilsh/confidential-agent-monitor/core/facts"
	"github.com/tinfoilsh/confidential-agent-monitor/core/tomledit"
	"golang.org/x/crypto/ssh"
)

const (
	AgentConnection    = "agent"
	maxPolicyBytes     = 2 << 20
	maxProposalChanges = 256
)

var (
	accessLevels = []string{"off", "read", "ask", "allow"}
	effectModes  = []string{"off", "ask", "allow"}
)

type ConnectionSpec struct {
	Name, Protocol              string
	Config, Definition, Options json.RawMessage
	PublicScope                 []string
}

type Access struct {
	Level   string            `json:"level"`
	Actions map[string]string `json:"actions,omitempty"`
	Effects map[string]string `json:"effects,omitempty"`
}

type Requirement struct {
	ID      string `json:"id"`
	Message string `json:"message"`
}

type Rule struct {
	Enabled      *bool          `json:"enabled,omitempty"`
	Version      int            `json:"version"`
	Connection   string         `json:"connection"`
	Action       string         `json:"action"`
	Operation    string         `json:"operation,omitempty"`
	Definition   string         `json:"definition,omitempty"`
	Scope        map[string]any `json:"scope"`
	Requirements []Requirement  `json:"requirements"`
}

type Identity struct {
	Routes      bool                       `json:"routes,omitempty"`
	Key         string                     `json:"key"`
	Groups      []string                   `json:"groups,omitempty"`
	Effects     map[string]string          `json:"effects,omitempty"`
	Connections map[string]Access          `json:"connections"`
	Rules       map[string]Rule            `json:"rules,omitempty"`
	Attributes  map[string]json.RawMessage `json:",embed"`
}

type PolicyOptions struct {
	Private []string `json:"private,omitempty"`
	Address string   `json:"address,omitempty"`
	Origin  string   `json:"origin,omitempty"`
}

type Connection struct {
	Preset        string                     `json:"preset"`
	Effects       map[string]string          `json:"effects,omitempty"`
	PolicyOptions PolicyOptions              `json:"policy_options"`
	Contents      string                     `json:"contents"`
	Strangers     bool                       `json:"strangers"`
	Sends         string                     `json:"sends"`
	Setup         map[string]json.RawMessage `json:",embed"`
}

type Lattices struct {
	Confidentiality bool `json:"confidentiality"`
	Integrity       bool `json:"integrity"`
}

type Config struct {
	AllowPaidInference bool                  `json:"allow_paid_inference,omitempty"`
	Effects            map[string]string     `json:"effects,omitempty"`
	DefaultAccess      map[string]Access     `json:"default_access,omitempty"`
	Lattices           Lattices              `json:"lattices"`
	AllowNetworks      []netip.Prefix        `json:"allow_networks"`
	Connections        map[string]Connection `json:"connections"`
	Identities         map[string]Identity   `json:"identities"`
	Policies           map[string]string     `json:"policies"`
	Data               map[string]any        `json:"data"`
	Principals         map[string]string     `json:"-"`
	presets            map[string]*catalog.Preset
}

func validateEffects(name string, effects map[string]string) error {
	for effect, mode := range effects {
		if _, ok := Vocabulary[effect]; !ok {
			return fmt.Errorf("%s: unknown effect %q", name, effect)
		}
		if !slices.Contains(effectModes, mode) {
			return fmt.Errorf("%s: effect %s must be off, ask or allow", name, effect)
		}
	}
	return nil
}

func inheritModes(defaults, overrides map[string]string) map[string]string {
	merged := make(map[string]string, len(defaults)+len(overrides))
	maps.Copy(merged, defaults)
	maps.Copy(merged, overrides)
	return merged
}

func Load(text string, presets map[string]*catalog.Preset) (*Config, error) {
	if len(text) > maxPolicyBytes {
		return nil, errors.New("policy source is too large")
	}
	decoded, err := tomledit.Read(text)
	if err != nil {
		return nil, err
	}
	cfg := &Config{Lattices: Lattices{Confidentiality: true}, presets: presets}
	raw, err := json.Marshal(decoded)
	if err == nil {
		err = facts.DecodeNumbers(raw, cfg)
	}
	if err != nil {
		return nil, err
	}
	if err := validateEffects("global settings", cfg.Effects); err != nil {
		return nil, err
	}
	for name, c := range cfg.Connections {
		if err := validateEffects("service "+name, c.Effects); err != nil {
			return nil, err
		}
		if !slices.Contains(Audiences, c.Contents) || !slices.Contains(Audiences, c.Sends) {
			return nil, fmt.Errorf("service %s: contents and sends must be one of %v", name, Audiences)
		}
		if name == AgentConnection {
			return nil, fmt.Errorf("service name %s is reserved", name)
		}
		if _, err := cfg.Spec(name); err != nil {
			return nil, err
		}
	}
	validateAccess := func(name string, connections map[string]Access) error {
		for connection, a := range connections {
			if _, ok := cfg.Connections[connection]; !ok || !slices.Contains(accessLevels, a.Level) {
				return fmt.Errorf("%s: service %s must exist and have a level in %v", name, connection, accessLevels)
			}
			if err := validateEffects(name+" on "+connection, a.Effects); err != nil {
				return err
			}
			for action, level := range a.Actions {
				if !slices.Contains(effectModes, level) {
					return fmt.Errorf("%s: action %s must be off, ask or allow", name, action)
				}
			}
		}
		return nil
	}
	if err := validateAccess("default access", cfg.DefaultAccess); err != nil {
		return nil, err
	}
	cfg.Principals = map[string]string{}
	for name, id := range cfg.Identities {
		if err := validateEffects("agent "+name, id.Effects); err != nil {
			return nil, err
		}
		if err := validateAccess("identity "+name, cfg.Accesses(name)); err != nil {
			return nil, err
		}
		fingerprint, err := KeyFingerprint(id.Key)
		if err != nil {
			return nil, fmt.Errorf("identity %s: %w", name, err)
		}
		if _, exists := cfg.Principals[fingerprint]; exists {
			return nil, fmt.Errorf("identity %s shares another identity's public key", name)
		}
		cfg.Principals[fingerprint] = name
	}
	return cfg, nil
}

func KeyFingerprint(authorizedKey string) (string, error) {
	key, _, _, _, err := ssh.ParseAuthorizedKey([]byte(authorizedKey))
	if err != nil {
		return "", err
	}
	return ssh.FingerprintSHA256(key), nil
}

func (c *Config) Principal(fingerprint string) (facts.Principal, bool) {
	name, ok := c.Principals[fingerprint]
	return facts.Principal{Key: fingerprint, Name: name, Groups: c.Identities[name].Groups, Attributes: c.Identities[name].Attributes}, ok
}

func (c *Config) Access(identity, connection string) Access {
	a := c.Identities[identity].Connections[connection]
	if a.Level == "" {
		base := c.DefaultAccess[connection]
		a.Level = cmp.Or(base.Level, "off")
		a.Actions = inheritModes(base.Actions, a.Actions)
		a.Effects = inheritModes(base.Effects, a.Effects)
	}
	return a
}

func (c *Config) Accesses(identity string) map[string]Access {
	connections := map[string]Access{}
	maps.Copy(connections, c.DefaultAccess)
	maps.Copy(connections, c.Identities[identity].Connections)
	for connection := range connections {
		connections[connection] = c.Access(identity, connection)
	}
	return connections
}

func (c *Config) Reaches(identity, connection string) bool {
	a := c.Access(identity, connection)
	if a.Level != "" && a.Level != "off" {
		return true
	}
	for _, mode := range a.Actions {
		if mode != "off" {
			return true
		}
	}
	return false
}

func (c *Config) Spec(name string) (ConnectionSpec, error) {
	connection := c.Connections[name]
	preset := c.presets[connection.Preset]
	if preset == nil {
		return ConnectionSpec{}, fmt.Errorf("service %s: unknown preset %s", name, connection.Preset)
	}
	spec := ConnectionSpec{Name: name, PublicScope: preset.PublicScope}

	var definition map[string]json.RawMessage
	if err := json.Unmarshal(preset.Source, &definition); err != nil {
		return ConnectionSpec{}, err
	}
	actions := map[string]map[string][]string{}
	for id, action := range preset.Catalog.Actions {
		if action.Effects != nil {
			actions[id] = map[string][]string{"effects": action.Effects}
		}
	}
	definition["catalog"], _ = json.Marshal(map[string]any{"actions": actions, "fields": preset.Catalog.Fields})
	spec.Definition, _ = json.Marshal(definition)

	setup, _ := json.Marshal(preset.Catalog.Connection)
	if preset.Catalog.Connection == nil {
		setup = []byte(`{}`)
	}
	if connection.Setup != nil {
		patch, _ := json.Marshal(connection.Setup)
		var err error
		if setup, err = jsonpatch.MergePatch(setup, patch); err != nil {
			return ConnectionSpec{}, err
		}
	}
	var protocols map[string]any
	if err := facts.DecodeNumbers(setup, &protocols); err != nil {
		return ConnectionSpec{}, err
	}
	if len(protocols) != 1 {
		return ConnectionSpec{}, fmt.Errorf("service %s must have one kind", name)
	}
	for protocol, value := range protocols {
		spec.Protocol = protocol
		spec.Config, _ = json.Marshal(value)
	}

	options := connection.PolicyOptions
	options.Private = nil
	spec.Options, _ = json.Marshal(options)
	return spec, nil
}

func (c *Config) Edit(source string, changes []tomledit.Change) (edited string, rebuild func(connection string) bool, renamed map[string]string, err error) {
	edited, err = tomledit.Edit(source, changes)
	if err != nil {
		return "", nil, nil, err
	}
	next, err := Load(edited, c.presets)
	if err != nil {
		return "", nil, nil, err
	}
	if reflect.DeepEqual(next, c) {
		return source, func(string) bool { return false }, nil, nil
	}
	networks := !slices.Equal(c.AllowNetworks, next.AllowNetworks)
	renamed = map[string]string{}
	for _, change := range changes {
		if len(change.Path) != 2 || len(change.From) != 2 || change.Path[0] != "connections" || change.From[0] != "connections" {
			continue
		}
		_, was := c.Connections[change.From[1]]
		if _, still := next.Connections[change.From[1]]; was && !still {
			renamed[change.Path[1]] = change.From[1]
		}
	}
	setup := func(connection string) bool {
		before, _ := c.Spec(cmp.Or(renamed[connection], connection))
		after, _ := next.Spec(connection)
		before.Name = after.Name
		return !reflect.DeepEqual(before, after)
	}
	var stale []tomledit.Change
	for _, name := range slices.Sorted(maps.Keys(next.Identities)) {
		rules := next.Identities[name].Rules
		for _, id := range slices.Sorted(maps.Keys(rules)) {
			if setup(rules[id].Connection) {
				stale = append(stale, tomledit.Change{Path: []string{"identities", name, "rules", id}, Delete: true})
			}
		}
	}
	if stale != nil {
		edited, err = tomledit.Edit(edited, stale)
	}
	return edited, func(connection string) bool { return networks || setup(connection) }, renamed, err
}

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

func (c *Config) Effective() (string, error) {
	v, err := c.View()
	if err != nil {
		return "", err
	}
	ps := map[string]any{}
	for _, connection := range c.Connections {
		if ps[connection.Preset], err = facts.JSON[map[string]any](c.presets[connection.Preset]); err != nil {
			return "", err
		}
	}
	v["presets"] = ps
	return tomledit.Render(v)
}

func (c *Config) AgentView(p facts.Principal) (map[string]any, error) {
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

func proposalTarget(path []string) (string, bool) {
	switch {
	case len(path) >= 2 && (path[0] == "connections" || path[0] == "default_access") && path[1] != "":
		return path[1], true
	case len(path) >= 4 && path[0] == "identities" && path[1] != "" && path[2] == "connections" && path[3] != "":
		return path[3], true
	}
	return "", false
}

func ProposalChanges(p facts.Principal, changes []tomledit.Change, others bool) (map[string][]tomledit.Change, error) {
	groups := map[string][]tomledit.Change{}
	for _, change := range changes {
		target, ok := proposalTarget(change.Path)
		if !ok || change.From != nil {
			return nil, errors.New("proposals may change only service setup and access")
		}
		if !others && (change.Path[0] == "default_access" || change.Path[0] == "identities" && change.Path[1] != p.Name) {
			return nil, errors.New("this identity may propose only service setup and its own access")
		}
		groups[target] = append(groups[target], change)
	}
	return groups, nil
}

type Proposal struct {
	Source  string            `json:"source,omitempty"`
	Changes []tomledit.Change `json:"changes,omitempty"`
	Reason  string            `json:"reason"`
	Delete  [][]string        `json:"delete,omitempty"`
}

func (p Proposal) Edits() ([]tomledit.Change, error) {
	if (p.Source != "" || p.Delete != nil) == (p.Changes != nil) {
		return nil, errors.New("proposal requires exactly one of a TOML fragment or structured changes")
	}
	changes := p.Changes
	if changes == nil {
		var err error
		if changes, err = tomledit.Fragment(p.Source); err != nil {
			return nil, err
		}
		for _, path := range p.Delete {
			changes = append(changes, tomledit.Change{Path: path, Delete: true})
		}
	}
	if len(changes) == 0 || len(changes) > maxProposalChanges {
		return nil, fmt.Errorf("proposal must contain 1-%d changes", maxProposalChanges)
	}
	return changes, nil
}

type Enrollment struct {
	Key        string                     `json:"key"`
	Routes     bool                       `json:"routes"`
	Restore    bool                       `json:"restore"`
	Attributes map[string]json.RawMessage `json:",embed"`
}

func (c *Config) Enroll(input map[string]Enrollment, enrolled map[string]bool, fields map[string]func(json.RawMessage) error) ([]tomledit.Change, error) {
	var changes []tomledit.Change
	for name, id := range input {
		fingerprint, err := KeyFingerprint(id.Key)
		if err != nil {
			return nil, err
		}
		attributes := map[string]any{}
		for key, raw := range id.Attributes {
			if fields[key] == nil {
				return nil, fmt.Errorf("an enrollment has no field %s", key)
			}
			if attributes[key], err = facts.JSON[any](raw); err != nil {
				return nil, err
			}
		}
		maps.DeleteFunc(attributes, func(_ string, value any) bool { return value == nil })
		if principal, ok := c.Principal(fingerprint); ok {
			existing := c.Identities[principal.Name]
			if id.Routes && !existing.Routes {
				if !id.Restore {
					return nil, errors.New("device route access was revoked")
				}
				changes = append(changes, tomledit.Change{Path: []string{"identities", principal.Name, "routes"}, Value: true})
			}
			for key, value := range attributes {
				if before, _ := facts.JSON[any](existing.Attributes[key]); !reflect.DeepEqual(value, before) {
					changes = append(changes, tomledit.Change{Path: []string{"identities", principal.Name, key}, Value: value})
				}
			}
			continue
		}
		if enrolled[fingerprint] && !id.Restore {
			return nil, errors.New("identity was revoked; restore access explicitly in the Perimeter")
		}
		if _, exists := c.Identities[name]; exists {
			return nil, errors.New("identity name belongs to another key")
		}
		value := map[string]any{"key": id.Key, "routes": id.Routes}
		maps.Copy(value, attributes)
		changes = append(changes, tomledit.Change{Path: []string{"identities", name}, Value: value})
	}
	return changes, nil
}
