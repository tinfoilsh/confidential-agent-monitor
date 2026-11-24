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
	"time"

	jsonpatch "github.com/evanphx/json-patch/v5"
	"github.com/tinfoilsh/confidential-agent-monitor/connector/catalog"
	"github.com/tinfoilsh/confidential-agent-monitor/core/facts"
	"github.com/tinfoilsh/confidential-agent-monitor/core/tomledit"
	"golang.org/x/crypto/ssh"
)

const (
	AgentConnection    = "agent"
	OwnerName          = "owner"
	maxPolicyBytes     = 2 << 20
	maxProposalChanges = 256
)

var accessLevels = []string{"off", "read", "ask", "allow"}

type ConnectionSpec struct {
	Name, Protocol              string
	Config, Definition, Options json.RawMessage
	PublicScope                 []string
}

type Access struct {
	Level   string            `json:"level,omitempty"`
	Actions map[string]string `json:"actions,omitempty"`
	Effects map[string]string `json:"effects,omitempty"`
}

type Group struct {
	Connections map[string]Access `json:"connections,omitempty"`
}

type CertificateBinding struct {
	KeyID string `json:"key_id,omitempty"`
	Group string `json:"group,omitempty"`
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
	Expires      string         `json:"expires,omitempty"`
}

type Identity struct {
	Key         string                     `json:"key,omitempty"`
	Certificate *CertificateBinding        `json:"certificate,omitempty"`
	Groups      []string                   `json:"groups,omitempty"`
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
	MatchOnly     bool                       `json:"match_only,omitempty"`
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
	Access        Access                `json:"access,omitzero"`
	DefaultAccess map[string]Access     `json:"default_access,omitempty"`
	Groups        map[string]Group      `json:"groups,omitempty"`
	Lattices      Lattices              `json:"lattices"`
	AllowNetworks []netip.Prefix        `json:"allow_networks"`
	Connections   map[string]Connection `json:"connections"`
	Identities    map[string]Identity   `json:"identities"`
	Policies      map[string]string     `json:"policies"`
	Data          map[string]any        `json:"data"`
	Catalogs      map[string]string     `json:"catalogs,omitempty"`
	Principals    map[string]string     `json:"-"`

	Presets    map[string]*catalog.Preset             `json:"-"`
	Operations map[string]map[string]OperationSummary `json:"-"`
}

type Library func(*Config) (map[string]*catalog.Preset, error)

func validateModes(where string, modes map[string]string, effects bool) error {
	for key, mode := range modes {
		if _, ok := Vocabulary[key]; effects && !ok {
			return fmt.Errorf("%s: unknown effect %q", where, key)
		}
		if !Mode(mode).valid() {
			return fmt.Errorf("%s.%s must be off, ask or allow", where, tomledit.Key(key))
		}
	}
	return nil
}

func validateBlock(at string, a Access) error {
	if a.Level != "" && !slices.Contains(accessLevels, a.Level) {
		return fmt.Errorf("%s.level must be one of %v", at, accessLevels)
	}
	if err := validateModes(at+".effects", a.Effects, true); err != nil {
		return err
	}
	return validateModes(at+".actions", a.Actions, false)
}

func (c *Config) validateAccess(where string, connections map[string]Access) error {
	for connection, a := range connections {
		at := tomlPath(where, connection)
		if _, ok := c.Connections[connection]; !ok {
			return fmt.Errorf("%s: connection %s does not exist", at, connection)
		}
		// A level there would grant every action of the Perimeter's API, root included.
		if connection == PerimeterConnection && (a.Level != "" || a.Effects != nil) {
			return fmt.Errorf("%s: the %s connection is granted by actions only", at, PerimeterConnection)
		}
		if err := validateBlock(at, a); err != nil {
			return err
		}
	}
	return nil
}

func Load(text string, presets Library) (*Config, error) {
	if len(text) > maxPolicyBytes {
		return nil, errors.New("policy source is too large")
	}
	decoded, err := tomledit.Read(text)
	if err == nil {
		err = perimeterTable(decoded)
	}
	if err != nil {
		return nil, err
	}
	cfg := &Config{Lattices: Lattices{Confidentiality: true}}
	raw, err := json.Marshal(decoded)
	if err == nil {
		err = facts.DecodeNumbers(raw, cfg)
	}
	if err == nil {
		cfg.Presets, err = presets(cfg)
	}
	if err == nil {
		err = cfg.builtIn()
	}
	if err == nil {
		err = cfg.validate()
	}
	if err != nil {
		return nil, err
	}
	return cfg, nil
}

func (c *Config) validate() error {
	if err := validateBlock(accountAccess, c.Access); err != nil {
		return err
	}
	for name, conn := range c.Connections {
		if name == AgentConnection {
			return fmt.Errorf("connection name %s is reserved", name)
		}
		if conn.Preset == "" {
			return fmt.Errorf("connection %s needs a preset", name)
		}
		if conn.Preset == PerimeterConnection && name != PerimeterConnection {
			return fmt.Errorf("connection %s: preset %s is the Perimeter's own", name, conn.Preset)
		}
		if !slices.Contains(Audiences, conn.Contents) || !slices.Contains(Audiences, conn.Sends) {
			return fmt.Errorf("connection %s: contents and sends must be one of %v", name, Audiences)
		}
		if _, err := c.Spec(name); name != PerimeterConnection && err != nil {
			return err
		}
	}
	if err := c.validateAccess("default_access", c.DefaultAccess); err != nil {
		return err
	}
	for name, group := range c.Groups {
		if err := c.validateAccess(tomlPath("groups", name, "connections"), group.Connections); err != nil {
			return err
		}
	}
	c.Principals = map[string]string{}
	keyIDs := map[string]string{}
	for name, id := range c.Identities {
		if name == OwnerName {
			return fmt.Errorf("identity name %s is reserved for the owner", name)
		}
		if (id.Key == "") == (id.Certificate == nil) {
			return fmt.Errorf("identity %s needs exactly one of key or certificate", name)
		}
		if err := c.validateAccess(tomlPath("identities", name, "connections"), id.Connections); err != nil {
			return err
		}
		for rule, r := range id.Rules {
			if _, err := time.Parse(time.RFC3339, r.Expires); r.Expires != "" && err != nil {
				return fmt.Errorf("identity %s rule %s: expires must be an RFC 3339 timestamp", name, rule)
			}
		}
		if cert := id.Certificate; cert != nil {
			if (cert.KeyID == "") == (cert.Group == "") {
				return fmt.Errorf("identity %s: certificate needs exactly one of key_id or group", name)
			}
			if other, taken := keyIDs[cert.KeyID]; cert.KeyID != "" && taken {
				return fmt.Errorf("identities %s and %s bind the same certificate key ID", min(name, other), max(name, other))
			}
			keyIDs[cert.KeyID] = name
			continue
		}
		fingerprint, err := KeyFingerprint(id.Key)
		if err != nil {
			return fmt.Errorf("identity %s: %w", name, err)
		}
		if _, exists := c.Principals[fingerprint]; exists {
			return fmt.Errorf("identity %s shares another identity's public key", name)
		}
		c.Principals[fingerprint] = name
	}
	return nil
}

func (c *Config) BindCertificate(keyID string, principals []string) (name string, groups []string, ok bool) {
	names := slices.Sorted(maps.Keys(c.Identities))
	bound := func(match func(*CertificateBinding) bool) bool {
		i := slices.IndexFunc(names, func(n string) bool { return c.Identities[n].Certificate != nil && match(c.Identities[n].Certificate) })
		if i >= 0 {
			name = names[i]
		}
		return i >= 0
	}
	if !bound(func(b *CertificateBinding) bool { return b.KeyID != "" && b.KeyID == keyID }) &&
		!bound(func(b *CertificateBinding) bool { return b.Group != "" && slices.Contains(principals, b.Group) }) {
		return "", nil, false
	}
	groups = slices.Clone(principals)
	for _, g := range c.Identities[name].Groups {
		if !slices.Contains(groups, g) {
			groups = append(groups, g)
		}
	}
	return name, groups, true
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

func (c *Config) Spec(name string) (ConnectionSpec, error) {
	connection := c.Connections[name]
	preset := c.Presets[connection.Preset]
	if preset == nil {
		return ConnectionSpec{}, fmt.Errorf("connection %s: unknown preset %s", name, connection.Preset)
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
		return ConnectionSpec{}, fmt.Errorf("connection %s must have one kind", name)
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

func (c *Config) Edit(source string, changes []tomledit.Change, presets Library) (edited string, rebuild func(connection string) bool, renamed map[string]string, err error) {
	edited, err = tomledit.Edit(source, changes)
	if err != nil {
		return "", nil, nil, err
	}
	next, err := Load(edited, presets)
	if err != nil {
		return "", nil, nil, err
	}
	// Operations are compiled when settings are prepared, so a freshly loaded policy has none to compare.
	next.Operations = c.Operations
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
	v.Connections = maps.Clone(c.Connections)
	for name, connection := range v.Connections {
		if name == PerimeterConnection {
			continue
		}
		spec, err := c.Spec(name)
		if err != nil {
			return nil, err
		}
		connection.Setup = map[string]json.RawMessage{spec.Protocol: spec.Config}
		v.Connections[name] = connection
	}
	resolved := map[string]map[string]Resolved{}
	for name, id := range c.Identities {
		resolved[name] = map[string]Resolved{}
		for connection := range c.Connections {
			resolved[name][connection] = c.Resolve(name, id.Groups, connection)
		}
	}
	view := map[string]any{"resolved": resolved}
	if stale := c.staleRules(); len(stale) != 0 {
		view["stale"] = stale
	}
	out, err := facts.JSON[map[string]any](v)
	if err != nil {
		return nil, err
	}
	extra, err := facts.JSON[map[string]any](view)
	maps.Copy(out, extra)
	return out, err
}

func (c *Config) Effective() (string, error) {
	v, err := c.View()
	if err != nil {
		return "", err
	}
	ps := map[string]any{}
	for _, connection := range c.Connections {
		if ps[connection.Preset], err = facts.JSON[map[string]any](c.Presets[connection.Preset]); err != nil {
			return "", err
		}
	}
	v["presets"] = ps
	return tomledit.Render(v)
}

func (c *Config) AgentView(p facts.Principal) (map[string]any, error) {
	own, resolved := map[string]Access{}, map[string]Resolved{}
	connections := map[string]any{}
	for name, connection := range c.Connections {
		r := c.Resolve(p.Name, p.Groups, name)
		if !r.Reaches {
			continue
		}
		resolved[name] = r
		connections[name] = map[string]any{"contents": connection.Contents, "strangers": connection.Strangers, "sends": connection.Sends, "policy_options": connection.PolicyOptions}
		if a, ok := c.Identities[p.Name].Connections[name]; ok {
			own[name] = a
		}
	}
	identity := map[string]any{"connections": own, "resolved": resolved}
	if rules := c.Identities[p.Name].Rules; len(rules) != 0 {
		identity["rules"] = rules
	}
	if stale := c.staleRules()[p.Name]; len(stale) != 0 {
		identity["stale"] = stale
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
			return nil, errors.New("proposals may change only connection setup and access")
		}
		// Access to the Perimeter's own API is the owner's to grant, never a proposal's.
		if target == PerimeterConnection {
			return nil, fmt.Errorf("proposals cannot change the %s connection", PerimeterConnection)
		}
		if !others && (change.Path[0] == "default_access" || change.Path[0] == "identities" && change.Path[1] != p.Name) {
			return nil, errors.New("this identity may propose only connection setup and its own access")
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

func (c *Config) PerimeterOff(p facts.Principal, action string) bool {
	op := c.Operation(PerimeterConnection, action)
	return strictest(c.Modes(p.Name, p.Groups, PerimeterConnection, op, KindOperation)).Mode == ModeOff
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
			// A label or the owner policy may stop a device for now; only its access says it was revoked.
			if id.Routes && c.PerimeterOff(principal, RoutesPublish) {
				if !id.Restore {
					return nil, errors.New("device route access was revoked")
				}
				if !slices.Contains(existing.Groups, DeviceGroup) {
					changes = append(changes, tomledit.Change{Path: []string{"identities", principal.Name, "groups"}, Value: append(slices.Clone(existing.Groups), DeviceGroup)})
				}
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
		value := map[string]any{"key": id.Key}
		if id.Routes {
			value["groups"] = []string{DeviceGroup}
		}
		maps.Copy(value, attributes)
		changes = append(changes, tomledit.Change{Path: []string{"identities", name}, Value: value})
	}
	return changes, nil
}
