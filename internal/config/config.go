package config

import (
	"encoding/json"
	"fmt"
	"maps"
	"slices"

	jsonpatch "github.com/evanphx/json-patch/v5"
	"github.com/tinfoilsh/monitor/facts"
	"github.com/tinfoilsh/monitor/presets"
	"golang.org/x/crypto/ssh"
)

var (
	levels = []string{"off", "read", "ask", "allow"}
	modes  = []string{"off", "ask", "allow"}
)

func validateEffects(name string, effects map[string]string) error {
	for effect, mode := range effects {
		if _, ok := facts.Effects[effect]; !ok {
			return fmt.Errorf("%s: unknown effect %q", name, effect)
		}
		if !slices.Contains(modes, mode) {
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

// Load validates declared settings without retaining expanded connections or identities.
// Protocol decoding and credential binding remain at the connector boundary.
func Load(text string) (*Config, error) {
	decoded, err := ReadSource(text)
	if err != nil {
		return nil, err
	}
	cfg := &Config{Lattices: Lattices{Confidentiality: true}}
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
		if !slices.Contains(facts.Audiences, c.Contents) || !slices.Contains(facts.Audiences, c.Sends) {
			return nil, fmt.Errorf("service %s: contents and sends must be one of %v", name, facts.Audiences)
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
			if _, ok := cfg.Connections[connection]; !ok || !slices.Contains(levels, a.Level) {
				return fmt.Errorf("%s: service %s must exist and have a level in %v", name, connection, levels)
			}
			if err := validateEffects(name+" on "+connection, a.Effects); err != nil {
				return err
			}
			for action, level := range a.Actions {
				if !slices.Contains(modes, level) {
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
		fingerprint, err := Fingerprint(id.Key)
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

// Fingerprint names the principal an identity's authorized key authenticates.
func Fingerprint(authorizedKey string) (string, error) {
	key, _, _, _, err := ssh.ParseAuthorizedKey([]byte(authorizedKey))
	if err != nil {
		return "", err
	}
	return ssh.FingerprintSHA256(key), nil
}

func (c *Config) Principal(key string) (Principal, bool) {
	name, ok := c.Principals[key]
	return Principal{Key: key, Name: name, Groups: c.Identities[name].Groups}, ok
}

// An explicit level replaces defaults; an omitted level inherits and overlays them.
func (c *Config) Access(agent, connection string) Access {
	a := c.Identities[agent].Connections[connection]
	if a.Level == "" {
		base := c.DefaultAccess[connection]
		a.Level = base.Level
		a.Actions = inheritModes(base.Actions, a.Actions)
		a.Effects = inheritModes(base.Effects, a.Effects)
	}
	return a
}

func (c *Config) Accesses(agent string) map[string]Access {
	connections := map[string]Access{}
	maps.Copy(connections, c.DefaultAccess)
	maps.Copy(connections, c.Identities[agent].Connections)
	for connection := range connections {
		connections[connection] = c.Access(agent, connection)
	}
	return connections
}

func (c *Config) Reaches(agent, connection string) bool {
	a := c.Access(agent, connection)
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

// Spec projects only this connection's setup; the returned definition remains opaque.
func (c *Config) Spec(name string) (ConnectionSpec, error) {
	connection := c.Connections[name]
	preset, err := presets.Lookup(connection.Preset)
	if err != nil {
		return ConnectionSpec{}, fmt.Errorf("service %s: %w", name, err)
	}
	// Parsers consume title, action effects and their opaque protocol roots.
	// Keep those roots as RawMessages so grant encodings retain their inner order;
	// catalog labels/defaults are control data, while title remains facts input.
	var definition map[string]json.RawMessage
	if err := json.Unmarshal(preset.Source, &definition); err != nil {
		return ConnectionSpec{}, err
	}
	actions := map[string]map[string][]string{}
	for name, action := range preset.Catalog.Actions {
		if action.Effects != nil {
			actions[name] = map[string][]string{"effects": action.Effects}
		}
	}
	definition["catalog"], _ = json.Marshal(map[string]any{"actions": actions})
	semantic, _ := json.Marshal(definition)
	raw, _ := json.Marshal(preset.Catalog.Connection)
	if preset.Catalog.Connection == nil {
		raw = []byte(`{}`)
	}
	if connection.Setup != nil {
		patch, _ := json.Marshal(connection.Setup)
		if raw, err = jsonpatch.MergePatch(raw, patch); err != nil {
			return ConnectionSpec{}, err
		}
	}
	var kinds map[string]any
	if err := facts.DecodeNumbers(raw, &kinds); err != nil {
		return ConnectionSpec{}, err
	}
	if len(kinds) != 1 {
		return ConnectionSpec{}, fmt.Errorf("service %s must have one kind", name)
	}
	local := connection.PolicyOptions
	local.Private = nil // Private patterns affect Gate, not connector interpretation.
	options, _ := json.Marshal(local)
	spec := ConnectionSpec{Name: name, Definition: semantic, Options: options, PublicScope: preset.PublicScope}
	for kind, value := range kinds {
		spec.Protocol = kind
		spec.Config, _ = json.Marshal(value) // Setup bytes retain the deployed canonical grant encoding.
	}
	return spec, nil
}
