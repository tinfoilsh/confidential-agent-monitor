package config

import (
	"encoding/json"
	"fmt"
	"maps"
	"reflect"
	"slices"

	jsonpatch "github.com/evanphx/json-patch/v5"
	"github.com/tinfoilsh/monitor/facts"
	"github.com/tinfoilsh/monitor/presets"
	"golang.org/x/crypto/ssh"
)

var levels = []string{"off", "read", "ask", "allow"}

func validateEffects(name string, effects map[string]string) error {
	for effect, mode := range effects {
		if _, ok := facts.Effects[effect]; !ok {
			return fmt.Errorf("%s: unknown effect %q", name, effect)
		}
		if !slices.Contains([]string{"off", "ask", "allow"}, mode) {
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

// Load validates declared settings without retaining expanded accounts or identities.
// Protocol decoding and credential binding remain at the connector boundary.
func Load(text string) (*Config, error) {
	decoded, err := readSource(text)
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
	if err := cfg.validateDevelopmentPresets(); err != nil {
		return nil, err
	}
	connections := map[string]string{}
	for acct, a := range cfg.Accounts {
		if err := validateEffects("account "+acct, a.Effects); err != nil {
			return nil, err
		}
		if !slices.Contains(facts.Audiences, a.Contents) || !slices.Contains(facts.Audiences, a.Sends) {
			return nil, fmt.Errorf("account %s: contents and sends must be one of %v", acct, facts.Audiences)
		}
		specs, err := cfg.Connections(acct)
		if err != nil {
			return nil, err
		}
		for _, spec := range specs {
			if _, exists := connections[spec.Name]; exists || spec.Name == AgentConnection {
				return nil, fmt.Errorf("connection name %s is taken or reserved", spec.Name)
			}
			connections[spec.Name] = spec.Protocol
		}
	}
	validateAccess := func(name string, accounts map[string]Access) error {
		for acct, a := range accounts {
			if _, ok := cfg.Accounts[acct]; !ok || !slices.Contains(levels, a.Level) {
				return fmt.Errorf("%s: account %s must exist and have a level in %v", name, acct, levels)
			}
			if err := validateEffects(name+" on "+acct, a.Effects); err != nil {
				return err
			}
			for action, level := range a.Actions {
				if level == "read" || !slices.Contains(levels, level) {
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
		key, _, _, _, err := ssh.ParseAuthorizedKey([]byte(id.Key))
		if err != nil {
			return nil, fmt.Errorf("identity %s: %w", name, err)
		}
		fingerprint := ssh.FingerprintSHA256(key)
		if _, exists := cfg.Principals[fingerprint]; exists {
			return nil, fmt.Errorf("identity %s shares another identity's public key", name)
		}
		cfg.Principals[fingerprint] = name
	}
	if err := cfg.validateDevelopment(connections); err != nil {
		return nil, err
	}
	return cfg, nil
}

func (c *Config) Principal(key string) (Principal, bool) {
	name, ok := c.Principals[key]
	return Principal{Fingerprint: key, Name: name}, ok
}

// An explicit level replaces defaults; an omitted level inherits and overlays them.
func (c *Config) Access(agent, account string) Access {
	id, ok := c.Identities[agent]
	if !ok {
		return Access{}
	}
	a := id.Accounts[account]
	if a.Level == "" {
		base := c.DefaultAccess[account]
		a.Level = base.Level
		a.Actions = inheritModes(base.Actions, a.Actions)
		a.Effects = inheritModes(base.Effects, a.Effects)
	}
	return a
}

func (c *Config) Accesses(agent string) map[string]Access {
	accounts := map[string]Access{}
	maps.Copy(accounts, c.DefaultAccess)
	maps.Copy(accounts, c.Identities[agent].Accounts)
	for account := range accounts {
		accounts[account] = c.Access(agent, account)
	}
	return accounts
}

func (c *Config) Reaches(agent, account string) bool {
	level := c.Access(agent, account).Level
	return level != "" && level != "off"
}

// SameProgram compares preparation inputs, not the persisted approval program hash.
func (c *Config) SameProgram(old *Config) bool {
	return old != nil && c.Lattices == old.Lattices && reflect.DeepEqual(c.Data, old.Data) && reflect.DeepEqual(c.Policies, old.Policies)
}

// Connections projects only this account's setup; the returned definitions remain opaque.
func (c *Config) Connections(account string) ([]ConnectionSpec, error) {
	a := c.Accounts[account]
	preset, err := c.Preset(a.Preset)
	if err != nil {
		return nil, fmt.Errorf("account %s: %w", account, err)
	}
	// Parsers consume title, action effects and their opaque protocol roots.
	// Keep those roots as RawMessages so grant encodings retain their inner order;
	// catalog labels/defaults are control data, while title remains facts input.
	var definition map[string]json.RawMessage
	if err := json.Unmarshal(preset.Source, &definition); err != nil {
		return nil, err
	}
	actions := map[string]map[string][]string{}
	for name, action := range preset.Catalog.Actions {
		if action.Effects != nil {
			actions[name] = map[string][]string{"effects": action.Effects}
		}
	}
	definition["catalog"], _ = json.Marshal(map[string]any{"actions": actions})
	semantic, _ := json.Marshal(definition)
	fields, err := preset.Catalog.CredentialFields()
	if err != nil {
		return nil, err
	}
	raw, _ := json.Marshal(preset.Catalog.Connections)
	if preset.Catalog.Connections == nil {
		raw = []byte(`{}`)
	}
	if a.Connections != nil {
		patch, _ := json.Marshal(a.Connections)
		if raw, err = jsonpatch.MergePatch(raw, patch); err != nil {
			return nil, err
		}
	}
	var connections map[string]map[string]any
	if err := facts.DecodeNumbers(raw, &connections); err != nil {
		return nil, err
	}
	local := a.PolicyOptions
	local.Private = nil // Private patterns affect Gate, not connector interpretation.
	options, _ := json.Marshal(local)
	var specs []ConnectionSpec
	for key, kinds := range connections {
		if len(kinds) != 1 {
			return nil, fmt.Errorf("connection %s must have one kind", ConnectionName(account, key))
		}
		for kind, value := range kinds {
			var credentials []string
			for _, paths := range fields {
				for _, path := range paths {
					if path.Connection == key && path.Protocol == kind {
						credentials = append(credentials, path.Secret)
					}
				}
			}
			raw, _ := json.Marshal(value) // Setup bytes retain the deployed canonical grant encoding.
			specs = append(specs, ConnectionSpec{Name: ConnectionName(account, key), Protocol: kind, Account: account, Key: key,
				Config: raw, Definition: semantic, Options: options, PublicScope: preset.PublicScope, CredentialNames: slices.Compact(slices.Sorted(slices.Values(credentials)))})
		}
	}
	return specs, nil
}

// Preset resolves shipped definitions in release builds. Explicit development
// builds may additionally merge custom source overrides.
func (c *Config) Preset(name string) (*presets.Preset, error) {
	shipped, err := presets.Shipped()
	if err != nil {
		return nil, err
	}
	return c.resolvePreset(shipped, name)
}
