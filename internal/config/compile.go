package config

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"slices"
	"strings"

	jsonpatch "github.com/evanphx/json-patch/v5"
	"github.com/tinfoilsh/monitor/facts"
	"github.com/tinfoilsh/monitor/internal/policy"
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

// Compile resolves source into a policy snapshot and connection specifications.
// The monitor validates connector configurations and binds credentials before activation.
func Compile(ctx context.Context, text string) (*Snapshot, map[string]ConnectionSpec, error) {
	source, err := ReadSource(text)
	if err != nil {
		return nil, nil, err
	}
	decoded, err := JSONValue(source)
	if err != nil {
		return nil, nil, err
	}
	cfg := &Config{Lattices: policy.Lattices{Confidentiality: true}}
	raw, err := json.Marshal(decoded)
	if err == nil {
		err = facts.DecodeNumbers(raw, cfg)
	}
	if err != nil {
		return nil, nil, err
	}
	if err := validateEffects("global settings", cfg.Effects); err != nil {
		return nil, nil, err
	}
	shipped, err := presets.Shipped()
	if err != nil {
		return nil, nil, err
	}
	cfg.Resolved = maps.Clone(shipped)
	for name, override := range cfg.Presets {
		raw := json.RawMessage(`{}`)
		if shipped[name] != nil {
			raw = shipped[name].Source
		}
		patch, err := json.Marshal(override)
		if err == nil {
			raw, err = jsonpatch.MergePatch(raw, patch)
		}
		if err == nil {
			cfg.Resolved[name], err = presets.Decode(raw)
		}
		if err != nil {
			return nil, nil, fmt.Errorf("preset %s: %w", name, err)
		}
	}
	connections := map[string]ConnectionSpec{}
	for acct, a := range cfg.Accounts {
		if _, ok := cfg.Resolved[a.Preset]; !ok {
			return nil, nil, fmt.Errorf("account %s has unknown preset %s", acct, a.Preset)
		}
		base, _ := json.Marshal(presets.Catalog{Connections: cfg.Resolved[a.Preset].Catalog.Connections})
		patch, _ := json.Marshal(a)
		raw, err := jsonpatch.MergePatch(base, patch)
		a = Account{}
		if err == nil {
			err = facts.DecodeNumbers(raw, &a)
		}
		if err != nil {
			return nil, nil, fmt.Errorf("account %s: %w", acct, err)
		}
		cfg.Accounts[acct] = a
		if err := validateEffects("account "+acct, a.Effects); err != nil {
			return nil, nil, err
		}
		if !slices.Contains(facts.Audiences, a.Contents) || !slices.Contains(facts.Audiences, a.Sends) {
			return nil, nil, fmt.Errorf("account %s: contents and sends must be one of %v", acct, facts.Audiences)
		}
		for key, kinds := range a.Connections {
			name := ConnectionName(acct, key)
			if name == AgentConnection {
				return nil, nil, fmt.Errorf("connection name %s is reserved for the monitor", name)
			}
			if _, exists := connections[name]; exists {
				return nil, nil, fmt.Errorf("connection name %s is taken", name)
			}
			if len(kinds) != 1 {
				return nil, nil, fmt.Errorf("connection %s must have one kind", name)
			}
			for kind, spec := range kinds {
				raw, _ := json.Marshal(spec)
				connections[name] = ConnectionSpec{Name: name, Protocol: kind, Account: acct, Key: key, Config: raw}
			}
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
		return nil, nil, err
	}
	for name, id := range cfg.Identities {
		if id.Reviewer != "" && (id.Reviewer != "tinfoil" || cfg.Reviewer == nil) {
			return nil, nil, fmt.Errorf("identity %s: configure Tinfoil review before assigning it", name)
		}
		if err := validateEffects("agent "+name, id.Effects); err != nil {
			return nil, nil, err
		}
		accounts := maps.Clone(cfg.DefaultAccess)
		if accounts == nil {
			accounts = map[string]Access{}
		}
		maps.Copy(accounts, id.Accounts)
		for acct, a := range accounts {
			if a.Level == "" {
				inherited := cfg.DefaultAccess[acct]
				a.Level = inherited.Level
				a.Actions = inheritModes(inherited.Actions, a.Actions)
				a.Effects = inheritModes(inherited.Effects, a.Effects)
				accounts[acct] = a
			}
		}
		id.Accounts = accounts
		if err := validateAccess("identity "+name, accounts); err != nil {
			return nil, nil, err
		}
		cfg.Identities[name] = id
	}
	if cfg.Reviewer != nil {
		r := cfg.Reviewer
		c, exists := connections[r.Connection]
		if !exists || c.Protocol != "tinfoil" {
			return nil, nil, errors.New("reviewer requires a Tinfoil connection")
		}
		if strings.TrimSpace(r.Model) == "" || len(r.Model) > 200 || strings.TrimSpace(r.Instructions) == "" || len(r.Instructions) > 8192 {
			return nil, nil, errors.New("reviewer requires a model and instructions of 1-8192 bytes")
		}
	}

	snapshot := &Snapshot{Config: cfg, Principals: map[string]Principal{}}
	for name, id := range cfg.Identities {
		key, _, _, _, err := ssh.ParseAuthorizedKey([]byte(id.Key))
		if err != nil {
			return nil, nil, fmt.Errorf("identity %s: %w", name, err)
		}
		fingerprint := ssh.FingerprintSHA256(key)
		if _, exists := snapshot.Principals[fingerprint]; exists {
			return nil, nil, fmt.Errorf("identity %s shares another identity's public key", name)
		}
		snapshot.Principals[fingerprint] = Principal{Key: fingerprint, Name: name, Identity: id}
	}
	if snapshot.Engine, err = policy.Prepare(ctx, cfg.Data, cfg.Policies, cfg.Lattices); err != nil {
		return nil, nil, err
	}
	if snapshot.Catalog, snapshot.CatalogID, err = catalog(cfg); err != nil {
		return nil, nil, err
	}
	return snapshot, connections, nil
}
