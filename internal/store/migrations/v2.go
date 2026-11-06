// Package migrations upgrades stored state documents written in earlier formats.
package migrations

import (
	"encoding/json"
	"maps"
	"slices"

	"github.com/tinfoilsh/monitor/internal/config"
	"github.com/tinfoilsh/monitor/presets"
)

// Version is the stored state format Upgrade produces.
const Version = 2

// namedKinds take their credential names from setup, which version 1 declared as secrets.
var namedKinds = []string{"cli", "ssh-agent"}

// split gives the preset each connection of a version 1 multi-connection preset now has.
var split = map[string]map[string]string{
	"email":   {"imap": "email", "smtp": "email_send"},
	"github":  {"": "github", "mcp": "github_mcp"},
	"tinfoil": {"": "tinfoil", "websearch": "tinfoil_websearch"},
}

// Upgrade rewrites documents older than Version; those written before versioning
// have the version 1 layout. Each version 1 account connection becomes a top-level
// connection named after it, with its account's settings, access and credentials,
// and rules name their connection. A connection its preset did not declare is
// dropped unless the preset declares none, since it would inherit the preset's.
// Credential declarations are removed from connection setups.
func Upgrade(plain []byte) ([]byte, error) {
	var v1 struct {
		Version int                                              `json:"version"`
		Policy  string                                           `json:"policy"`
		Secrets map[string]map[string]map[string]json.RawMessage `json:"secrets"`
	}
	if err := json.Unmarshal(plain, &v1); err != nil {
		return nil, err
	}
	if v1.Version >= Version {
		return plain, nil
	}
	source, err := config.ReadSource(v1.Policy)
	if err != nil {
		return nil, err
	}
	shipped, err := presets.Shipped()
	if err != nil {
		return nil, err
	}
	accounts, _ := source["accounts"].(map[string]any)
	connections := map[string]map[string]any{}
	credentials := map[string]map[string]json.RawMessage{}
	targets := map[string][]string{}
	for _, name := range slices.Sorted(maps.Keys(accounts)) {
		account, _ := accounts[name].(map[string]any)
		preset, _ := account["preset"].(string)
		setups, _ := account["connections"].(map[string]any)
		keys := maps.Clone(split[preset])
		if keys == nil {
			keys = map[string]string{}
			if p := shipped[preset]; p != nil && p.Catalog.Connection != nil {
				keys[""] = preset
			}
		}
		for key, setup := range setups {
			if setup == nil {
				delete(keys, key)
			} else if p := shipped[preset]; keys[key] == "" && p != nil && p.Catalog.Connection == nil {
				keys[key] = preset
			}
		}
		for _, key := range slices.Sorted(maps.Keys(keys)) {
			target := name
			if key != "" {
				target = name + "-" + key
			}
			connection := maps.Clone(account)
			delete(connection, "connections")
			connection["preset"] = keys[key]
			setup, _ := setups[key].(map[string]any)
			for kind, value := range setup {
				cfg, _ := value.(map[string]any)
				if declared, ok := cfg["secrets"]; ok {
					delete(cfg, "secrets")
					if names, _ := declared.(map[string]any); slices.Contains(namedKinds, kind) && len(names) != 0 {
						cfg["credentials"] = slices.Sorted(maps.Keys(names))
					}
				}
				connection[kind] = value
			}
			connections[target] = connection
			targets[name] = append(targets[name], target)
			if len(v1.Secrets[name][key]) != 0 {
				credentials[target] = v1.Secrets[name][key]
			}
		}
	}
	var changes []config.Change
	if accounts != nil {
		changes = append(changes, config.Change{Path: []string{"accounts"}, Delete: true})
	}
	for _, name := range slices.Sorted(maps.Keys(connections)) {
		changes = append(changes, config.Change{Path: []string{"connections", name}, Value: connections[name]})
	}
	regrant := func(path []string, granted map[string]any) {
		for _, account := range slices.Sorted(maps.Keys(granted)) {
			for _, target := range targets[account] {
				changes = append(changes, config.Change{Path: append(slices.Clone(path), target), Value: granted[account]})
			}
		}
	}
	if defaults, ok := source["default_access"].(map[string]any); ok {
		changes = append(changes, config.Change{Path: []string{"default_access"}, Delete: true})
		regrant([]string{"default_access"}, defaults)
	}
	identities, _ := source["identities"].(map[string]any)
	for _, identity := range slices.Sorted(maps.Keys(identities)) {
		id, _ := identities[identity].(map[string]any)
		if granted, ok := id["accounts"].(map[string]any); ok {
			changes = append(changes, config.Change{Path: []string{"identities", identity, "accounts"}, Delete: true})
			regrant([]string{"identities", identity, "connections"}, granted)
		}
		rules, _ := id["rules"].(map[string]any)
		for _, rule := range slices.Sorted(maps.Keys(rules)) {
			if r, _ := rules[rule].(map[string]any); r["account"] != nil {
				path := []string{"identities", identity, "rules", rule}
				changes = append(changes, config.Change{Path: append(path, "account"), Delete: true},
					config.Change{Path: append(slices.Clone(path), "connection"), Value: r["account"]})
			}
		}
	}
	if len(changes) != 0 {
		if v1.Policy, err = config.EditSource(v1.Policy, changes); err != nil {
			return nil, err
		}
	}
	var doc map[string]json.RawMessage
	if err := json.Unmarshal(plain, &doc); err != nil {
		return nil, err
	}
	delete(doc, "secrets")
	doc["version"], _ = json.Marshal(Version)
	doc["policy"], _ = json.Marshal(v1.Policy)
	doc["credentials"], _ = json.Marshal(credentials)
	return json.Marshal(doc)
}
