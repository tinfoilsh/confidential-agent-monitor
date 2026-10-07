package main

import (
	"encoding/json"
	"fmt"
	"net/netip"
	"slices"
	"strings"

	"github.com/tinfoilsh/monitor/connector"
)

const mcpNameChars = "abcdefghijklmnopqrstuvwxyz0123456789-"

var (
	audiences = []string{"me", "team", "anyone"}
	trusts    = []string{"untrusted", "trusted"}
	levels    = []string{"off", "read", "ask", "allow"}
)

type identity struct {
	Key      string            `json:"key"`
	Accounts map[string]access `json:"accounts"`
	Rules    []rule            `json:"rules,omitempty"`
	Messages *messageAccess    `json:"messages,omitempty"`
	// Profile admits every request unchanged and unlabeled, recording it, to learn what a client sends.
	Profile bool `json:"profile,omitempty"`
}

type access struct {
	Level   string            `json:"level"`
	Actions map[string]string `json:"actions,omitempty"`
}

// A rule waives gaps for one recognized operation under the definition the owner approved.
type rule struct {
	Account    string         `json:"account"`
	Action     string         `json:"action"`
	Operation  string         `json:"operation,omitempty"`
	Definition string         `json:"definition,omitempty"`
	Scope      map[string]any `json:"scope"`
	Waives     []string       `json:"waives"`
}

// policyOptions contains settings used only by policy, never connection setup.
type policyOptions struct {
	Private []string `json:"private,omitempty"`
	Address string   `json:"address,omitempty"`
	Origin  string   `json:"origin,omitempty"`
}

type account struct {
	Preset        string                    `json:"preset"`
	PolicyOptions policyOptions             `json:"policy_options"`
	Contents      string                    `json:"contents"`
	Strangers     bool                      `json:"strangers"`
	Sends         string                    `json:"sends"`
	Connections   map[string]map[string]any `json:"connections,omitempty"`
}

// Lattice switches control enforcement. Labels keep recording both axes.
type latticeOptions struct {
	Confidentiality bool `json:"confidentiality"`
	Integrity       bool `json:"integrity"`
}

type config struct {
	Lattices      latticeOptions      `json:"lattices"`
	AllowNetworks []netip.Prefix      `json:"allow_networks"`
	Accounts      map[string]account  `json:"accounts"`
	Identities    map[string]identity `json:"identities"`
	Policies      map[string]string   `json:"policies"`
	Data          map[string]any      `json:"data"`

	// Presets are the owner's, in the shipped file format; each replaces the shipped preset of its name.
	Presets  map[string]map[string]any `json:"presets,omitempty"`
	resolved map[string]preset
}

// parse decodes the owner's config without starting anything.
func parse(raw []byte) (*config, map[string]*connection, error) {
	cfg := config{Lattices: latticeOptions{Confidentiality: true}}
	if err := connector.DecodeNumbers(raw, &cfg); err != nil {
		return nil, nil, err
	}
	for _, reserved := range []string{"definitions", "presets", "lattices"} {
		if _, ok := cfg.Data[reserved]; ok {
			return nil, nil, fmt.Errorf("data.%s is reserved for the monitor", reserved)
		}
	}
	resolved, err := withOwned(cfg.Presets)
	if err != nil {
		return nil, nil, err
	}
	cfg.resolved = resolved
	connections := map[string]*connection{}
	for acct, a := range cfg.Accounts {
		if _, ok := resolved[a.Preset]; !ok {
			return nil, nil, fmt.Errorf("account %s has unknown preset %s", acct, a.Preset)
		}
		if !slices.Contains(audiences, a.Contents) || !slices.Contains(audiences, a.Sends) {
			return nil, nil, fmt.Errorf("account %s: contents and sends must be one of %v", acct, audiences)
		}
		for key, kinds := range a.Connections {
			name := connectionName(acct, key)
			if name == "messages" || name == "mcp" || name == "agent" {
				return nil, nil, fmt.Errorf("connection name %s is reserved for the monitor", name)
			}
			if connections[name] != nil {
				return nil, nil, fmt.Errorf("connection name %s is taken", name)
			}
			if len(kinds) != 1 {
				return nil, nil, fmt.Errorf("connection %s must have one kind", name)
			}
			for kind, spec := range kinds {
				// The gateway names tools name__tool, so the first separator must end the connection name.
				if kind == "mcp" && strings.Trim(strings.ToLower(name), mcpNameChars) != "" {
					return nil, nil, fmt.Errorf("MCP connection name %s may use only letters, digits and -", name)
				}
				newConnector, ok := connectorKinds[kind]
				if !ok {
					return nil, nil, fmt.Errorf("connection %s has unknown kind %s", name, kind)
				}
				raw, _ := json.Marshal(spec)
				instance := newConnector()
				if err := connector.Decode(raw, instance); err != nil {
					return nil, nil, fmt.Errorf("connection %s: %w", name, err)
				}
				connections[name] = &connection{name: name, protocol: kind, account: acct, key: key,
					config: raw, connector: instance}
			}
		}
	}
	for name, id := range cfg.Identities {
		if err := validateMessageAccess(name, id.Messages, cfg.Identities); err != nil {
			return nil, nil, err
		}
		for acct, a := range id.Accounts {
			if _, ok := cfg.Accounts[acct]; !ok || !slices.Contains(levels, a.Level) {
				return nil, nil, fmt.Errorf("identity %s: account %s must exist and have a level in %v", name, acct, levels)
			}
			for action, level := range a.Actions {
				if level == "read" || !slices.Contains(levels, level) {
					return nil, nil, fmt.Errorf("identity %s: action %s must be off, ask or allow", name, action)
				}
			}
		}
	}
	return &cfg, connections, nil
}
