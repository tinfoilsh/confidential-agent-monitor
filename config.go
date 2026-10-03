package main

import (
	"encoding/json"
	"fmt"
	"io/fs"
	"net/netip"
	"slices"

	"github.com/tinfoilsh/monitor/connector"
)

var (
	audiences = []string{"me", "team", "anyone"}
	levels    = []string{"off", "read", "ask", "allow"}
)

type identity struct {
	Key      string            `json:"key"`
	Accounts map[string]access `json:"accounts"`
	Rules    []rule            `json:"rules,omitempty"`
}

type access struct {
	Level   string            `json:"level"`
	Actions map[string]string `json:"actions,omitempty"`
}

type rule struct {
	Account string         `json:"account"`
	Action  string         `json:"action"`
	Scope   map[string]any `json:"scope"`
	Waives  []string       `json:"waives"`
}

// policyOptions contains settings used only by policy, never connection setup.
type policyOptions struct {
	Private []string `json:"private,omitempty"`
	Address string   `json:"address,omitempty"`
}

type account struct {
	Template      string                    `json:"template"`
	PolicyOptions policyOptions             `json:"policy_options"`
	Contents      string                    `json:"contents"`
	Strangers     bool                      `json:"strangers"`
	Sends         string                    `json:"sends"`
	Connections   map[string]map[string]any `json:"connections,omitempty"`
}

type config struct {
	AllowNetworks []netip.Prefix      `json:"allow_networks"`
	Accounts      map[string]account  `json:"accounts"`
	Identities    map[string]identity `json:"identities"`
	Policies      map[string]string   `json:"policies"`
	Data          map[string]any      `json:"data"`
}

// parse decodes the owner's config without starting anything.
func parse(raw []byte) (*config, map[string]*connection, error) {
	var cfg config
	if err := connector.Decode(raw, &cfg); err != nil {
		return nil, nil, err
	}
	connections := map[string]*connection{}
	for acct, a := range cfg.Accounts {
		if _, err := fs.Stat(templates, templateDir+"/"+a.Template+".rego"); err != nil {
			return nil, nil, fmt.Errorf("account %s has unknown template %s", acct, a.Template)
		}
		if !slices.Contains(audiences, a.Contents) || !slices.Contains(audiences, a.Sends) {
			return nil, nil, fmt.Errorf("account %s: contents and sends must be one of %v", acct, audiences)
		}
		for key, kinds := range a.Connections {
			name := connectionName(acct, key)
			if connections[name] != nil {
				return nil, nil, fmt.Errorf("connection name %s is taken", name)
			}
			if len(kinds) != 1 {
				return nil, nil, fmt.Errorf("connection %s must have one kind", name)
			}
			for kind, spec := range kinds {
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
