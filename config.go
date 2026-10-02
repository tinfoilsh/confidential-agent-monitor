package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io/fs"
	"maps"
	"net/netip"
	"slices"
	"strings"

	"github.com/tinfoilsh/monitor/connector/credential"
)

const secretRef = "$secret"

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

type account struct {
	Template    string                    `json:"template"`
	Fields      map[string]any            `json:"fields,omitempty"`
	Contents    string                    `json:"contents"`
	Strangers   bool                      `json:"strangers"`
	Sends       string                    `json:"sends"`
	Connections map[string]map[string]any `json:"connections,omitempty"`
}

type config struct {
	AllowNetworks []netip.Prefix      `json:"allow_networks"`
	Accounts      map[string]account  `json:"accounts"`
	Identities    map[string]identity `json:"identities"`
	Policies      map[string]string   `json:"policies"`
	Data          map[string]any      `json:"data"`
}

// parse decodes the owner's config without starting anything.
func parse(raw []byte, secrets map[string]map[string]any) (*config, map[string]*connection, error) {
	var cfg config
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&cfg); err != nil {
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
			name := acct
			if key != "" {
				name += "-" + key
			}
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
				c := &connection{name: name, protocol: kind, account: acct, connector: newConnector()}
				var paths []string
				if fields, ok := c.connector.(credential.Fields); ok {
					paths = fields.CredentialFields()
				}
				resolved, err := resolve(spec, secrets[acct], paths, &c.credentialRefs)
				if err != nil {
					return nil, nil, fmt.Errorf("connection %s: %w", name, err)
				}
				raw, err := json.Marshal(resolved)
				if err != nil {
					return nil, nil, err
				}
				if err := json.Unmarshal(raw, c.connector); err != nil {
					return nil, nil, fmt.Errorf("connection %s: %w", name, err)
				}
				raw, err = json.Marshal([]any{kind, resolved, cfg.AllowNetworks})
				if err != nil {
					return nil, nil, err
				}
				c.spec = string(raw)
				c.ctx, c.cancel = context.WithCancel(context.Background())
				c.ready, c.done = make(chan struct{}), make(chan struct{})
				connections[name] = c
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

// resolve expands ordinary secrets and retains credential references for runtime lookup.
// paths lists the credential fields still reachable below v.
func resolve(v any, secrets map[string]any, paths []string, refs *[]string) (any, error) {
	childPaths := func(key string) []string {
		var child []string
		for _, path := range paths {
			head, tail, _ := strings.Cut(path, "/")
			if head == key || head == "*" {
				child = append(child, tail)
			}
		}
		return child
	}
	var err error
	switch v := v.(type) {
	case map[string]any:
		if key, ok := v[secretRef].(string); ok && len(v) == 1 {
			if secret, ok := secrets[key]; ok {
				if slices.Contains(paths, "") {
					*refs = append(*refs, key)
					return v, nil
				}
				if len(paths) > 0 {
					// A secret may hold a whole config object or credential map.
					// Exclude it while expanding to reject recursive references.
					remaining := maps.Clone(secrets)
					delete(remaining, key)
					return resolve(secret, remaining, paths, refs)
				}
				return secret, nil
			}
			return nil, fmt.Errorf("secret %s is not set", key)
		}
		out := make(map[string]any, len(v))
		for k, e := range v {
			if out[k], err = resolve(e, secrets, childPaths(k), refs); err != nil {
				return nil, err
			}
		}
		return out, nil
	case []any:
		out := make([]any, len(v))
		for i, e := range v {
			if out[i], err = resolve(e, secrets, childPaths("*"), refs); err != nil {
				return nil, err
			}
		}
		return out, nil
	}
	return v, nil
}
