// Command monitor forwards streams through connectors that terminate each protocol,
// ask the policy before each operation, and attach stored credentials.
package main

import (
	"cmp"
	"context"
	"flag"
	"fmt"
	"log"
	"os"

	"github.com/open-policy-agent/opa/v1/rego"
	"github.com/tinfoilsh/mcp-sentinel"
	"github.com/tinfoilsh/monitor/connector"
	"gopkg.in/yaml.v3"
)

const (
	stateMode       = 0o700
	secretMode      = 0o600
	defaultPolicies = "policies"
)

type config struct {
	Listen         string                          `yaml:"listen"`
	AuthorizedKeys string                          `yaml:"authorized_keys"`
	Policies       string                          `yaml:"policies"`
	Connections    map[string]map[string]yaml.Node `yaml:"connections"`
}

// connection selects exactly one connector.
type connection struct {
	name, protocol string
	connector      connector.Connector
}

type monitor struct {
	connections map[string]*connection
	policy      *sentinel.Policy
	connector.Env
}

func main() {
	configPath := flag.String("c", "monitor.yml", "config file")
	stateDir := flag.String("state", "state", "directory holding the host key and CA")
	flag.Parse()
	if err := run(*configPath, *stateDir, flag.Args()); err != nil {
		log.Fatal(err)
	}
}

func run(configPath, stateDir string, args []string) error {
	raw, err := os.ReadFile(configPath)
	if err != nil {
		return err
	}
	var cfg config
	if err := yaml.Unmarshal(raw, &cfg); err != nil {
		return fmt.Errorf("%s: %w", configPath, err)
	}
	m := &monitor{connections: map[string]*connection{}}
	for name, kinds := range cfg.Connections {
		if len(kinds) != 1 {
			return fmt.Errorf("%s: connection %s must have one kind", configPath, name)
		}
		for kind, node := range kinds {
			newConnector, ok := connector.Kinds[kind]
			if !ok {
				return fmt.Errorf("%s: connection %s has unknown kind %s", configPath, name, kind)
			}
			c := &connection{name: name, protocol: kind, connector: newConnector()}
			if err := node.Decode(c.connector); err != nil {
				return fmt.Errorf("%s: %w", configPath, err)
			}
			m.connections[name] = c
		}
	}
	if len(args) == 1 && args[0] == "env" {
		for name, c := range m.connections {
			r, ok := c.connector.(*connector.HTTP)
			if !ok {
				continue
			}
			for secret := range r.Secrets {
				fmt.Printf("export %s=%s\n", secret, connector.Placeholder(name, secret))
			}
		}
		return nil
	}
	policies := rego.Load([]string{cmp.Or(cfg.Policies, defaultPolicies)}, nil)
	if m.policy, err = sentinel.NewPolicy(context.Background(), policies); err != nil {
		return err
	}
	if err := os.MkdirAll(stateDir, stateMode); err != nil {
		return err
	}
	if m.TLS, err = loadCA(stateDir); err != nil {
		return err
	}
	if m.HostKey, err = loadHostKey(stateDir); err != nil {
		return err
	}
	for _, c := range m.connections {
		if r, ok := c.connector.(connector.Starter); ok {
			r.Start(&m.Env)
		}
	}
	return m.serveSSH(cfg.Listen, cfg.AuthorizedKeys)
}
