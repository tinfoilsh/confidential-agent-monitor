package main

import (
	"cmp"
	"context"
	"flag"
	"fmt"
	"log"
	"net/netip"
	"os"

	"github.com/open-policy-agent/opa/v1/rego"
	"github.com/tinfoilsh/mcp-sentinel"
	"github.com/tinfoilsh/monitor/connector"
	"github.com/tinfoilsh/monitor/connector/email"
	"github.com/tinfoilsh/monitor/connector/postgres"
	"github.com/tinfoilsh/monitor/connector/redis"
	"github.com/tinfoilsh/monitor/connector/session"
	"github.com/tinfoilsh/monitor/connector/signer"
	"github.com/tinfoilsh/monitor/connector/web"
	"gopkg.in/yaml.v3"
)

const (
	stateMode       = 0o700
	secretMode      = 0o600
	defaultPolicies = "policies"
)

// The kind is also the protocol policies see.
var connectorKinds = map[string]func() connector.Connector{
	"http":      func() connector.Connector { return new(web.HTTP) },
	"ssh":       func() connector.Connector { return new(session.SSH) },
	"cli":       func() connector.Connector { return new(session.CLI) },
	"ssh-agent": func() connector.Connector { return new(signer.SSHAgent) },
	"gpg-agent": func() connector.Connector { return new(signer.GPGAgent) },
	"imap":      func() connector.Connector { return new(email.IMAP) },
	"smtp":      func() connector.Connector { return new(email.SMTP) },
	"postgres":  func() connector.Connector { return new(postgres.Postgres) },
	"redis":     func() connector.Connector { return new(redis.Redis) },
}

type config struct {
	Listen         string                          `yaml:"listen"`
	AuthorizedKeys string                          `yaml:"authorized_keys"`
	Policies       string                          `yaml:"policies"`
	AllowNetworks  []netip.Prefix                  `yaml:"allow_networks"`
	Connections    map[string]map[string]yaml.Node `yaml:"connections"`
}

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
			newConnector, ok := connectorKinds[kind]
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
			r, ok := c.connector.(*web.HTTP)
			if !ok {
				continue
			}
			for secret := range r.Secrets {
				fmt.Printf("export %s=%s\n", secret, web.Placeholder(name, secret))
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
	m.Dialer = connector.NewDialer(cfg.AllowNetworks)
	for _, c := range m.connections {
		if r, ok := c.connector.(connector.Starter); ok {
			r.Start(&m.Env)
		}
	}
	return m.serveSSH(cfg.Listen, cfg.AuthorizedKeys)
}
