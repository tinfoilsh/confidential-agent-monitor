package monitor

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"slices"

	"github.com/tinfoilsh/monitor/connector"
	"github.com/tinfoilsh/monitor/connector/credential"
	"github.com/tinfoilsh/monitor/internal/config"
	"github.com/tinfoilsh/monitor/internal/store"
	"github.com/tinfoilsh/monitor/internal/supervisor"
	"github.com/tinfoilsh/monitor/internal/worker"
)

// build validates without starting anything or mutating live credentials.
func (m *monitor) build(ctx context.Context, document *store.Document, env connector.Env, old *state) (*state, error) {
	snapshot, specs, err := config.Compile(ctx, document.Policy)
	if err != nil {
		return nil, err
	}
	s := &state{Snapshot: snapshot, connections: map[string]*connection{}, Env: env}
	s.Dialer = connector.NewDialer(snapshot.Config.AllowNetworks)
	secrets := document.Secrets.Clone()
	for name, spec := range specs {
		definition, ok := m.kinds[spec.Protocol]
		if !ok {
			return nil, fmt.Errorf("connection %s has unknown kind %s", name, spec.Protocol)
		}
		server := definition.NewConfig()
		if err := connector.Decode(spec.Config, server); err != nil {
			return nil, fmt.Errorf("connection %s: %w", name, err)
		}
		c := &connection{ConnectionSpec: spec, Server: server}
		if owner, ok := server.(connector.SecretHolder); ok {
			c.Secrets = owner.SecretValues()
			for _, value := range c.Secrets {
				if value != nil && value.Raw() != nil {
					return nil, errors.New("set credentials through account settings")
				}
			}
			preset := snapshot.Config.Resolved[snapshot.Config.Accounts[c.Account].Preset]
			fields, err := preset.Catalog.CredentialFields()
			if err != nil {
				return nil, err
			}
			for _, paths := range fields {
				for _, path := range paths {
					if path.Connection == c.Key && path.Protocol == c.Protocol && c.Secrets[path.Secret] == nil {
						c.Secrets[path.Secret] = new(credential.Value)
					}
				}
			}
			for name, value := range c.Secrets {
				if value == nil {
					c.Secrets[name] = new(credential.Value)
				}
			}
		}
		s.connections[name] = c
	}
	for id, raw := range secrets {
		c := s.connections[config.ConnectionName(id.Account, id.Connection)]
		if c == nil || c.Account != id.Account || c.Key != id.Connection || c.Secrets == nil {
			delete(secrets, id)
			continue
		}
		value := new(credential.Value)
		if err := value.UnmarshalJSON(raw); err != nil {
			return nil, fmt.Errorf("credential %v: %w", id, err)
		}
		c.Secrets[id.Name] = value
	}
	client := s.Client()
	for name, c := range s.connections {
		if old != nil && slices.Equal(old.Config.AllowNetworks, snapshot.Config.AllowNetworks) {
			previous := old.connections[name]
			if previous != nil && previous.Account == c.Account && previous.Protocol == c.Protocol && bytes.Equal(previous.Config, c.Config) &&
				maps.EqualFunc(m.store.Doc.Secrets.Connection(c.Account, c.Key), secrets.Connection(c.Account, c.Key), slices.Equal[json.RawMessage]) {
				s.connections[name] = previous
				continue
			}
		}
		for name, value := range c.Secrets {
			id := store.SecretID{Account: c.Account, Connection: c.Key, Name: name}
			value.Placeholder = placeholder(document.Keys, id)
			value.Client = client
			value.Save = func(ctx context.Context, before, after json.RawMessage) error {
				return m.replaceValue(ctx, c, id, before, after)
			}
		}
	}
	document.Secrets = secrets
	return s, nil
}

// A connection binds a compiled specification to credentials and runtime resources.
// Reconciliation starts its server only after the candidate has been persisted.
type connection struct {
	config.ConnectionSpec
	Secrets map[string]*credential.Value
	Server  connector.Server
	supervisor.Conn
}

func (m *monitor) reconcile(s *state) {
	next := make(map[string]*supervisor.Conn, len(s.connections))
	for name, c := range s.connections {
		next[name] = &c.Conn
	}
	supervisor.Reconcile(m.running, next, func(name string) (connector.Server, connector.Env) {
		c := s.connections[name]
		def, env := m.kinds[c.Protocol], s.Env
		if !def.HostKey {
			env.HostKey = nil
		}
		if m.workers != nil {
			return &worker.Proxy{Definition: def, Kind: c.Protocol, Config: c.Config, Secrets: c.Secrets, Launcher: m.workers}, env
		}
		return c.Server, env
	})
}
