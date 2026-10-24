package monitor

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"maps"
	"slices"
	"sync"

	"github.com/tinfoilsh/monitor/connector"
	"github.com/tinfoilsh/monitor/connector/credential"
	"github.com/tinfoilsh/monitor/facts"
	"github.com/tinfoilsh/monitor/internal/config"
	"github.com/tinfoilsh/monitor/internal/store"
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
		if err := facts.DecodeNumbers(spec.Config, server); err != nil {
			return nil, fmt.Errorf("connection %s: %w", name, err)
		}
		c := &connection{ConnectionSpec: spec, Server: server}
		if owner, ok := server.(interface {
			SecretValues() map[string]*credential.Value
		}); ok {
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
	for id, raw := range secrets.All() {
		c := s.connections[config.ConnectionName(id[0], id[1])]
		if c == nil || c.Account != id[0] || c.Key != id[1] || c.Secrets == nil {
			secrets.Set(id, nil)
			continue
		}
		value := new(credential.Value)
		if err := value.UnmarshalJSON(raw); err != nil {
			return nil, fmt.Errorf("credential %v: %w", id, err)
		}
		c.Secrets[id[2]] = value
	}
	client := s.Client()
	for name, c := range s.connections {
		if old != nil && slices.Equal(old.Config.AllowNetworks, snapshot.Config.AllowNetworks) {
			previous := old.connections[name]
			if previous != nil && previous.Account == c.Account && previous.Protocol == c.Protocol && bytes.Equal(previous.Config, c.Config) &&
				maps.EqualFunc(m.store.Doc.Secrets[c.Account][c.Key], secrets[c.Account][c.Key], slices.Equal[json.RawMessage]) {
				s.connections[name] = previous
				continue
			}
		}
		for name, value := range c.Secrets {
			id := store.SecretID{c.Account, c.Key, name}
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
	Secrets     map[string]*credential.Value
	Server      connector.Server
	ctx         context.Context
	cancel      context.CancelFunc
	ready, done chan struct{}
	incoming    chan func(connector.Server, *connector.Env)
	details     json.RawMessage // Published by closing ready.
	err         error           // Published by closing done.
}

func (c *connection) dispatch(ctx context.Context, run func(connector.Server, *connector.Env)) error {
	finished := make(chan struct{})
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-c.ctx.Done():
		return errors.New("connector stopped")
	case c.incoming <- func(server connector.Server, env *connector.Env) { defer close(finished); run(server, env) }:
	}
	// Once admitted, the caller must wait until the operation releases its resources.
	<-finished
	return nil
}

// reconcile never waits for upstreams. Replacements wait for their predecessors,
// including when a connection is removed and immediately re-added.
func (m *monitor) reconcile(s *state) {
	for name, c := range m.running {
		if s.connections[name] != c {
			c.cancel()
			select {
			case <-c.done:
				delete(m.running, name)
			default:
			}
		}
	}
	for name, c := range s.connections {
		previous := m.running[name]
		if previous == c {
			continue
		}
		c.ctx, c.cancel = context.WithCancel(context.Background())
		c.ready, c.done, c.incoming = make(chan struct{}), make(chan struct{}), make(chan func(connector.Server, *connector.Env))
		m.running[name] = c
		go func() {
			defer close(c.done)
			defer c.cancel()
			if previous != nil {
				<-previous.done
			}
			if c.ctx.Err() != nil {
				return
			}
			server := c.Server
			def, env := m.kinds[c.Protocol], s.Env
			if !def.HostKey {
				env.HostKey = nil
			}
			if m.workers != nil {
				server = &worker.Proxy{Definition: def, Kind: c.Protocol, Config: c.Config, Secrets: c.Secrets, Launcher: m.workers}
			}
			serve := func(ctx context.Context) {
				var active sync.WaitGroup
				defer active.Wait()
				defer c.cancel()
				if d, ok := server.(connector.Detailer); ok {
					c.details = d.Details()
				}
				close(c.ready)
				for {
					select {
					case run := <-c.incoming:
						active.Go(func() { run(server, &env) })
					case <-ctx.Done():
						return
					}
				}
			}
			if runner, ok := server.(connector.Runner); ok {
				if err := runner.Run(c.ctx, &env, serve); err != nil {
					c.err = err
				}
			} else {
				serve(c.ctx)
			}
			if c.err != nil && !errors.Is(c.err, context.Canceled) {
				log.Printf("connector %s: %v", c.Name, c.err)
			}
		}()
	}
}

type connectionStatus struct {
	State   string          `json:"state"`
	Error   string          `json:"error,omitempty"`
	Details json.RawMessage `json:"details,omitempty"`
}

func (c *connection) status() connectionStatus {
	select {
	case <-c.done:
		if c.err != nil {
			return connectionStatus{State: "error", Error: c.err.Error()}
		}
		return connectionStatus{State: "stopped"}
	default:
	}
	select {
	case <-c.ready:
		return connectionStatus{State: "ready", Details: c.details}
	default:
		return connectionStatus{State: "connecting"}
	}
}
