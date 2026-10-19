package main

import (
	"context"
	"encoding/json"
	"errors"
	"log"
	"sync"

	"github.com/tinfoilsh/monitor/connector"
	"github.com/tinfoilsh/monitor/connector/credential"
	"github.com/tinfoilsh/monitor/connector/rpc"
)

func connectionName(account, key string) string {
	if key != "" {
		return account + "-" + key
	}
	return account
}

// Compilation fills settings; reconciliation starts runtime resources after persistence.
type connection struct {
	Secrets                      map[string]*credential.Value
	name, protocol, account, key string
	config                       json.RawMessage
	connector                    connector.Server
	ctx                          context.Context
	cancel                       context.CancelFunc
	ready, done                  chan struct{}
	incoming                     chan func(connector.Server, *connector.Env)
	details                      json.RawMessage // Published by closing ready.
	err                          error           // Published by closing done.
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
			server := c.connector
			def, env := connectorKinds[c.protocol], s.Env
			if !def.HostKey {
				env.HostKey = nil
			}
			if m.workers != nil {
				server = &rpc.Proxy{Definition: def, Kind: c.protocol, Config: c.config, Secrets: c.Secrets, Launcher: m.workers}
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
				log.Printf("connector %s: %v", c.name, c.err)
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
