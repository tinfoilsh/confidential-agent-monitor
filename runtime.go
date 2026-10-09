package main

import (
	"context"
	"encoding/json"
	"log"

	"github.com/tinfoilsh/monitor/connector"
	"github.com/tinfoilsh/monitor/connector/credential"
	"github.com/tinfoilsh/monitor/connector/mcp"
)

// Compilation fills settings; reconciliation starts runtime resources after persistence.
type connection struct {
	Secrets                      map[string]*credential.Value
	name, protocol, account, key string
	config                       json.RawMessage
	connector                    any
	ctx                          context.Context
	cancel                       context.CancelFunc
	ready, done                  chan struct{}
	incoming                     *connector.Listener
	err                          error // Published by closing done.
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
		c.ready, c.done = make(chan struct{}), make(chan struct{})
		c.incoming = connector.NewListener(c.ctx)
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
			if runner, ok := c.connector.(connector.Runner); ok {
				c.err = runner.Run(c.ctx, &s.Env, c.incoming, func() { close(c.ready) })
			} else {
				server := c.connector.(connector.Server)
				c.err = connector.ServeStreams(c.incoming, func() { close(c.ready) }, func(stream *connector.Stream) { server.Serve(stream, &s.Env) })
			}
			if c.err != nil && c.ctx.Err() == nil {
				log.Printf("connector %s: %v", c.name, c.err)
			}
		}()
	}
}

type connectionStatus struct {
	State   string `json:"state"`
	Error   string `json:"error,omitempty"`
	Details any    `json:"details,omitempty"`
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
		result := connectionStatus{State: "ready"}
		if reporter, ok := c.connector.(*mcp.Server); ok {
			result.Details = reporter.Status()
		}
		return result
	default:
		return connectionStatus{State: "connecting"}
	}
}
