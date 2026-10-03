package main

import (
	"context"
	"encoding/json"
	"log"

	"github.com/tinfoilsh/monitor/connector"
)

// Parsing fills settings; apply allocates runtime resources after persistence.
type connection struct {
	name, protocol, account, key string
	config                       json.RawMessage
	connector                    connector.Connector
	ctx                          context.Context
	cancel                       context.CancelFunc
	ready, done                  chan struct{}
	incoming                     *connector.Listener
	err                          error // Published by closing done.
}

// apply never waits for upstreams. Replacements wait for their predecessors,
// including when a connection is removed and immediately re-added.
func (m *monitor) apply(s *state) {
	if m.running == nil {
		m.running = map[string]*connection{}
	}
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
		c.incoming = connector.NewListener()
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
			stop := context.AfterFunc(c.ctx, func() { c.incoming.Close() })
			defer stop()
			defer c.incoming.Close()
			c.err = connector.Run(c.connector, c.ctx, &s.Env, c.incoming, func() { close(c.ready) })
			if c.err != nil && c.ctx.Err() == nil {
				log.Printf("connector %s: %v", c.name, c.err)
			}
		}()
	}
}

func (c *connection) status() any {
	select {
	case <-c.done:
		if c.err != nil {
			return map[string]string{"state": "error", "error": c.err.Error()}
		}
		return map[string]string{"state": "stopped"}
	default:
	}
	select {
	case <-c.ready:
		if r, ok := c.connector.(connector.Reporter); ok {
			return r.Status()
		}
		return map[string]string{"state": "ready"}
	default:
		return map[string]string{"state": "connecting"}
	}
}

func connectionName(account, key string) string {
	if key != "" {
		return account + "-" + key
	}
	return account
}
