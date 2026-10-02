package main

import (
	"context"

	"github.com/tinfoilsh/monitor/connector"
)

type credentialKey struct{ account, name string }

type connection struct {
	name, protocol, account string
	spec                    string
	credentialRefs          []string
	connector               connector.Connector
	ctx                     context.Context
	cancel                  context.CancelFunc
	ready, done             chan struct{}
}

// Owner edits to a referenced secret replace its connectors just like other config edits.
func (c *connection) usesChangedCredential(changed map[credentialKey]bool) bool {
	for _, name := range c.credentialRefs {
		if changed[credentialKey{c.account, name}] {
			return true
		}
	}
	return false
}

// apply never waits for upstreams. Each replacement waits for its predecessor
// to stop, including when a connection is removed and immediately re-added.
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
		m.running[name] = c
		go func() {
			defer close(c.done)
			if previous != nil {
				<-previous.done
			}
			if c.ctx.Err() != nil {
				return
			}
			if r, ok := c.connector.(connector.Starter); ok {
				env := s.Env
				env.Credentials = s.credentials[c.account]
				r.Start(c.ctx, &env)
			}
			close(c.ready)
			<-c.ctx.Done()
			if r, ok := c.connector.(connector.Stopper); ok {
				r.Stop()
			}
		}()
	}
}

func (c *connection) status() any {
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
