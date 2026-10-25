// Package supervisor runs one connector server per name, starting each replacement after its predecessor stops.
package supervisor

import (
	"context"
	"encoding/json"
	"errors"
	"log"
	"sync"

	"github.com/tinfoilsh/monitor/connector"
)

// A Conn runs one server; dispatched work runs inside its serve loop.
type Conn struct {
	ctx         context.Context
	cancel      context.CancelFunc
	ready, done chan struct{}
	incoming    chan func(connector.Server, *connector.Env)
	details     json.RawMessage // Published by closing ready.
	err         error           // Published by closing done.
}

func (c *Conn) Context() context.Context { return c.ctx }

func (c *Conn) Done() <-chan struct{} { return c.done }

func (c *Conn) Dispatch(ctx context.Context, run func(connector.Server, *connector.Env)) error {
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

// Reconcile never waits for upstreams. Replacements wait for their predecessors,
// including when a connection is removed and immediately re-added.
// start supplies each new Conn's server and environment; the caller serializes calls.
func Reconcile(running, next map[string]*Conn, start func(name string) (connector.Server, connector.Env)) {
	for name, c := range running {
		if next[name] != c {
			c.cancel()
			select {
			case <-c.done:
				delete(running, name)
			default:
			}
		}
	}
	for name, c := range next {
		previous := running[name]
		if previous == c {
			continue
		}
		server, env := start(name)
		c.ctx, c.cancel = context.WithCancel(context.Background())
		c.ready, c.done, c.incoming = make(chan struct{}), make(chan struct{}), make(chan func(connector.Server, *connector.Env))
		running[name] = c
		go func() {
			defer close(c.done)
			defer c.cancel()
			if previous != nil {
				<-previous.done
			}
			if c.ctx.Err() != nil {
				return
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
				log.Printf("connector %s: %v", name, c.err)
			}
		}()
	}
}

type Status struct {
	State   string          `json:"state"`
	Error   string          `json:"error,omitempty"`
	Details json.RawMessage `json:"details,omitempty"`
}

func (c *Conn) Status() Status {
	select {
	case <-c.done:
		if c.err != nil {
			return Status{State: "error", Error: c.err.Error()}
		}
		return Status{State: "stopped"}
	default:
	}
	select {
	case <-c.ready:
		return Status{State: "ready", Details: c.details}
	default:
		return Status{State: "connecting"}
	}
}
