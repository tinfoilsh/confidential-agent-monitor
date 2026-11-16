// Package core routes streams to connectors under the access its caller decides.
package core

import (
	"context"
	"encoding/json"
	"errors"
	"maps"
	"net"
	"net/http"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/tinfoilsh/confidential-agent-monitor/connector"
	"github.com/tinfoilsh/confidential-agent-monitor/core/netx"
)

const (
	Ready           = "ready"
	stateConnecting = "connecting"
	stateError      = "error"
	openTimeout     = time.Minute
)

var errNoTarget = errors.New("the Perimeter does not forward this target")

// Access decides for the identity ctx carries. A Table never holds its lock while calling it.
type Access interface {
	// Reaches reports whether the identity may address connection; others are never selected.
	Reaches(ctx context.Context, connection string) bool
	// Admit decides a stream before it is accepted, and may wait.
	Admit(ctx context.Context, r Request) (Watch, error)
}

// A Watch gates an accepted stream's operations until ctx ends and calls end to revoke it; false refuses the stream.
type Watch func(ctx context.Context, end func()) (connector.Gate, bool)

type Request struct {
	Connection string
	// Host is the host the stream asked for, which may be the connection's own name.
	Host       string
	Port       uint32
	PerMessage bool
	// Valid reports that the connection still serves the setup this stream selected.
	Valid func() bool
}

type Status struct {
	State   string          `json:"state"`
	Error   string          `json:"error,omitempty"`
	Details json.RawMessage `json:"details,omitempty"`
}

// Connection is a copy of one installed connection's state.
type Connection struct {
	Name, Protocol string
	Status
	Prepared *connector.Prepared
	Secrets  map[string]connector.Secret
}

type connection struct {
	name, protocol string
	prepared       *connector.Prepared
	secrets        map[string]connector.Secret
	env            connector.Env
	handler        connector.Handler
	setup          context.Context // Logical stream authority, not resource lifetime.
	cancel         context.CancelFunc
	active         sync.WaitGroup // Final retirement only; a restaged setup does not join uses.
	ready          bool
	err            error
	details        json.RawMessage
}

// Table holds the installed connections. Its caller serializes Stage, Remove, Start and Close.
type Table struct {
	kinds           map[string]connector.Kind
	access          Access
	mu              sync.Mutex
	connections     map[string]*connection
	staged, retired []*connection
}

func New(kinds map[string]connector.Kind, access Access) *Table {
	return &Table{kinds: kinds, access: access, connections: map[string]*connection{}}
}

// status runs under mu. Process availability is independent
// of successful setup delivery; it is queried directly without a watcher.
func (c *connection) status() Status {
	if c.err != nil {
		return Status{State: stateError, Error: c.err.Error()}
	}
	if !c.ready {
		return Status{State: stateConnecting}
	}
	if runtime, ok := c.handler.(connector.Readier); ok {
		if err := runtime.Ready(); err != nil {
			return Status{State: stateError, Error: err.Error()}
		}
	}
	return Status{State: Ready, Details: c.details}
}

func (c *connection) close() {
	c.active.Wait()
	connector.Close(c.handler)
}

// usable runs under mu: c is still installed with this setup and ready.
func (t *Table) usable(c *connection, prepared *connector.Prepared) bool {
	return t.connections[c.name] == c && c.prepared == prepared && c.status().State == Ready
}

func (t *Table) Connections() map[string]Connection {
	t.mu.Lock()
	defer t.mu.Unlock()
	out := make(map[string]Connection, len(t.connections))
	for name, c := range t.connections {
		out[name] = Connection{Name: name, Protocol: c.protocol, Status: c.status(), Prepared: c.prepared, Secrets: c.secrets}
	}
	return out
}

// Stage sets the setup Start opens for name; a changed setup ends the installed one's streams now.
func (t *Table) Stage(name, protocol string, prepared *connector.Prepared, secrets map[string]connector.Secret, env connector.Env) {
	t.mu.Lock()
	defer t.mu.Unlock()
	c := t.connections[name]
	if c == nil {
		c = &connection{name: name}
		t.connections[name] = c
	}
	if c.prepared != prepared {
		if c.cancel != nil {
			c.cancel()
		}
		c.setup, c.cancel = context.WithCancel(context.Background())
	}
	c.protocol, c.prepared, c.secrets = protocol, prepared, secrets
	// Admission requires successful delivery.
	c.env, c.ready, c.err = env, false, nil
	if !t.kinds[protocol].UsesHostKey {
		c.env.HostKey = nil
	}
	t.staged = append(t.staged, c)
}

// Remove ends name's streams now; Start closes its connector once they have returned.
func (t *Table) Remove(name string) {
	t.mu.Lock()
	defer t.mu.Unlock()
	if c := t.connections[name]; c != nil {
		c.cancel()
		t.retired = append(t.retired, c)
		delete(t.connections, name)
	}
}

// Start closes what Remove retired and opens what Stage staged, without the lock during connector I/O.
func (t *Table) Start() {
	t.mu.Lock()
	staged, retired := t.staged, t.retired
	t.staged, t.retired = nil, nil
	t.mu.Unlock()
	for _, c := range retired {
		c.close()
	}
	ctx, cancel := context.WithTimeout(context.Background(), openTimeout)
	defer cancel()
	for _, c := range staged {
		t.mu.Lock()
		old, env := c.handler, c.env
		c.handler = nil
		t.mu.Unlock()
		connector.Close(old)
		h, err := t.kinds[c.protocol].Open(ctx, *c.prepared, c.secrets, &env)
		t.mu.Lock()
		c.handler, c.err, c.ready = h, err, err == nil
		if d, ok := h.(connector.Detailer); ok && err == nil {
			c.details = d.Details()
		}
		t.mu.Unlock()
	}
}

func (t *Table) Close() {
	t.mu.Lock()
	retired := slices.Collect(maps.Values(t.connections))
	for _, c := range retired {
		c.cancel()
	}
	clear(t.connections)
	t.mu.Unlock()
	for _, c := range retired {
		c.close()
	}
}

// Control pins name's ready connector until release; setup ends when the connector's setup does.
func (t *Table) Control(name string) (handler http.Handler, setup context.Context, release func(), ok bool) {
	t.mu.Lock()
	defer t.mu.Unlock()
	c := t.connections[name]
	if c == nil || !t.usable(c, c.prepared) {
		return nil, nil, nil, false
	}
	c.active.Add(1)
	return connector.Control(c.handler), c.setup, c.active.Done, true
}

// candidate is a ready connection as Open found it, so a later restage shows as a change.
type candidate struct {
	c          *connection
	prepared   *connector.Prepared
	setup      context.Context
	perMessage bool
}

// Open selects the ready connection claiming host and port among those the identity reaches, has
// Access admit the stream, accepts it and serves it until it ends. An error before accept refuses it.
func (t *Table) Open(ctx context.Context, host string, port uint32, accept func() (net.Conn, error)) error {
	t.mu.Lock()
	var ready []candidate
	for _, c := range t.connections {
		if c.status().State == Ready {
			ready = append(ready, candidate{c, c.prepared, c.setup, t.kinds[c.protocol].PerMessage})
		}
	}
	t.mu.Unlock()
	ready = slices.DeleteFunc(ready, func(r candidate) bool { return !t.access.Reaches(ctx, r.c.name) })
	selected, explicit, ok := selectTarget(host, port, ready)
	if !ok {
		return errNoTarget
	}
	c, prepared, setup := selected.c, selected.prepared, selected.setup
	usable := func() bool {
		t.mu.Lock()
		defer t.mu.Unlock()
		return t.usable(c, prepared)
	}
	// The identity admits under the setup's lifetime, not the caller's.
	admitting, done := netx.Bind(context.WithoutCancel(ctx), setup)
	watch, err := t.access.Admit(admitting, Request{Connection: c.name, Host: host, Port: port, PerMessage: selected.perMessage, Valid: usable})
	done()
	if err != nil {
		return err
	}
	conn, err := accept()
	if err != nil {
		return err
	}
	s := connector.NewStream(setup, conn)
	s.Name, s.Port = c.name, port
	if !explicit {
		s.Host = host
	}
	defer s.Close()
	context.AfterFunc(ctx, func() { s.Close() })
	t.mu.Lock()
	pinned, handler := t.usable(c, prepared), c.handler
	if pinned {
		c.active.Add(1)
	}
	t.mu.Unlock()
	if !pinned {
		return nil
	}
	defer c.active.Done()
	gate, ok := watch(s.Context, func() { s.Close() })
	if !ok {
		return nil
	}
	s.Gate = gate
	// A worker proxy relays the bytes into the concrete connector and sends its
	// Gate calls back to this stream.
	handler.ServeStream(s)
	return nil
}

// selectTarget resolves only supplied candidates, so inaccessible connections cannot tie.
func selectTarget(host string, port uint32, candidates []candidate) (selected candidate, explicit, ok bool) {
	if name, named := strings.CutSuffix(host, connector.Domain); named {
		i := slices.IndexFunc(candidates, func(r candidate) bool { return r.c.name == name })
		if i < 0 {
			return candidate{}, true, false
		}
		return candidates[i], true, true
	}
	best, tied := -1, false
	for _, r := range candidates {
		if r.prepared.Claim == nil {
			continue
		}
		score := r.prepared.Claim(host, port)
		if score < 0 {
			continue
		}
		if score > best {
			selected, best, tied = r, score, false
		} else if score == best {
			tied = true
		}
	}
	return selected, false, best >= 0 && !tied
}
