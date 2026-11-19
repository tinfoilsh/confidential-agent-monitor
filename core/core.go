package core

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"net"
	"net/http"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/tinfoilsh/confidential-agent-monitor/core/connector"
	"github.com/tinfoilsh/confidential-agent-monitor/core/facts"
	"github.com/tinfoilsh/confidential-agent-monitor/core/transport/netx"
)

const (
	Ready           = "ready"
	stateConnecting = "connecting"
	stateError      = "error"
)

var (
	errNoTarget = errors.New("no connection serves this target")
	errNoServe  = errors.New("the connector serves no streams")

	ErrAmbiguous = errors.New("ambiguous target")
)

type Watch = func(ctx context.Context, end func()) (connector.Gate, bool)

type Open = func(context.Context) (connector.Instance, error)

type Request struct {
	Connection string
	Target     connector.Target
	Valid      func() bool
}

type Candidate struct {
	Name  string
	Claim func(connector.Target) int
}

type Status struct {
	State   string          `json:"state"`
	Error   string          `json:"error,omitempty"`
	Details json.RawMessage `json:"details,omitempty"`
}

type setup struct {
	network string
	claim   func(connector.Target) int
	open    Open
	ctx     context.Context
	cancel  context.CancelFunc
}

type connection struct {
	name      string
	setup     *setup
	connector connector.Instance
	active    sync.WaitGroup
	ready     bool
	err       error
}

type Table struct {
	reaches      func(context.Context, facts.Principal, string) bool
	admit        func(context.Context, facts.Principal, Request) (Watch, error)
	selectTarget func(connector.Target, []Candidate) (string, bool, error)
	openTimeout  time.Duration
	mu           sync.Mutex
	connections  map[string]*connection
	staged       []*connection
	retired      []*connection
}

func New(reaches func(ctx context.Context, p facts.Principal, connection string) bool,
	admit func(ctx context.Context, p facts.Principal, r Request) (Watch, error),
	selectTarget func(target connector.Target, candidates []Candidate) (name string, explicit bool, err error),
	openTimeout time.Duration) *Table {
	return &Table{reaches: reaches, admit: admit, selectTarget: selectTarget, openTimeout: openTimeout, connections: map[string]*connection{}}
}

func (c *connection) status() Status {
	if c.err != nil {
		return Status{State: stateError, Error: c.err.Error()}
	}
	if !c.ready {
		return Status{State: stateConnecting}
	}
	if c.connector.Ready != nil {
		if err := c.connector.Ready(); err != nil {
			return Status{State: stateError, Error: err.Error()}
		}
	}
	return Status{State: Ready, Details: c.connector.Details}
}

func closeConnector(c connector.Instance) {
	if c.Close != nil {
		c.Close()
	}
}

func (t *Table) usable(c *connection, s *setup) bool {
	return t.connections[c.name] == c && c.setup == s && c.status().State == Ready
}

func (t *Table) Connections() map[string]Status {
	t.mu.Lock()
	defer t.mu.Unlock()
	out := make(map[string]Status, len(t.connections))
	for name, c := range t.connections {
		out[name] = c.status()
	}
	return out
}

func (t *Table) Stage(name, network string, claim func(connector.Target) int, open Open) {
	t.mu.Lock()
	defer t.mu.Unlock()
	c := t.connections[name]
	if c == nil {
		c = &connection{name: name}
		t.connections[name] = c
	}
	if c.setup != nil {
		c.setup.cancel()
	}
	s := &setup{network: network, claim: claim, open: open}
	s.ctx, s.cancel = context.WithCancel(context.Background())
	c.setup, c.ready, c.err = s, false, nil
	t.staged = append(t.staged, c)
}

func (t *Table) Remove(name string) {
	t.mu.Lock()
	defer t.mu.Unlock()
	if c := t.connections[name]; c != nil {
		c.setup.cancel()
		t.retired = append(t.retired, c)
		delete(t.connections, name)
	}
}

func (t *Table) Start() {
	t.mu.Lock()
	staged, retired := t.staged, t.retired
	t.staged, t.retired = nil, nil
	t.mu.Unlock()
	for _, c := range retired {
		c.active.Wait()
		closeConnector(c.connector)
	}
	ctx, cancel := context.WithTimeout(context.Background(), t.openTimeout)
	defer cancel()
	for i, c := range staged {
		t.mu.Lock()
		current := t.connections[c.name] == c && slices.Index(staged, c) == i
		old, s := c.connector, c.setup
		if current {
			c.connector = connector.Instance{}
		}
		t.mu.Unlock()
		if !current {
			continue
		}
		closeConnector(old)
		opened, err := s.open(ctx)
		if err == nil && opened.Serve == nil {
			closeConnector(opened)
			opened, err = connector.Instance{}, errNoServe
		}
		t.mu.Lock()
		c.connector, c.err, c.ready = opened, err, err == nil
		t.mu.Unlock()
	}
}

func (t *Table) Close() {
	t.mu.Lock()
	retired := append(t.retired, slices.Collect(maps.Values(t.connections))...)
	for _, c := range t.connections {
		c.setup.cancel()
	}
	clear(t.connections)
	t.staged, t.retired = nil, nil
	t.mu.Unlock()
	for _, c := range retired {
		c.active.Wait()
		closeConnector(c.connector)
	}
}

func (t *Table) Control(name string) (handler http.Handler, setup context.Context, release func(), ok bool) {
	t.mu.Lock()
	defer t.mu.Unlock()
	c := t.connections[name]
	if c == nil || !t.usable(c, c.setup) {
		return nil, nil, nil, false
	}
	c.active.Add(1)
	handler = c.connector.Control
	if handler == nil {
		handler = http.NotFoundHandler()
	}
	return handler, c.setup.ctx, c.active.Done, true
}

type candidate struct {
	c *connection
	s *setup
}

func BestClaim(target connector.Target, candidates []Candidate) (name string, explicit bool, err error) {
	best, tied := -1, []string(nil)
	for _, c := range candidates {
		if c.Claim == nil {
			continue
		}
		switch score := c.Claim(target); {
		case score > best:
			best, tied = score, []string{c.Name}
		case score == best:
			tied = append(tied, c.Name)
		}
	}
	switch {
	case best < 0:
		return "", false, errNoTarget
	case len(tied) > 1:
		slices.Sort(tied)
		return "", false, fmt.Errorf("%w: connections %s serve %s:%d equally; address one of them explicitly", ErrAmbiguous, strings.Join(tied, ", "), target.Host, target.Port)
	}
	return tied[0], false, nil
}

func (t *Table) Open(p facts.Principal) netx.Open {
	return func(ctx context.Context, network, host string, port uint32, accept func() (net.Conn, error)) error {
		return t.open(ctx, p, connector.Target{Network: network, Host: host, Port: port}, accept)
	}
}

func (t *Table) open(ctx context.Context, p facts.Principal, target connector.Target, accept func() (net.Conn, error)) error {
	t.mu.Lock()
	var ready []candidate
	for _, c := range t.connections {
		if c.status().State == Ready && c.setup.network == target.Network {
			ready = append(ready, candidate{c, c.setup})
		}
	}
	t.mu.Unlock()
	ready = slices.DeleteFunc(ready, func(r candidate) bool { return !t.reaches(ctx, p, r.c.name) })
	offered := make([]Candidate, len(ready))
	for i, r := range ready {
		offered[i] = Candidate{Name: r.c.name, Claim: r.s.claim}
	}
	name, explicit, err := t.selectTarget(target, offered)
	if err != nil {
		return err
	}
	i := slices.IndexFunc(ready, func(r candidate) bool { return r.c.name == name })
	if i < 0 {
		return errNoTarget
	}
	c, s := ready[i].c, ready[i].s
	usable := func() bool {
		t.mu.Lock()
		defer t.mu.Unlock()
		return t.usable(c, s)
	}
	admitting, cancel := context.WithCancel(context.WithoutCancel(ctx))
	stop := context.AfterFunc(s.ctx, cancel)
	watch, err := t.admit(admitting, p, Request{Connection: c.name, Target: target, Valid: usable})
	stop()
	cancel()
	if err != nil {
		return err
	}
	conn, err := accept()
	if err != nil {
		return err
	}
	stream, end := context.WithCancel(s.ctx)
	defer end()
	defer conn.Close()
	context.AfterFunc(stream, func() { conn.Close() })
	defer context.AfterFunc(ctx, end)()
	t.mu.Lock()
	pinned, serve := t.usable(c, s), c.connector.Serve
	if pinned {
		c.active.Add(1)
	}
	t.mu.Unlock()
	if !pinned {
		return nil
	}
	defer c.active.Done()
	gate, ok := watch(stream, end)
	if !ok {
		return nil
	}
	if explicit {
		target.Host = ""
	}
	serve(stream, conn, c.name, target, gate)
	return nil
}
