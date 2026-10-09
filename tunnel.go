package main

import (
	"context"
	"errors"
	"fmt"
	"log"
	"maps"
	"net"
	"net/http"
	"reflect"
	"slices"
	"strings"
	"time"

	sdk "github.com/modelcontextprotocol/go-sdk/mcp"
	sentinel "github.com/tinfoilsh/mcp-sentinel"
	"github.com/tinfoilsh/monitor/connector"
	"github.com/tinfoilsh/monitor/connector/mcp"
	"github.com/tinfoilsh/monitor/connector/web"
	"github.com/tinfoilsh/monitor/facts"
	"golang.org/x/crypto/ssh"
)

const (
	channelDirect        = "direct-tcpip"
	fingerprintExtension = "fingerprint"
)

func (m *monitor) serveSSH(ln net.Listener) {
	log.Printf("monitor listening on %s", ln.Addr())
	for {
		nc, err := ln.Accept()
		if err != nil {
			if !errors.Is(err, net.ErrClosed) {
				log.Printf("SSH listener: %v", err)
			}
			return
		}
		go func() {
			st := m.live.Load()
			if st == nil {
				nc.Close()
				return
			}
			front := &ssh.ServerConfig{PublicKeyCallback: m.authorized}
			front.AddHostKey(st.HostKey)
			conn, chans, reqs, err := ssh.NewServerConn(nc, front)
			if err != nil {
				nc.Close()
				return
			}
			defer conn.Close()
			go ssh.DiscardRequests(reqs)
			for nc := range chans {
				go m.forward(conn.Permissions.Extensions[fingerprintExtension], nc)
			}
		}()
	}
}

func (m *monitor) forward(key string, nc ssh.NewChannel) {
	if nc.ChannelType() != channelDirect {
		nc.Reject(ssh.Prohibited, "only direct-tcpip channels are forwarded")
		return
	}
	var target struct {
		Host string
		Port uint32
		Rest []byte `ssh:"rest"`
	}
	if err := ssh.Unmarshal(nc.ExtraData(), &target); err != nil {
		nc.Reject(ssh.ConnectionFailed, "malformed direct-tcpip request")
		return
	}
	st := m.live.Load()
	p := st.principals[key]
	ctx := context.Background()
	var serve func(*connector.Stream)
	switch target.Host {
	case agentHost, mcpHost:
		// The SSH identity supplies authorization; the owner API is never exposed here.
		if target.Port != agentPort {
			nc.Reject(ssh.Prohibited, fmt.Sprintf("%s uses HTTP on port %d inside the SSH tunnel", target.Host, agentPort))
			return
		}
		serve = func(s *connector.Stream) {
			handler := m.agentHandler(key)
			if target.Host == mcpHost {
				handler = sdk.NewStreamableHTTPHandler(func(*http.Request) *sdk.Server { return m.mcpServer(key, s) }, &sdk.StreamableHTTPOptions{Stateless: true})
			}
			connector.ServeHTTP(s, s, handler)
		}
	default:
		c, selected := st.route(p, target.Host, target.Port)
		if c == nil {
			log.Printf("%s: dropped %s:%d", p.Name, target.Host, target.Port)
			nc.Reject(ssh.Prohibited, "the monitor does not forward this target")
			return
		}
		if err := m.gate(c.ctx, input{Key: key, Connection: c.name, Request: &admissionRequest{Host: target.Host, Port: target.Port}}); err != nil {
			nc.Reject(ssh.Prohibited, err.Error())
			return
		}
		ctx = c.ctx
		serve = func(s *connector.Stream) {
			s.Name, s.Host, s.Port = c.name, target.Host, target.Port
			if selected {
				s.Host = ""
			}
			s.Gate = func(request connector.Request) error {
				return m.gate(s.Context, input{stream: s, Key: key, Connection: c.name, Request: request})
			}
			log.Printf("%s: forwarding %s:%d", p.Name, target.Host, target.Port)
			select {
			case c.incoming <- s:
			case <-s.Context.Done():
			}
		}
	}
	ch, reqs, err := nc.Accept()
	if err != nil {
		return
	}
	go ssh.DiscardRequests(reqs)
	s := connector.NewStream(ctx, channelConn{ch})
	// agent.monitor authorizes each request against live state, and an approved proposal must answer on its stream.
	if target.Host != agentHost && !m.trackStream(key, s, st) {
		s.Close()
		return
	}
	serve(s)
}

// Only connections the principal reaches are routed, so their claims never tie with another principal's.
// A name.monitor target selects that connection; a claimer then checks each request's origin itself.
func (st *state) route(p principal, host string, port uint32) (*connection, bool) {
	if name, ok := strings.CutSuffix(host, ".monitor"); ok {
		c := st.connections[name]
		if c == nil || !p.reaches(c.account) {
			return nil, false
		}
		return c, true
	}
	best, tied := -1, false
	var selected *connection
	for _, c := range st.connections {
		r, ok := c.connector.(*web.HTTP)
		if !ok || !p.reaches(c.account) {
			continue
		}
		score := r.Claim(host, port)
		if score < 0 {
			continue
		}
		if score > best {
			best, tied, selected = score, false, c
		} else if score == best {
			tied = true
		}
	}
	if tied {
		log.Printf("ambiguous route for %s:%d at claim %d", host, port, best)
		return nil, false
	}
	return selected, false
}

type channelConn struct{ ssh.Channel }

func (channelConn) LocalAddr() net.Addr              { return &net.TCPAddr{} }
func (channelConn) RemoteAddr() net.Addr             { return &net.TCPAddr{} }
func (channelConn) SetDeadline(time.Time) error      { return nil }
func (channelConn) SetReadDeadline(time.Time) error  { return nil }
func (channelConn) SetWriteDeadline(time.Time) error { return nil }

// authorized reads the identities on every attempt, so keys change without a restart.
func (m *monitor) authorized(_ ssh.ConnMetadata, key ssh.PublicKey) (*ssh.Permissions, error) {
	fingerprint := ssh.FingerprintSHA256(key)
	if _, ok := m.live.Load().principals[fingerprint]; ok {
		return &ssh.Permissions{Extensions: map[string]string{fingerprintExtension: fingerprint}}, nil
	}
	return nil, errors.New("key is not authorized")
}

// trackStream registers a stream before it carries data, so later changes to its identity's
// authority close it. A policy published since st may have changed the stream's admission.
func (m *monitor) trackStream(fingerprint string, s *connector.Stream, st *state) bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.live.Load() != st {
		return false
	}
	m.streams[s] = fingerprint
	context.AfterFunc(s.Context, func() {
		m.mu.Lock()
		delete(m.streams, s)
		m.mu.Unlock()
	})
	return true
}

type admissionRequest facts.TCP

func (r *admissionRequest) Describe(c connector.Context) (facts.Facts, error) {
	return facts.Facts{Kind: facts.KindAdmission, Operation: &facts.Operation{Action: "session.admit", Effects: []string{"session"}},
		Title: "Open " + c.Connection, Parameters: map[string]any{"host": r.Host, "port": r.Port}, Details: facts.Details{TCP: (*facts.TCP)(r)},
		Context: facts.Context{Observes: cleanLabel}}, nil
}

const agentHost = "agent.monitor"

// Discovery describes reachable connections, not the owner's configuration or credentials.
// HTTP connections add public routing and placeholder data, never credentials.
type agentConnection struct {
	Name         string            `json:"name"`
	Account      string            `json:"account"`
	Kind         string            `json:"kind"`
	Host         string            `json:"host"`
	State        string            `json:"state"`
	Access       access            `json:"access"`
	Hosts        []string          `json:"hosts"`
	Slots        []web.Slot        `json:"slots"`
	Placeholders map[string]string `json:"placeholders"`
}

func (m *monitor) agentHandler(key string) http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /connections", agentJSON(m, key, func(r *http.Request, _ struct{}, p principal) (any, error) {
		st := m.live.Load()
		result := struct {
			Identity    string            `json:"identity"`
			CA          string            `json:"ca"`
			Connections []agentConnection `json:"connections"`
		}{p.Name, m.doc.Keys.CACert, []agentConnection{}}
		for _, name := range slices.Sorted(maps.Keys(st.connections)) {
			c := st.connections[name]
			if !p.reaches(c.account) {
				continue
			}
			ac := agentConnection{Name: name, Account: c.account, Kind: c.protocol, Host: name + ".monitor",
				State: c.status().State, Access: p.Accounts[c.account]}
			if h, ok := c.connector.(*web.HTTP); ok {
				ac.Hosts, ac.Slots, ac.Placeholders = h.Hosts, h.Slots, map[string]string{}
				for secret := range h.Names() {
					ac.Placeholders[secret] = web.Placeholder(name, secret)
				}
			}
			result.Connections = append(result.Connections, ac)
		}
		return result, nil
	}))
	show := func() (any, error) {
		st := m.live.Load()
		p := st.principals[key]
		visible, _, err := agentView(st.cfg, p)
		if err != nil {
			return nil, err
		}
		source, err := renderTOML(visible)
		return map[string]any{"identity": p.Name, "source": source}, err
	}
	mux.HandleFunc("GET /policy", agentJSON(m, key, func(*http.Request, struct{}, principal) (any, error) {
		return show()
	}))
	mux.HandleFunc("POST /policy/proposals", agentJSON(m, key, func(r *http.Request, input proposalInput, p principal) (any, error) {
		if err := m.proposePolicy(r.Context(), p, input); err != nil {
			return nil, err
		}
		return show()
	}))
	return mux
}

const (
	mcpHost       = "mcp.monitor"
	agentPort     = 80
	mcpSeparator  = "__"
	maxAgentBytes = 96 << 10
)

// mcpServer is built for each request from the live state, so upstreams change without restarting the gateway.
func (m *monitor) mcpServer(key string, s *connector.Stream) *sdk.Server {
	st := m.live.Load()
	p := st.principals[key]
	var upstreams []*connection
	var instructions []string
	for _, name := range slices.Sorted(maps.Keys(st.connections)) {
		c := st.connections[name]
		if _, isMCP := c.connector.(*mcp.Server); !isMCP || !p.reaches(c.account) || c.status().State != "ready" ||
			m.gate(s.Context, input{Key: key, Connection: c.name, Request: &admissionRequest{Host: mcpHost, Port: agentPort}}) != nil {
			continue
		}
		upstreams = append(upstreams, c)
		if text := c.connector.(*mcp.Server).Instructions(); text != "" {
			instructions = append(instructions, "## "+c.name+"\n\n"+text)
		}
	}
	server := sdk.NewServer(&sdk.Implementation{Name: "monitor", Version: sentinel.Version}, &sdk.ServerOptions{Instructions: strings.Join(instructions, "\n\n")})
	for _, c := range upstreams {
		c.connector.(*mcp.Server).Register(server, c.name+mcpSeparator, func(request connector.Request) error {
			return m.gate(s.Context, input{stream: s, Key: key, Connection: c.name, Request: request})
		})
	}
	return server
}

func agentJSON[T any](m *monitor, key string, fn func(*http.Request, T, principal) (any, error)) http.HandlerFunc {
	return jsonHandler(maxAgentBytes, func(r *http.Request, input T) (any, error) {
		m.mu.Lock()
		defer m.mu.Unlock()
		p, ok := m.live.Load().principals[key]
		if !ok {
			return nil, errNoAgent
		}
		return fn(r, input, p)
	})
}

const (
	maxProposalBytes   = 64 << 10
	maxProposalReason  = 4096
	maxProposalDeletes = 64
)

type proposalInput struct {
	Source string     `json:"source"`
	Reason string     `json:"reason"`
	Delete [][]string `json:"delete,omitempty"`
}

// agentView splits the configuration into the settings p may read and propose
// changing, and the rest, which a proposal must leave unchanged.
func agentView(cfg *config, p principal) (visible, rest map[string]any, err error) {
	if rest, err = facts.JSON[map[string]any](cfg); err != nil {
		return nil, nil, err
	}
	identities, _ := rest["identities"].(map[string]any)
	identity, _ := identities[p.Name].(map[string]any)
	accounts, _ := rest["accounts"].(map[string]any)
	reachable := map[string]any{}
	for name, a := range accounts {
		if p.reaches(name) {
			reachable[name] = take(a.(map[string]any), "contents", "strangers", "sends", "policy_options")
		}
	}
	visible = map[string]any{"lattices": rest["lattices"], "identities": map[string]any{p.Name: take(identity, "accounts", "rules")}, "accounts": reachable}
	delete(rest, "lattices")
	return visible, rest, nil
}

// take moves the named fields out of m.
func take(m map[string]any, fields ...string) map[string]any {
	out := map[string]any{}
	for _, field := range fields {
		if value, ok := m[field]; ok {
			out[field] = value
			delete(m, field)
		}
	}
	return out
}

// fragmentChanges sets each leaf of a TOML fragment, merging it into the source.
func fragmentChanges(v map[string]any, path []string) (changes []sourceChange) {
	for _, key := range slices.Sorted(maps.Keys(v)) {
		at := append(slices.Clone(path), key)
		if table, ok := v[key].(map[string]any); ok && len(table) > 0 {
			changes = append(changes, fragmentChanges(table, at)...)
		} else {
			changes = append(changes, sourceChange{Path: at, Value: v[key]})
		}
	}
	return changes
}

// proposePolicy holds an agent's change as an approval card and applies it once the owner allows it.
func (m *monitor) proposePolicy(ctx context.Context, p principal, input proposalInput) (err error) {
	if len(input.Source) > maxProposalBytes || len(input.Reason) > maxProposalReason || strings.TrimSpace(input.Reason) == "" || len(input.Delete) > maxProposalDeletes {
		return fmt.Errorf("proposal needs a reason of 1-%d bytes, at most %d bytes of TOML, and at most %d deletions", maxProposalReason, maxProposalBytes, maxProposalDeletes)
	}
	patch, err := readSource(input.Source)
	if err != nil {
		return err
	}
	changes := fragmentChanges(patch, nil)
	for _, path := range input.Delete {
		changes = append(changes, sourceChange{Path: path, Delete: true})
	}
	base := m.doc.Policy
	source, err := editSource(base, changes)
	if err != nil {
		return err
	}
	if source == base {
		return errors.New("proposal does not change policy")
	}
	next, st, err := m.prepareCandidate(ctx, source, nil)
	if err != nil {
		return err
	}
	_, before, err := agentView(m.live.Load().cfg, p)
	if err != nil {
		return err
	}
	_, after, err := agentView(st.cfg, p)
	if err != nil {
		return err
	}
	if !reflect.DeepEqual(before, after) {
		return errors.New("proposal may edit only your permissions, reachable accounts' policy settings, or lattice switches")
	}
	diff, err := m.policyPreview(next, st)
	if err != nil {
		return err
	}
	r := m.addRecord(&decision{Facts: &facts.Facts{Version: facts.Version, Principal: facts.Principal{Key: p.Key, Name: p.Name},
		Title: "Change policy", Parameters: map[string]any{}, Details: facts.Details{Policy: diff}},
		Requirements: []requirement{{ID: "policy", Message: input.Reason}}})
	defer func() { r.settle(err) }()
	if err = m.await(ctx, r); err != nil {
		return err
	}
	if m.doc.Policy != base {
		return errPolicyConflict
	}
	if next, st, err = m.prepareCandidate(ctx, next.Policy, nil); err != nil {
		return err
	}
	return m.activate(ctx, next, st)
}
