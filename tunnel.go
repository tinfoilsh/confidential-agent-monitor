package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/json"
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

	"github.com/tinfoilsh/monitor/connector"
	"github.com/tinfoilsh/monitor/connector/web"
	"github.com/tinfoilsh/monitor/facts"
	"golang.org/x/crypto/ssh"
)

const (
	channelDirect        = "direct-tcpip"
	fingerprintExtension = "fingerprint"
)

type forwardedAddress struct {
	Host       string
	Port       uint32
	Origin     string
	OriginPort uint32
}

func (m *monitor) serveSSH(ln net.Listener) {
	log.Printf("monitor listening on %s", ln.Addr())
	handshakes := make(chan struct{}, maxSSHHandshakes)
	for {
		nc, err := ln.Accept()
		if err != nil {
			if !errors.Is(err, net.ErrClosed) {
				log.Printf("SSH listener: %v", err)
			}
			return
		}
		hostKey := m.sshHostKey
		if st := m.live.Load(); st != nil {
			hostKey = st.HostKey
		}
		if hostKey == nil {
			nc.Close()
			continue
		}
		select {
		case handshakes <- struct{}{}:
		default:
			nc.Close()
			continue
		}
		go func() {
			front := &ssh.ServerConfig{PublicKeyCallback: m.authorized, MaxAuthTries: 3}
			front.AddHostKey(hostKey)
			nc.SetDeadline(time.Now().Add(sshHandshakeTimeout))
			conn, chans, reqs, err := ssh.NewServerConn(nc, front)
			<-handshakes
			if err != nil {
				nc.Close()
				return
			}
			nc.SetDeadline(time.Time{})
			defer conn.Close()
			if conn.Permissions.Extensions[ownerSSHExtension] == "true" {
				go ssh.DiscardRequests(reqs)
				for nc := range chans {
					go m.forwardOwner(nc)
				}
				return
			}
			if !m.admitSession(conn) {
				return
			}
			defer m.removeSession(conn)
			go m.routeRequests(conn, reqs)
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
	var target forwardedAddress
	if err := ssh.Unmarshal(nc.ExtraData(), &target); err != nil {
		nc.Reject(ssh.ConnectionFailed, "malformed direct-tcpip request")
		return
	}
	st := m.live.Load()
	p, known := st.principals[key]
	if !known {
		nc.Reject(ssh.Prohibited, "key has no agent access")
		return
	}
	if reservedRoute(target.Host) {
		m.forwardRoute(key, p, st, target, nc)
		return
	}
	ctx := context.Background()
	var name string
	host := target.Host
	var serve func(*connector.Stream)
	switch target.Host {
	case agentHost:
		// The SSH identity supplies authorization; the owner API is never exposed here.
		if target.Port != agentPort {
			nc.Reject(ssh.Prohibited, fmt.Sprintf("%s uses HTTP on port %d inside the SSH tunnel", target.Host, agentPort))
			return
		}
		serve = func(s *connector.Stream) {
			connector.ServeHTTP(s, s, m.agentHandler(key))
		}
	default:
		c, selected := st.route(p, target.Host, target.Port)
		if c == nil {
			log.Printf("%s: dropped %s:%d", p.Name, target.Host, target.Port)
			nc.Reject(ssh.Prohibited, "the monitor does not forward this target")
			return
		}
		if err := m.check(c.ctx, input{Key: key, Connection: c.name, Request: &admissionRequest{Host: target.Host, Port: target.Port}}); err != nil {
			nc.Reject(ssh.Prohibited, err.Error())
			return
		}
		ctx = c.ctx
		name = c.name
		if selected {
			host = ""
		}
		serve = func(s *connector.Stream) {
			s.Check = func(request connector.Request) error {
				return m.check(s.Context, input{stream: s, Key: key, Connection: c.name, Request: request})
			}
			log.Printf("%s: forwarding %s:%d", p.Name, target.Host, target.Port)
			c.dispatch(s.Context, func(server connector.Server, env *connector.Env) { server.Serve(s, env) })
		}
	}
	ch, reqs, err := nc.Accept()
	if err != nil {
		return
	}
	s := connector.NewStream(ctx, channelConn{ch})
	s.Name, s.Host, s.Port = name, host, target.Port
	defer s.Close()
	go func() { ssh.DiscardRequests(reqs); s.Close() }()
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
		r, ok := c.connector.(interface{ Claim(string, uint32) int })
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

// Any key authenticates so that it can publish its route. Key probes run this without a
// signature, so it only labels the session; opening channels still needs a live identity.
func (m *monitor) authorized(_ ssh.ConnMetadata, key ssh.PublicKey) (*ssh.Permissions, error) {
	if raw, ok := key.(ssh.CryptoPublicKey); ok && m.ownerPublicKey != nil {
		if public, ok := raw.CryptoPublicKey().(ed25519.PublicKey); ok && m.ownerPublicKey.Equal(public) {
			return &ssh.Permissions{Extensions: map[string]string{ownerSSHExtension: "true"}}, nil
		}
	}
	if m.live.Load() == nil {
		return nil, errLocked
	}
	return &ssh.Permissions{Extensions: map[string]string{
		fingerprintExtension: ssh.FingerprintSHA256(key), routeExtension: routeName(key),
	}}, nil
}

// sameStreamAuthority compares only the authority used by this stream. Sandbox
// routes do not use connector policy; connector streams use their own account.
func (st *state) sameStreamAuthority(old *state, key string, s *connector.Stream) bool {
	p, exists := st.principals[key]
	if !exists {
		return false
	}
	if reservedRoute(s.Host) {
		return p.Routes
	}
	previous := old.principals[key]
	c := old.connections[s.Name]
	if c == nil || st.connections[s.Name] != c || !p.reaches(c.account) {
		return false
	}
	if st == old {
		return true
	}
	if previous.Name != p.Name ||
		previous.Profile != p.Profile || st.cfg.Lattices != old.cfg.Lattices || st.program != old.program ||
		st.cfg.AllowPaidInference != old.cfg.AllowPaidInference {
		return false
	}
	a, b := previous.Accounts[c.account], p.Accounts[c.account]
	if a.Level != b.Level || !maps.Equal(a.Actions, b.Actions) ||
		!maps.Equal(old.cfg.effectModes(previous.Name, c.account), st.cfg.effectModes(p.Name, c.account)) {
		return false
	}
	for _, pair := range [][2]map[string]rule{{previous.Rules, p.Rules}, {p.Rules, previous.Rules}} {
		for name, rule := range pair[0] {
			if rule.Account == c.account && !reflect.DeepEqual(rule, pair[1][name]) {
				return false
			}
		}
	}
	before, after := old.cfg.Accounts[c.account], st.cfg.Accounts[c.account]
	if before.Preset != after.Preset || before.Contents != after.Contents || before.Sends != after.Sends || before.Strangers != after.Strangers {
		return false
	}
	ap, bp := old.cfg.resolved[before.Preset], st.cfg.resolved[after.Preset]
	// Compare protocol definitions without their compiled caches or setup/display metadata.
	left, _ := json.Marshal([]any{before.PolicyOptions, ap.PublicScope, ap.HTTP, ap.MCP})
	right, _ := json.Marshal([]any{after.PolicyOptions, bp.PublicScope, bp.HTTP, bp.MCP})
	return bytes.Equal(left, right) && maps.EqualFunc(ap.Catalog.Actions, bp.Catalog.Actions, func(a, b presetAction) bool {
		return slices.Equal(a.Effects, b.Effects)
	})
}

// trackStream registers a stream before it carries data. A policy published since
// st only invalidates admission if it changed this stream's authority.
func (m *monitor) trackStream(fingerprint string, s *connector.Stream, st *state) bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	if !m.live.Load().sameStreamAuthority(st, fingerprint, s) {
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
			if provider, ok := c.connector.(interface{ HTTPConfig() *web.HTTP }); ok {
				h := provider.HTTPConfig()
				ac.Hosts, ac.Slots, ac.Placeholders = h.Hosts, h.Slots, map[string]string{}
				for secret := range h.Names() {
					ac.Placeholders[secret] = h.Placeholder(secret)
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
	agentPort     = 80
	maxAgentBytes = 96 << 10
)

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
	var tables []sourceChange
	for _, key := range slices.Sorted(maps.Keys(v)) {
		at := append(slices.Clone(path), key)
		if table, ok := v[key].(map[string]any); ok && len(table) > 0 && table["$json"] == nil {
			tables = append(tables, fragmentChanges(table, at)...)
		} else {
			changes = append(changes, sourceChange{Path: at, Value: v[key]})
		}
	}
	// A table's own keys come first so its header precedes its subtables'.
	return append(changes, tables...)
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
	r := m.addRecord(&record{Facts: &facts.Facts{Version: facts.Version, Principal: facts.Principal{Key: p.Key, Name: p.Name},
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
