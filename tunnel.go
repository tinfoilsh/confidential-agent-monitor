package main

import (
	"context"
	"errors"
	"fmt"
	"log"
	"maps"
	"net"
	"net/http"
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

type principalKey struct{}

const (
	channelDirect = "direct-tcpip"
)

func (m *monitor) serveSSH(ln net.Listener) {
	front := &ssh.ServerConfig{PublicKeyCallback: m.authorized}
	front.AddHostKey(m.live.Load().HostKey)
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
			conn, chans, reqs, err := ssh.NewServerConn(nc, front)
			if err != nil {
				nc.Close()
				return
			}
			defer conn.Close()
			go ssh.DiscardRequests(reqs)
			p := conn.Permissions.ExtraData[principalKey{}].(principal)
			for nc := range chans {
				go m.forward(p, nc)
			}
		}()
	}
}

func (m *monitor) forward(p principal, nc ssh.NewChannel) {
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
	switch target.Host {
	case discoveryHost:
		m.serveAgentHTTP(p, nc, target.Port, target.Host, readHeaderTimeout, func(*connector.Stream) http.Handler { return m.discoveryHandler(p.Key) })
		return
	case gatewayHost:
		if len(gatewayUpstreams(m.live.Load(), p.Key)) == 0 {
			nc.Reject(ssh.Prohibited, "this identity reaches no MCP connection")
			return
		}
		m.serveAgentHTTP(p, nc, target.Port, target.Host, 0, func(stream *connector.Stream) http.Handler {
			return sdk.NewStreamableHTTPHandler(func(*http.Request) *sdk.Server { return m.gatewayServer(p.Key, stream) }, &sdk.StreamableHTTPOptions{Stateless: true})
		})
		return
	}
	st := m.live.Load()
	p = st.principals[p.Key]
	c, selected := st.route(p, target.Host, target.Port)
	if c == nil {
		log.Printf("%s: dropped %s:%d", p.Name, target.Host, target.Port)
		nc.Reject(ssh.Prohibited, "the monitor does not forward this target")
		return
	}
	select {
	case <-c.ready:
	default:
		nc.Reject(ssh.ConnectionFailed, "the connector is starting")
		return
	}
	if c.ctx.Err() != nil {
		nc.Reject(ssh.ConnectionFailed, "the connector is stopped")
		return
	}
	s := connector.NewStream(c.ctx)
	s.Name, s.Host, s.Port = c.name, target.Host, target.Port
	if selected {
		s.Host = ""
	}
	s.Gate = func(request connector.Request) error {
		return m.gate(s.Context, input{stream: s, Key: p.Key, Connection: c.name, Request: request})
	}
	if err := m.gate(s.Context, input{Key: p.Key, Connection: c.name, Request: &admissionRequest{Host: target.Host, Port: target.Port}}); err != nil {
		s.Close()
		nc.Reject(ssh.Prohibited, err.Error())
		return
	}
	ch, reqs, err := nc.Accept()
	if err != nil {
		s.Close()
		return
	}
	go ssh.DiscardRequests(reqs)
	s.Conn = channelConn{ch}
	if err := m.trackStream(p.Key, s); err != nil {
		s.Close()
		return
	}
	log.Printf("%s: forwarding %s:%d", p.Name, target.Host, target.Port)
	c.incoming.Hand(s)
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
	if p, ok := m.live.Load().principals[ssh.FingerprintSHA256(key)]; ok {
		return &ssh.Permissions{ExtraData: map[any]any{principalKey{}: p}}, nil
	}
	return nil, errors.New("key is not authorized")
}

// Connector streams are registered before any connector can consume their data.
// Mailbox channels are separate and remain available after a label changes.
func (m *monitor) trackStream(fingerprint string, s *connector.Stream) error {
	return m.transact(func(tx *transaction) error {
		if _, ok := tx.live.Load().principals[fingerprint]; !ok {
			return errNoAgent
		}
		if tx.streams[fingerprint] == nil {
			tx.streams[fingerprint] = map[*connector.Stream]struct{}{}
		}
		tx.streams[fingerprint][s] = struct{}{}
		context.AfterFunc(s.Context, func() {
			m.transact(func(tx *transaction) error {
				delete(tx.streams[fingerprint], s)
				if len(tx.streams[fingerprint]) == 0 {
					delete(tx.streams, fingerprint)
				}
				return nil
			})
		})
		return nil
	})
}

// Closing the client side prevents further
// input under an old authorization, including on raw SSH and CLI streams.
func (m *transaction) retireStreams(fingerprint string, source *connector.Stream) {
	for s := range m.streams[fingerprint] {
		if s == source {
			continue
		}
		s.Close()
		delete(m.streams[fingerprint], s)
	}
	if len(m.streams[fingerprint]) == 0 {
		delete(m.streams, fingerprint)
	}
}

type admissionRequest facts.TCP

func (r *admissionRequest) Describe(c connector.Context) (facts.Facts, error) {
	return facts.Facts{Kind: facts.KindAdmission, Operation: &facts.Operation{Action: "session.admit", Effects: []string{"session"}},
		Title: "Open " + c.Connection, Parameters: map[string]any{"host": r.Host, "port": r.Port}, Details: facts.Details{TCP: (*facts.TCP)(r)},
		Context: facts.Context{Observes: c.Label, Sends: c.Label.Audience}}, nil
}

const discoveryHost = "agent.monitor"

// Discovery describes reachable connections, not the owner's configuration or credentials.
type agentConnection struct {
	Name    string `json:"name"`
	Account string `json:"account"`
	Kind    string `json:"kind"`
	Host    string `json:"host"`
	State   string `json:"state"`
	Access  access `json:"access"`
}

// Client setup contains public routing and placeholder data, never credentials.
type agentSetupConnection struct {
	Name         string            `json:"name"`
	Hosts        []string          `json:"hosts"`
	Origins      []string          `json:"origins"`
	Placeholders map[string]string `json:"placeholders"`
	Git          []agentGitSlot    `json:"git"`
}

type agentGitSlot struct {
	Origin   string `json:"origin"`
	Path     string `json:"path"`
	Password string `json:"password"`
}

type agentSetup struct {
	Version     int                    `json:"version"`
	Identity    string                 `json:"identity"`
	CA          string                 `json:"ca"`
	Connections []agentSetupConnection `json:"http"`
}

func (m *monitor) discoveryHandler(key string) http.Handler {
	mux := http.NewServeMux()
	m.agentPolicyRoutes(mux, key)
	mux.HandleFunc("GET /setup", agentJSON(m, key, func(r *http.Request, _ struct{}, base policyBase, p principal) (any, error) {
		st, ca := base.state, base.doc.Keys.CACert
		result := agentSetup{Version: 1, Identity: p.Name, CA: ca, Connections: []agentSetupConnection{}}
		for _, name := range slices.Sorted(maps.Keys(st.connections)) {
			c := st.connections[name]
			h, ok := c.connector.(*web.HTTP)
			if !ok || !p.reaches(c.account) {
				continue
			}
			setup := agentSetupConnection{Name: name, Hosts: h.Hosts, Origins: []string{}, Placeholders: map[string]string{}, Git: []agentGitSlot{}}
			for secret := range h.Names() {
				setup.Placeholders[secret] = web.Placeholder(name, secret)
			}
			for _, slot := range h.Slots {
				if !slices.Contains(setup.Origins, slot.Origin) {
					setup.Origins = append(setup.Origins, slot.Origin)
				}
				if slot.Basic == "password" && slot.Origin == "https://github.com" && setup.Placeholders[slot.Value] != "" {
					setup.Git = append(setup.Git, agentGitSlot{slot.Origin, slot.Path, setup.Placeholders[slot.Value]})
				}
			}
			result.Connections = append(result.Connections, setup)
		}
		return result, nil
	}))
	mux.HandleFunc("GET /connections", agentJSON(m, key, func(r *http.Request, _ struct{}, base policyBase, p principal) (any, error) {
		st := base.state
		connections := []agentConnection{}
		for _, name := range slices.Sorted(maps.Keys(st.connections)) {
			c := st.connections[name]
			if !p.reaches(c.account) {
				continue
			}
			status := c.status()
			connections = append(connections, agentConnection{
				Name: name, Account: c.account, Kind: c.protocol, Host: name + ".monitor",
				State: status.State, Access: p.Accounts[c.account],
			})
		}
		return struct {
			Connections []agentConnection `json:"connections"`
		}{connections}, nil
	}))
	return mux
}

const (
	gatewayHost      = "mcp.monitor"
	gatewayPort      = 80
	gatewaySeparator = "__"
)

// The SSH identity supplies authorization; the owner API is never exposed here.
func (m *monitor) serveAgentHTTP(p principal, nc ssh.NewChannel, port uint32, host string, timeout time.Duration, handler func(*connector.Stream) http.Handler) {
	if port != gatewayPort {
		nc.Reject(ssh.Prohibited, fmt.Sprintf("%s uses HTTP on port %d inside the SSH tunnel", host, gatewayPort))
		return
	}
	ch, reqs, err := nc.Accept()
	if err != nil {
		return
	}
	go ssh.DiscardRequests(reqs)
	ctx := context.Background()
	if timeout != 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, timeout)
		defer cancel()
	}
	stream := connector.NewStream(ctx)
	stream.Conn, stream.Name = channelConn{ch}, host
	defer stream.Close()
	if err := m.trackStream(p.Key, stream); err != nil {
		return
	}
	in := connector.NewListener(stream.Context)
	server := &http.Server{Handler: handler(stream), MaxHeaderBytes: 8192, ReadHeaderTimeout: readHeaderTimeout,
		ConnContext: func(context.Context, net.Conn) context.Context { return stream.Context }}
	server.SetKeepAlivesEnabled(timeout == 0)
	defer server.Close()
	go in.Hand(stream)
	if err := server.Serve(in); err != nil && !errors.Is(err, net.ErrClosed) && !errors.Is(err, http.ErrServerClosed) {
		log.Printf("%s HTTP: %v", host, err)
	}
}

// gatewayServer is built for each request from the live state, so upstreams change without restarting the gateway.
func (m *monitor) gatewayServer(key string, s *connector.Stream) *sdk.Server {
	st := m.live.Load()
	p := st.principals[key]
	var upstreams []*connection
	var instructions []string
	for _, c := range gatewayUpstreams(st, key) {
		if m.gate(s.Context, input{Key: p.Key, Connection: c.name, Request: &admissionRequest{Host: gatewayHost, Port: gatewayPort}}) != nil {
			continue
		}
		upstreams = append(upstreams, c)
		if text := c.connector.(*mcp.Server).Instructions(); text != "" {
			instructions = append(instructions, "## "+c.name+"\n\n"+text)
		}
	}
	server := sdk.NewServer(&sdk.Implementation{Name: "monitor", Version: sentinel.Version}, &sdk.ServerOptions{Instructions: strings.Join(instructions, "\n\n")})
	for _, c := range upstreams {
		c.connector.(*mcp.Server).Register(server, c.name+gatewaySeparator, func(request connector.Request) error {
			return m.gate(s.Context, input{stream: s, Key: p.Key, Connection: c.name, Request: request})
		})
	}
	return server
}

// gatewayUpstreams are the running MCP connections the identity reaches, in name order.
func gatewayUpstreams(st *state, key string) (upstreams []*connection) {
	p, ok := st.principals[key]
	if !ok {
		return nil
	}
	for _, name := range slices.Sorted(maps.Keys(st.connections)) {
		c := st.connections[name]
		if _, isMCP := c.connector.(*mcp.Server); isMCP && p.reaches(c.account) && c.status().State == "ready" {
			upstreams = append(upstreams, c)
		}
	}
	return upstreams
}

func agentJSON[T any](m *monitor, key string, fn func(*http.Request, T, policyBase, principal) (any, error)) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		base, err := m.policySnapshot()
		if err != nil {
			responseError(w, err)
			return
		}
		p, ok := base.state.principals[key]
		if !ok {
			responseError(w, errNoAgent)
			return
		}
		jsonHandler(96<<10, func(r *http.Request, input T) (any, error) { return fn(r, input, base, p) })(w, r)
	}
}
