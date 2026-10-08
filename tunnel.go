package main

import (
	"context"
	"encoding/json"
	"errors"
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
	if target.Host == messageHost {
		m.forwardMessages(p, nc, target.Port)
		return
	}
	if target.Host == gatewayHost {
		m.forwardGateway(p, nc, target.Port)
		return
	}
	if target.Host == discoveryHost {
		m.forwardDiscovery(p, nc, target.Port)
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
		return m.gate(s.Context, input{stream: s, Principal: p, Connection: c.name, Request: request}, c.account)
	}
	if err := m.gate(s.Context, input{Principal: p, Connection: c.name, Request: &admissionRequest{Host: target.Host, Port: target.Port}}, c.account); err != nil {
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
		r, ok := c.connector.(connector.Claimer)
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
	m.flow.Lock()
	defer m.flow.Unlock()
	if _, ok := m.live.Load().principals[fingerprint]; !ok {
		return errNoAgent
	}
	if m.streams == nil {
		m.streams = map[string]map[*connector.Stream]struct{}{}
	}
	if m.streams[fingerprint] == nil {
		m.streams[fingerprint] = map[*connector.Stream]struct{}{}
	}
	m.streams[fingerprint][s] = struct{}{}
	context.AfterFunc(s.Context, func() {
		m.flow.Lock()
		defer m.flow.Unlock()
		delete(m.streams[fingerprint], s)
		if len(m.streams[fingerprint]) == 0 {
			delete(m.streams, fingerprint)
		}
	})
	return nil
}

// retireStreamsLocked requires flow. Closing the client side prevents further
// input under an old authorization, including on raw SSH and CLI streams.
func (m *monitor) retireStreamsLocked(fingerprint string, source *connector.Stream) {
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

func (r *admissionRequest) Describe(c connector.Context) (facts.Facts, connector.Approval, error) {
	return facts.Facts{Kind: facts.KindAdmission, Operation: &facts.Operation{Action: "session.admit", Effects: []string{"session"}},
		Title: "Open " + c.Connection, Parameters: connector.JSONFields(r), Details: facts.Details{TCP: (*facts.TCP)(r)},
		Context: facts.Context{Observes: c.Label, Sends: c.Label.Audience}}, connector.Approval{}, nil
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
	mux.HandleFunc("GET /setup", func(w http.ResponseWriter, r *http.Request) {
		m.mu.Lock()
		ca := m.doc.Keys.CACert
		st := m.live.Load()
		m.mu.Unlock()
		p, ok := st.principals[key]
		if !ok {
			http.Error(w, "identity removed", http.StatusForbidden)
			return
		}
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
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Cache-Control", "no-store")
		json.NewEncoder(w).Encode(result)
	})
	mux.HandleFunc("GET /connections", func(w http.ResponseWriter, r *http.Request) {
		st := m.live.Load()
		p, ok := st.principals[key]
		if !ok {
			http.Error(w, "identity removed", http.StatusForbidden)
			return
		}
		connections := []agentConnection{}
		for _, name := range slices.Sorted(maps.Keys(st.connections)) {
			c := st.connections[name]
			if !p.reaches(c.account) {
				continue
			}
			state := "connecting"
			select {
			case <-c.done:
				state = "stopped"
				if c.err != nil {
					state = "error"
				}
			default:
				select {
				case <-c.ready:
					state = "ready"
				default:
				}
			}
			connections = append(connections, agentConnection{
				Name: name, Account: c.account, Kind: c.protocol, Host: name + ".monitor",
				State: state, Access: p.Accounts[c.account],
			})
		}
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Cache-Control", "no-store")
		json.NewEncoder(w).Encode(struct {
			Connections []agentConnection `json:"connections"`
		}{connections})
	})
	return mux
}

// The SSH identity supplies authorization; the owner API is never exposed here.
func (m *monitor) forwardDiscovery(p principal, nc ssh.NewChannel, port uint32) {
	if port != 80 {
		nc.Reject(ssh.Prohibited, "agent.monitor uses HTTP on port 80 inside the SSH tunnel")
		return
	}
	ch, reqs, err := nc.Accept()
	if err != nil {
		return
	}
	go ssh.DiscardRequests(reqs)
	ctx, cancel := context.WithTimeout(context.Background(), readHeaderTimeout)
	defer cancel()
	s := connector.NewStream(ctx)
	s.Conn, s.Name = channelConn{ch}, discoveryHost
	defer s.Close()
	if err := m.trackStream(p.Key, s); err != nil {
		return
	}
	in := connector.NewListener()
	defer in.Close()
	stop := context.AfterFunc(s.Context, func() { in.Close(); s.Close() })
	defer stop()
	server := &http.Server{Handler: m.discoveryHandler(p.Key), MaxHeaderBytes: 8192,
		ReadHeaderTimeout: readHeaderTimeout,
		ConnContext:       func(context.Context, net.Conn) context.Context { return s.Context }}
	server.SetKeepAlivesEnabled(false)
	defer server.Close()
	go in.Hand(s)
	if err := server.Serve(in); err != nil && !errors.Is(err, net.ErrClosed) && !errors.Is(err, http.ErrServerClosed) {
		log.Printf("discovery HTTP: %v", err)
	}
}

const (
	gatewayHost      = "mcp.monitor"
	gatewayPort      = 80
	gatewaySeparator = "__"
)

// forwardGateway serves every MCP connection the identity reaches as one server, each tool prefixed with its connection's name.
func (m *monitor) forwardGateway(p principal, nc ssh.NewChannel, port uint32) {
	if port != gatewayPort {
		nc.Reject(ssh.Prohibited, "mcp.monitor uses HTTP on port 80 inside the SSH tunnel")
		return
	}
	if len(gatewayUpstreams(m.live.Load(), p.Key)) == 0 {
		nc.Reject(ssh.Prohibited, "this identity reaches no MCP connection")
		return
	}
	ch, reqs, err := nc.Accept()
	if err != nil {
		return
	}
	go ssh.DiscardRequests(reqs)
	s := connector.NewStream(context.Background())
	s.Conn, s.Name = channelConn{ch}, gatewayHost
	defer s.Close()
	if err := m.trackStream(p.Key, s); err != nil {
		return
	}
	in := connector.NewListener()
	defer in.Close()
	stop := context.AfterFunc(s.Context, func() { in.Close() })
	defer stop()
	go in.Hand(s)
	handler := sdk.NewStreamableHTTPHandler(func(*http.Request) *sdk.Server { return m.gatewayServer(p.Key, s) }, &sdk.StreamableHTTPOptions{Stateless: true})
	if err := connector.ServeHTTP(s.Context, in, func() {}, handler); err != nil && !errors.Is(err, net.ErrClosed) && !errors.Is(err, http.ErrServerClosed) {
		log.Printf("MCP gateway: %v", err)
	}
}

// gatewayServer is built for each request from the live state, so upstreams change without restarting the gateway.
func (m *monitor) gatewayServer(key string, s *connector.Stream) *sdk.Server {
	st := m.live.Load()
	p := st.principals[key]
	var upstreams []*connection
	var instructions []string
	for _, c := range gatewayUpstreams(st, key) {
		if m.gate(s.Context, input{Principal: p, Connection: c.name, Request: &admissionRequest{Host: gatewayHost, Port: gatewayPort}}, c.account) != nil {
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
			return m.gate(s.Context, input{stream: s, Principal: p, Connection: c.name, Request: request}, c.account)
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
		if _, isMCP := c.connector.(*mcp.Server); !isMCP || !p.reaches(c.account) || c.ready == nil {
			continue
		}
		select {
		case <-c.done:
			continue
		default:
		}
		select {
		case <-c.ready:
			upstreams = append(upstreams, c)
		default:
		}
	}
	return upstreams
}
