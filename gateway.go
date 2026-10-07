package main

import (
	"context"
	"errors"
	"log"
	"maps"
	"net"
	"net/http"
	"slices"
	"strings"

	sdk "github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/tinfoilsh/mcp-sentinel"
	"github.com/tinfoilsh/monitor/connector"
	"github.com/tinfoilsh/monitor/connector/mcp"
	"golang.org/x/crypto/ssh"
)

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
		if m.gate(s.Context, input{Principal: p, Connection: c.name, Protocol: c.protocol, TCP: &tcpLayer{Host: gatewayHost, Port: gatewayPort}}, c.account) != nil {
			continue
		}
		upstreams = append(upstreams, c)
		if text := c.connector.(*mcp.Server).Instructions(); text != "" {
			instructions = append(instructions, "## "+c.name+"\n\n"+text)
		}
	}
	server := sdk.NewServer(&sdk.Implementation{Name: "monitor", Version: sentinel.Version}, &sdk.ServerOptions{Instructions: strings.Join(instructions, "\n\n")})
	for _, c := range upstreams {
		c.connector.(*mcp.Server).Register(server, c.name+gatewaySeparator, func(e connector.Event) error {
			return m.gate(s.Context, input{stream: s, Principal: p, Connection: c.name, Protocol: c.protocol, Event: &e}, c.account)
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
