package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net"
	"net/http"
	"sync/atomic"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/tinfoilsh/mcp-sentinel"
	"github.com/tinfoilsh/monitor/connector"
	"github.com/tinfoilsh/monitor/connector/credential"
)

const (
	protocolMCP       = "mcp"
	gatewayName       = "mcp"
	toolSeparator     = "__"
	readHeaderTimeout = 30 * time.Second
)

type mcpServer struct {
	URL      string                 `yaml:"url"`
	Token    *credential.Credential `yaml:"token"`
	account  string
	err      string
	upstream atomic.Pointer[sentinel.Upstream]
}

// bearer asks the credential on every request, so a refreshed token replaces an expired one.
type bearer struct {
	token *credential.Credential
	base  http.RoundTripper
}

func (b bearer) RoundTrip(r *http.Request) (*http.Response, error) {
	token, err := b.token.Value()
	if err != nil {
		return nil, err
	}
	r = r.Clone(r.Context())
	r.Header.Set("Authorization", "Bearer "+token)
	return b.base.RoundTrip(r)
}

func (m *monitor) startMCP() {
	server := &http.Server{
		ReadHeaderTimeout: readHeaderTimeout,
		ConnContext: func(ctx context.Context, c net.Conn) context.Context {
			return context.WithValue(ctx, principalKey{}, connector.StreamOf(c).Conn.(channelConn).principal)
		},
		Handler: mcp.NewStreamableHTTPHandler(m.unified, &mcp.StreamableHTTPOptions{Stateless: true}),
	}
	go func() { log.Fatal(server.Serve(m.gateway)) }()
}

func (m *monitor) connectMCP(st *state, name string, s *mcpServer) error {
	ctx, cancel := context.WithTimeout(context.Background(), connector.DialTimeout)
	defer cancel()
	session, err := dialMCP(ctx, st.Dialer, s)
	if err != nil {
		return err
	}
	u, err := sentinel.NewUpstream(ctx, name, session, st.cfg.Pins[name])
	if err != nil {
		session.Close()
		return err
	}
	s.upstream.Store(u)
	return nil
}

func (s *mcpServer) close() {
	if u := s.upstream.Load(); u != nil {
		u.Close()
	}
}

func dialMCP(ctx context.Context, d *net.Dialer, s *mcpServer) (*mcp.ClientSession, error) {
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.Proxy = nil
	transport.DialContext = d.DialContext
	client := &http.Client{Transport: transport}
	if s.Token != nil {
		client.Transport = bearer{s.Token, transport}
	}
	return mcp.NewClient(&mcp.Implementation{Name: "monitor", Version: sentinel.Version}, nil).
		Connect(ctx, &mcp.StreamableClientTransport{Endpoint: s.URL, HTTPClient: client}, nil)
}

// unified is built per request, so tools/list never shows a principal a server it does not reach.
func (m *monitor) unified(r *http.Request) *mcp.Server {
	p := r.Context().Value(principalKey{}).(principal)
	server := mcp.NewServer(&mcp.Implementation{Name: "monitor", Version: sentinel.Version}, nil)
	for name, s := range m.live.Load().mcp {
		if u := s.upstream.Load(); u != nil && p.reaches(s.account) {
			u.Register(server, name+toolSeparator, func(ctx context.Context, t *mcp.Tool, args json.RawMessage) error {
				layer := &connector.MCPLayer{Tool: t.Name, Arguments: args, ReadOnly: t.Annotations != nil && t.Annotations.ReadOnlyHint}
				return m.gate(ctx, input{Principal: p, Connection: name, Protocol: protocolMCP, Event: &connector.Event{MCP: layer}}, s.account)
			})
		}
	}
	return server
}

type review struct {
	Changes []string           `json:"changes"`
	Pin     *sentinel.Snapshot `json:"pin"`
}

// review shows how the server's tools differ from its pin; patching pins with Pin approves them.
func (m *monitor) review(ctx context.Context, name string) (*review, error) {
	st := m.live.Load()
	s := st.mcp[name]
	if s == nil {
		return nil, fmt.Errorf("no mcp server %s", name)
	}
	ctx, cancel := context.WithTimeout(ctx, connector.DialTimeout)
	defer cancel()
	session, err := dialMCP(ctx, st.Dialer, s)
	if err != nil {
		return nil, err
	}
	defer session.Close()
	cur, err := sentinel.Inspect(ctx, session)
	if err != nil {
		return nil, err
	}
	return &review{st.cfg.Pins[name].Diff(cur), cur}, nil
}
