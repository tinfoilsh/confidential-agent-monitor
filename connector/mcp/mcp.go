package mcp

import (
	"context"
	"encoding/json"
	"net/http"

	sdk "github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/tinfoilsh/mcp-sentinel"
	"github.com/tinfoilsh/monitor/connector"
	"github.com/tinfoilsh/monitor/connector/credential"
)

type Server struct {
	Token    credential.Value   `json:"token"`
	URL      string             `json:"url"`
	Pin      *sentinel.Snapshot `json:"pin"`
	upstream *sentinel.Upstream
	current  *sentinel.Snapshot
}

func (m *Server) Fields() []connector.Field {
	return []connector.Field{{Path: []string{"token"}, Value: &m.Token, Redact: true}}
}

// bearer asks the credential on every request, so a refreshed token replaces an expired one.
type bearer struct {
	token *credential.Value
	base  http.RoundTripper
}

func (b bearer) RoundTrip(r *http.Request) (*http.Response, error) {
	token, err := b.token.Value(r.Context())
	if err != nil {
		return nil, err
	}
	r = r.Clone(r.Context())
	r.Header.Set("Authorization", "Bearer "+token)
	return b.base.RoundTrip(r)
}

func (m *Server) Run(ctx context.Context, e *connector.Env, in *connector.Listener, ready func()) error {
	transport := e.Transport()
	defer transport.CloseIdleConnections()
	if err := m.connect(ctx, transport); err != nil {
		return err
	}
	defer m.upstream.Close()
	return connector.ServeHTTP(ctx, in, ready, sdk.NewStreamableHTTPHandler(m.serve, &sdk.StreamableHTTPOptions{Stateless: true}))
}

func (m *Server) connect(ctx context.Context, transport *http.Transport) error {
	ctx, cancel := context.WithTimeout(ctx, connector.DialTimeout)
	defer cancel()
	client := &http.Client{Transport: transport}
	if len(m.Token.Raw()) > 0 {
		client.Transport = bearer{&m.Token, transport}
	}
	session, err := sdk.NewClient(&sdk.Implementation{Name: "monitor", Version: sentinel.Version}, nil).
		Connect(ctx, &sdk.StreamableClientTransport{Endpoint: m.URL, HTTPClient: client}, nil)
	if err != nil {
		return err
	}
	// The review needs its own snapshot, since NewUpstream keeps none and edits the tools it inspects.
	cur, err := sentinel.Inspect(ctx, session)
	if err == nil {
		m.upstream, err = sentinel.NewUpstream(ctx, m.URL, session, m.Pin)
	}
	if err != nil {
		session.Close()
		return err
	}
	m.current = cur
	return nil
}

func (m *Server) Status() any {
	status := map[string]any{"state": "ready", "blocked": m.upstream.Blocked}
	if m.upstream.Blocked > 0 {
		status["changes"], status["pin"] = m.Pin.Diff(m.current), m.current
	}
	return status
}

// serve builds a server per request, so each call is screened by the gate of the stream it arrived on.
func (m *Server) serve(r *http.Request) *sdk.Server {
	s := connector.RequestStream(r)
	server := sdk.NewServer(&sdk.Implementation{Name: "monitor", Version: sentinel.Version}, nil)
	m.upstream.Register(server, "", func(_ context.Context, t *sdk.Tool, args json.RawMessage) error {
		return s.Gate(connector.Event{MCP: &connector.MCPLayer{Tool: t.Name, Arguments: args, ReadOnly: t.Annotations != nil && t.Annotations.ReadOnlyHint}})
	})
	return server
}
