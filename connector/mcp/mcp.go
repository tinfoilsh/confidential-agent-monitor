package mcp

import (
	"context"
	"encoding/json"
	"log"
	"net"
	"net/http"
	"time"

	sdk "github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/tinfoilsh/mcp-sentinel"
	"github.com/tinfoilsh/monitor/connector"
	"github.com/tinfoilsh/monitor/connector/credential"
)

const readHeaderTimeout = 30 * time.Second

type Server struct {
	URL      string                 `json:"url"`
	Token    *credential.Credential `json:"token"`
	Pin      *sentinel.Snapshot     `json:"pin"`
	conns    *connector.Listener
	server   *http.Server
	upstream *sentinel.Upstream
	status   status
}

func (*Server) CredentialFields() []string { return []string{"token"} }

// Approving the tools that await review means patching the connection's pin with Pin.
type status struct {
	State   string             `json:"state"`
	Error   string             `json:"error,omitempty"`
	Blocked int                `json:"blocked"`
	Changes []string           `json:"changes,omitempty"`
	Pin     *sentinel.Snapshot `json:"pin,omitempty"`
}

type streamKey struct{}

// bearer asks the credential on every request, so a refreshed token replaces an expired one.
type bearer struct {
	token       *credential.Credential
	credentials credential.Store
	base        http.RoundTripper
}

func (b bearer) RoundTrip(r *http.Request) (*http.Response, error) {
	token, err := b.token.Value(r.Context(), b.credentials)
	if err != nil {
		return nil, err
	}
	r = r.Clone(r.Context())
	r.Header.Set("Authorization", "Bearer "+token)
	return b.base.RoundTrip(r)
}

func (m *Server) Start(ctx context.Context, e *connector.Env) {
	m.status.State = "ready"
	if err := m.connect(ctx, e); err != nil {
		log.Printf("%s: %v", m.URL, err)
		m.status.State = "error"
		m.status.Error = err.Error()
	}
	m.conns = connector.NewListener()
	handler := sdk.NewStreamableHTTPHandler(m.serve, &sdk.StreamableHTTPOptions{Stateless: true})
	m.server = &http.Server{
		ReadHeaderTimeout: readHeaderTimeout,
		ConnContext: func(ctx context.Context, c net.Conn) context.Context {
			return context.WithValue(ctx, streamKey{}, connector.StreamOf(c))
		},
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if m.status.Error != "" {
				http.Error(w, m.status.Error, http.StatusServiceUnavailable)
				return
			}
			handler.ServeHTTP(w, r)
		}),
	}
	go func() {
		if err := m.server.Serve(m.conns); err != http.ErrServerClosed {
			log.Fatal(err)
		}
	}()
}

func (m *Server) connect(ctx context.Context, e *connector.Env) error {
	ctx, cancel := context.WithTimeout(ctx, connector.DialTimeout)
	defer cancel()
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.Proxy = nil
	transport.DialContext = e.Dialer.DialContext
	client := &http.Client{Transport: transport}
	if m.Token != nil {
		client.Transport = bearer{m.Token, e.Credentials, transport}
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
	if m.status.Blocked = m.upstream.Blocked; m.status.Blocked > 0 {
		m.status.Changes, m.status.Pin = m.Pin.Diff(cur), cur
	}
	return nil
}

func (m *Server) Serve(s *connector.Stream) { m.conns.Hand(s) }

func (m *Server) Stop() {
	m.server.Close()
	if m.upstream != nil {
		m.upstream.Close()
	}
}

func (m *Server) Status() any { return m.status }

// serve builds a server per request, so each call is screened by the gate of the stream it arrived on.
func (m *Server) serve(r *http.Request) *sdk.Server {
	s := r.Context().Value(streamKey{}).(*connector.Stream)
	server := sdk.NewServer(&sdk.Implementation{Name: "monitor", Version: sentinel.Version}, nil)
	if m.upstream != nil {
		m.upstream.Register(server, "", func(_ context.Context, t *sdk.Tool, args json.RawMessage) error {
			return s.Gate(connector.Event{MCP: &connector.MCPLayer{Tool: t.Name, Arguments: args, ReadOnly: t.Annotations != nil && t.Annotations.ReadOnlyHint}})
		})
	}
	return server
}
