package mcp

import (
	"context"
	"encoding/json"
	"errors"
	"maps"
	"net/http"
	"net/url"
	"slices"

	sdk "github.com/modelcontextprotocol/go-sdk/mcp"
	sentinel "github.com/tinfoilsh/mcp-sentinel"
	"github.com/tinfoilsh/monitor/connector"
	"github.com/tinfoilsh/monitor/connector/credential"
	"github.com/tinfoilsh/monitor/facts"
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
	resp, err := b.base.RoundTrip(r)
	if err != nil {
		// The error may quote the authenticated request.
		if ctxErr := r.Context().Err(); ctxErr != nil {
			return nil, ctxErr
		}
		return nil, errors.New("the MCP request failed")
	}
	return resp, nil
}

func (m *Server) Run(ctx context.Context, e *connector.Env, in *connector.Listener, ready func()) error {
	client := e.Client()
	defer client.CloseIdleConnections()
	if err := m.connect(ctx, client); err != nil {
		return err
	}
	defer m.upstream.Close()
	return connector.ServeHTTP(ctx, in, ready, sdk.NewStreamableHTTPHandler(m.serve, &sdk.StreamableHTTPOptions{Stateless: true}))
}

func (m *Server) connect(ctx context.Context, client *http.Client) error {
	ctx, cancel := context.WithTimeout(ctx, connector.DialTimeout)
	defer cancel()
	if len(m.Token.Raw()) > 0 {
		if u, err := url.Parse(m.URL); err != nil || u.Scheme != "https" {
			return errors.New("an MCP token needs an https server URL")
		}
		client.Transport = bearer{&m.Token, client.Transport}
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
	server := sdk.NewServer(&sdk.Implementation{Name: "monitor", Version: sentinel.Version}, nil)
	m.Register(server, "", connector.RequestStream(r).Gate)
	return server
}

// Register adds the pinned tools under prefix; the gate sees each tool's own name.
func (m *Server) Register(server *sdk.Server, prefix string, gate func(connector.Request) error) {
	m.upstream.Register(server, prefix, func(_ context.Context, t *sdk.Tool, args json.RawMessage) error {
		return gate(&Request{Tool: t.Name, Arguments: args, ReadOnly: t.Annotations != nil && t.Annotations.ReadOnlyHint})
	})
}

func (m *Server) Instructions() string { return m.upstream.Instructions }

type Request struct {
	Tool      string          `json:"tool"`
	Arguments json.RawMessage `json:"arguments"`
	ReadOnly  bool            `json:"read_only"`
}

func (r *Request) Describe(c connector.Context) (facts.Facts, connector.Approval, error) {
	f := facts.Facts{Details: facts.Details{MCP: &facts.MCP{Tool: r.Tool, Arguments: r.Arguments, ReadOnly: r.ReadOnly}}, Title: "Use " + r.Tool}
	action := "use." + r.Tool
	if r.ReadOnly {
		action = "read." + r.Tool
	}
	var args any
	if err := connector.DecodeNumbers(r.Arguments, &args); err != nil {
		return f, connector.Approval{}, err
	}
	f.Parameters = map[string]any{"arguments": args}
	f.Details.MCP.Arguments = args
	f.Operation = &facts.Operation{Action: action, RequiresTrust: !r.ReadOnly}
	var approval connector.Approval
	if p, _ := c.Specs["mcp"].(*Preset); p != nil {
		if p.definition == nil {
			copy := *p
			if err := copy.Validate(); err != nil {
				return f, approval, err
			}
			p = &copy
		}
		var errs []error
		for _, name := range p.names {
			spec := p.Scope[name]
			value, present := spec.Read(args)
			if err := connector.CheckSelection(name, value, present, spec.Type, spec.Optional); err != nil {
				errs = append(errs, err)
			} else if present {
				f.Parameters[name] = value
			}
		}
		approval.Definition = p.definition
		return f, approval, errors.Join(errs...)
	}
	return f, approval, nil
}

// Preset selects service resource identifiers from tool arguments.
type Preset struct {
	Scope      map[string]connector.JSONSelector `json:"scope,omitempty"`
	names      []string
	definition json.RawMessage
}

func (p *Preset) Validate() error {
	scope := maps.Clone(p.Scope)
	for name, spec := range scope {
		compiled, err := spec.Compile()
		if err != nil {
			return err
		}
		scope[name] = compiled
	}
	definition, err := json.Marshal(p)
	if err != nil {
		return err
	}
	p.Scope, p.names, p.definition = scope, slices.Sorted(maps.Keys(scope)), definition
	return nil
}
