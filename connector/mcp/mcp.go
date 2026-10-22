package mcp

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"net"
	"net/http"
	"net/url"
	"slices"

	sdk "github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/tinfoilsh/monitor/connector"
	"github.com/tinfoilsh/monitor/connector/credential"
	"github.com/tinfoilsh/monitor/facts"
	sentinel "github.com/tinfoilsh/monitor/internal/sentinel"
)

var Definition = connector.Definition{NewConfig: func() connector.Server { return new(Server) }, Requests: []connector.Request{new(Request)}}

type Server struct {
	connector.SecretConfig
	URL      string             `json:"url"`
	Pin      *sentinel.Snapshot `json:"pin"`
	upstream *sentinel.Upstream
	current  *sentinel.Snapshot
}

func (c *Server) UnmarshalJSON(raw []byte) error {
	type plain Server
	if err := facts.DecodeNumbers(raw, (*plain)(c)); err != nil {
		return err
	}
	return c.Validate()
}

func (c *Server) Validate() error {
	u, err := connector.ParseURL(c.URL)
	if err != nil || u.Scheme != "http" && u.Scheme != "https" {
		return errors.New("MCP requires an http:// or https:// server URL")
	}
	return nil
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

func (m *Server) Run(ctx context.Context, e *connector.Env, serve func(context.Context)) error {
	client := e.Client()
	defer client.Transport.(*http.Transport).CloseIdleConnections()
	return m.RunWithClient(ctx, client, serve)
}

// RunWithClient uses a caller-owned transport. Tools must match the owner's pin,
// and each call still passes the policy gate.
func (m *Server) RunWithClient(ctx context.Context, client *http.Client, serve func(context.Context)) error {
	if err := m.connect(ctx, client); err != nil {
		return err
	}
	defer m.upstream.Close()
	serve(ctx)
	return nil
}

// Serve builds a server per request, so each call is screened by the stream's gate.
// SSH admission authenticates these streams; worker transport addresses are internal.
func (m *Server) Serve(s *connector.Stream, e *connector.Env) {
	var c net.Conn = s
	if s.Port == 443 {
		c = tls.Server(s, e.TLS)
	}
	connector.ServeHTTP(s, c, sdk.NewStreamableHTTPHandler(func(*http.Request) *sdk.Server {
		server := sdk.NewServer(&sdk.Implementation{Name: "monitor", Version: sentinel.Version}, &sdk.ServerOptions{Instructions: m.upstream.Instructions})
		m.upstream.Register(server, "", func(ctx context.Context, t *sdk.Tool, args json.RawMessage) error {
			return s.Gate(ctx, &Request{Tool: t.Name, Arguments: args, ReadOnly: t.Annotations != nil && t.Annotations.ReadOnlyHint})
		})
		return server
	}, &sdk.StreamableHTTPOptions{Stateless: true, PropagateRequestCancellation: true, DisableLocalhostProtection: true}))
}

func (m *Server) connect(ctx context.Context, client *http.Client) error {
	ctx, cancel := context.WithTimeout(ctx, connector.DialTimeout)
	defer cancel()
	if token := m.Secrets["token"]; token != nil && len(token.Raw()) > 0 {
		if u, err := url.Parse(m.URL); err != nil || u.Scheme != "https" {
			return errors.New("an MCP token needs an https server URL")
		}
		client.Transport = bearer{token, client.Transport}
	}
	session, err := sdk.NewClient(&sdk.Implementation{Name: "monitor", Version: sentinel.Version}, nil).
		Connect(ctx, &sdk.StreamableClientTransport{Endpoint: m.URL, HTTPClient: client}, nil)
	if err != nil {
		return err
	}
	cur, err := sentinel.Inspect(ctx, session)
	if err != nil {
		session.Close()
		return err
	}
	m.current = cur
	m.upstream = sentinel.NewUpstream(m.URL, session, m.Pin, cur)
	return nil
}

func (m *Server) Details() json.RawMessage {
	status := map[string]any{"blocked": m.upstream.Blocked}
	if m.upstream.Blocked > 0 {
		status["changes"], status["pin"] = m.Pin.Diff(m.current), m.current
	}
	raw, _ := json.Marshal(status)
	return raw
}

type Request struct {
	Tool      string          `json:"tool"`
	Arguments json.RawMessage `json:"arguments"`
	ReadOnly  bool            `json:"read_only"`
}

func (r *Request) Describe(c connector.Context) (facts.Facts, error) {
	f := facts.Facts{Details: facts.Details{MCP: &facts.MCP{Tool: r.Tool, Arguments: r.Arguments, ReadOnly: r.ReadOnly}}, Title: "Use " + r.Tool}
	action := "use." + r.Tool
	if r.ReadOnly {
		action = "read." + r.Tool
	}
	var args any
	if err := facts.DecodeNumbers(r.Arguments, &args); err != nil {
		return f, err
	}
	f.Parameters = map[string]any{"arguments": args}
	f.Details.MCP.Arguments = args
	f.Operation = &facts.Operation{Action: action}
	if p, _ := c.Spec.(*Preset); p != nil {
		scope, err := p.scope.Select(args)
		maps.Copy(f.Parameters, scope)
		f.Definition = p.definition
		f.Context.Sends = p.Sends
		if p.Observes != nil {
			f.Context.Observes = *p.Observes
		}
		return f, err
	}
	return f, nil
}

// Preset selects service resource identifiers from tool arguments.
type Preset struct {
	Scope      map[string]Selector `json:"scope,omitempty"`
	Sends      string              `json:"sends,omitempty"`
	Observes   *facts.Label        `json:"observes,omitempty"`
	scope      selectors
	definition json.RawMessage
}

func (p *Preset) UnmarshalJSON(raw []byte) error {
	type plain Preset
	err := facts.DecodeNumbers(raw, (*plain)(p))
	if err == nil && (!slices.Contains([]string{"", "me", "team", "anyone", "account"}, p.Sends) || p.Observes != nil && !p.Observes.Valid()) {
		return errors.New("invalid MCP data-flow settings")
	}
	if err == nil {
		p.scope, err = compileSelectors(p.Scope)
	}
	if err == nil {
		p.definition, err = json.Marshal((*plain)(p))
	}
	return err
}

// Selector selects a typed value from a JSON document.
type Selector struct {
	At       string `json:"at"`
	Type     string `json:"type,omitempty"`
	Optional bool   `json:"optional,omitempty"`
}

type compiledSelector struct {
	name string
	Selector
	read func(any) (any, bool)
}

// selectors keeps compiled MCP scope entries in name order.
type selectors []compiledSelector

func compileSelectors(specs map[string]Selector) (selectors, error) {
	out := make(selectors, 0, len(specs))
	for _, name := range slices.Sorted(maps.Keys(specs)) {
		spec := specs[name]
		if !connector.ValidJSONType(spec.Type) {
			return nil, fmt.Errorf("invalid selector type %q", spec.Type)
		}
		read, err := connector.CompilePointer(spec.At)
		if err != nil {
			return nil, err
		}
		out = append(out, compiledSelector{name: name, Selector: spec, read: read})
	}
	return out, nil
}

func (scope selectors) Select(doc any) (map[string]any, error) {
	out := make(map[string]any, len(scope))
	var errs []error
	for _, spec := range scope {
		value, present := spec.read(doc)
		if err := connector.CheckSelection(spec.name, value, present, spec.Type, spec.Optional); err != nil {
			errs = append(errs, err)
		} else if present {
			out[spec.name] = value
		}
	}
	return out, errors.Join(errs...)
}
