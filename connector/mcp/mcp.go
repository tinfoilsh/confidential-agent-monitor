package mcp

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
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
	connector.SecretConfig
	URL      string             `json:"url"`
	Pin      *sentinel.Snapshot `json:"pin"`
	upstream *sentinel.Upstream
	current  *sentinel.Snapshot
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

func (m *Server) Run(ctx context.Context, e *connector.Env, serve func()) error {
	client := e.Client()
	defer client.CloseIdleConnections()
	if err := m.connect(ctx, client); err != nil {
		return err
	}
	defer m.upstream.Close()
	serve()
	return nil
}

// Serve builds a server per request, so each call is screened by the stream's gate.
func (m *Server) Serve(s *connector.Stream, _ *connector.Env) {
	connector.ServeHTTP(s, s, sdk.NewStreamableHTTPHandler(func(*http.Request) *sdk.Server {
		server := sdk.NewServer(&sdk.Implementation{Name: "monitor", Version: sentinel.Version}, nil)
		m.Register(server, "", s.Gate)
		return server
	}, &sdk.StreamableHTTPOptions{Stateless: true}))
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

func (m *Server) Status() any {
	status := map[string]any{"blocked": m.upstream.Blocked}
	if m.upstream.Blocked > 0 {
		status["changes"], status["pin"] = m.Pin.Diff(m.current), m.current
	}
	return status
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
		return f, err
	}
	return f, nil
}

// Preset selects service resource identifiers from tool arguments.
type Preset struct {
	Scope      map[string]Selector `json:"scope,omitempty"`
	scope      selectors
	definition json.RawMessage
}

func (p *Preset) UnmarshalJSON(raw []byte) error {
	type plain Preset
	err := facts.DecodeNumbers(raw, (*plain)(p))
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
