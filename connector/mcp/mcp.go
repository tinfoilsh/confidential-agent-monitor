package mcp

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"maps"
	"net"
	"net/http"
	"net/url"
	"slices"
	"sync"
	"sync/atomic"

	sdk "github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/tinfoilsh/monitor/connector"
	"github.com/tinfoilsh/monitor/connector/credential"
	"github.com/tinfoilsh/monitor/connector/jsonsel"
	"github.com/tinfoilsh/monitor/facts"
)

var Kind = connector.Kind{Parse: Parse, New: func() connector.Server { return new(Server) }}

type Setup struct {
	connector.SecretConfig
	URL    string    `json:"url"`
	Pin    *Snapshot `json:"pin"`
	preset *Preset
}

type session struct {
	Setup
	current *Snapshot
	session *sdk.ClientSession
	// tools match the pin exactly; blocked counts the others, which await review.
	tools          []*sdk.Tool
	blocked        int
	instructions   string
	closeTransport func()
}

// ParseSetup lets an attested connector add its own source fields without a
// second decoding path for MCP matching, pins or credential declarations.
func ParseSetup(source connector.Setup, config any, setup *Setup) (connector.Prepared, error) {
	preset := struct {
		*connector.Semantics
		MCP *Preset `json:"mcp"`
	}{Semantics: &setup.Semantics}
	if err := connector.ParseSetup(source, config, &preset, &setup.Semantics); err != nil {
		return connector.Prepared{}, err
	}
	u, err := connector.ParseURL(setup.URL)
	if err != nil || u.Scheme != "http" && u.Scheme != "https" {
		return connector.Prepared{}, errors.New("MCP requires an http:// or https:// server URL")
	}
	setup.preset = preset.MCP
	names, err := setup.Declarations("token")
	return connector.Prepared{Source: source, Value: setup, SecretNames: names}, err
}

func Parse(source connector.Setup) (connector.Prepared, error) {
	setup := new(Setup)
	return ParseSetup(source, setup, setup)
}

// Server owns the SDK session; each request closes over its setup and exact pin.
type Server struct {
	mu      sync.Mutex
	current atomic.Pointer[session]
}

func (s *Server) Update(ctx context.Context, prepared connector.Prepared, secrets map[string]*credential.Value, env *connector.Env) error {
	setup := *prepared.Value.(*Setup)
	setup.Secrets = maps.Clone(secrets)
	client := env.Client()
	return s.UpdateWithClient(ctx, setup, client, client.Transport.(*http.Transport).CloseIdleConnections)
}

// UpdateWithClient owns cleanup after a failed install or after the SDK session closes.
func (s *Server) UpdateWithClient(ctx context.Context, setup Setup, client *http.Client, cleanup func()) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if old := s.current.Swap(nil); old != nil {
		old.Close()
	}
	next := &session{Setup: setup, closeTransport: cleanup}
	if err := next.connect(ctx, client); err != nil {
		next.Close()
		return err
	}
	s.current.Store(next)
	return nil
}

func (s *Server) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if old := s.current.Swap(nil); old != nil {
		return old.Close()
	}
	return nil
}

func (s *Server) Serve(stream *connector.Stream, env *connector.Env) {
	if current := s.current.Load(); current != nil {
		current.serve(stream, env)
	}
}

func (s *Server) Details() json.RawMessage {
	if current := s.current.Load(); current != nil {
		return current.details()
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

func (m *session) Close() error {
	if m.session != nil {
		m.session.Close()
	}
	if m.closeTransport != nil {
		m.closeTransport()
	}
	return nil
}

// Serve builds a server per request, so each call is screened by the stream's gate.
// SSH admission authenticates these streams; worker transport addresses are internal.
func (m *session) serve(s *connector.Stream, e *connector.Env) {
	var c net.Conn = s
	if s.Port == 443 {
		c = tls.Server(s, e.TLS)
	}
	connector.ServeHTTP(s, c, sdk.NewStreamableHTTPHandler(func(*http.Request) *sdk.Server {
		server := sdk.NewServer(&sdk.Implementation{Name: "monitor", Version: Version}, &sdk.ServerOptions{Instructions: m.instructions})
		for _, t := range m.tools {
			server.AddTool(t, func(ctx context.Context, req *sdk.CallToolRequest) (*sdk.CallToolResult, error) {
				if err := s.Gate(ctx, m.Capture((&Request{Tool: t.Name, Arguments: req.Params.Arguments, ReadOnly: t.Annotations != nil && t.Annotations.ReadOnlyHint}).Describe(m.preset))); err != nil {
					log.Printf("%s: blocked %s: %v", m.URL, t.Name, err)
					return &sdk.CallToolResult{IsError: true, Content: []sdk.Content{&sdk.TextContent{Text: "blocked by policy: " + err.Error()}}}, nil
				}
				return m.session.CallTool(ctx, &sdk.CallToolParams{Name: t.Name, Arguments: req.Params.Arguments})
			})
		}
		return server
	}, &sdk.StreamableHTTPOptions{Stateless: true, PropagateRequestCancellation: true, DisableLocalhostProtection: true}))
}

func (m *session) connect(ctx context.Context, client *http.Client) error {
	ctx, cancel := context.WithTimeout(ctx, connector.DialTimeout)
	defer cancel()
	if token := m.Secrets["token"]; token != nil && len(token.Raw()) > 0 {
		if u, err := url.Parse(m.URL); err != nil || u.Scheme != "https" {
			return errors.New("an MCP token needs an https server URL")
		}
		client.Transport = bearer{token, client.Transport}
	}
	session, err := sdk.NewClient(&sdk.Implementation{Name: "monitor", Version: Version}, nil).
		Connect(ctx, &sdk.StreamableClientTransport{Endpoint: m.URL, HTTPClient: client}, nil)
	if err != nil {
		return err
	}
	cur, err := Inspect(ctx, session)
	if err != nil {
		session.Close()
		return err
	}
	var blocked []string
	m.current, m.session = cur, session
	m.tools, blocked = m.Pin.approved(cur)
	m.blocked = len(blocked)
	if len(m.tools) > 0 {
		m.instructions = cur.Instructions
	}
	for i, original := range m.tools {
		t := *original
		m.tools[i] = &t
		schema, _ := t.InputSchema.(map[string]any)
		if schema["type"] != "object" {
			schema = maps.Clone(schema)
			if schema == nil {
				schema = map[string]any{}
			}
			schema["type"] = "object"
			t.InputSchema = schema
		}
	}
	log.Printf("%s: exposing %d of %d tools", m.URL, len(m.tools), len(cur.Tools))
	return nil
}

func (m *session) details() json.RawMessage {
	status := map[string]any{"blocked": m.blocked}
	if m.blocked > 0 {
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

func (r *Request) Describe(p *Preset) (facts.Facts, error) {
	f := facts.Facts{Details: Details{MCP: &MCPFacts{Tool: r.Tool, Arguments: r.Arguments, ReadOnly: r.ReadOnly}}, Title: "Use " + r.Tool}
	action := "use." + r.Tool
	if r.ReadOnly {
		action = "read." + r.Tool
	}
	var args any
	if err := facts.DecodeNumbers(r.Arguments, &args); err != nil {
		return f, err
	}
	f.Parameters = map[string]any{"arguments": args}
	f.Details.(Details).MCP.Arguments = args
	f.Operation = &facts.Operation{Action: action}
	if p != nil {
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
	Scope      map[string]jsonsel.Selector `json:"scope,omitempty"`
	Sends      string                      `json:"sends,omitempty"`
	Observes   *facts.Label                `json:"observes,omitempty"`
	scope      selectors
	definition json.RawMessage
}

func (p *Preset) UnmarshalJSON(raw []byte) error {
	type plain Preset
	err := facts.DecodeNumbers(raw, (*plain)(p))
	if err == nil && (!facts.ValidSends(p.Sends) || p.Observes != nil && !p.Observes.Valid()) {
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

type compiledSelector struct {
	name string
	jsonsel.Selector
	read func(any) (any, bool)
}

// selectors keeps compiled MCP scope entries in name order.
type selectors []compiledSelector

func compileSelectors(specs map[string]jsonsel.Selector) (selectors, error) {
	out := make(selectors, 0, len(specs))
	for _, name := range slices.Sorted(maps.Keys(specs)) {
		spec := specs[name]
		if !spec.Valid() {
			return nil, fmt.Errorf("invalid selector type %q", spec.Type)
		}
		read, err := jsonsel.CompilePointer(spec.At)
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
		if err := spec.Check(spec.name, value, present); err != nil {
			errs = append(errs, err)
		} else if present {
			out[spec.name] = value
		}
	}
	return out, errors.Join(errs...)
}
