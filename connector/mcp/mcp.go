package mcp

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"log"
	"maps"
	"net"
	"net/http"
	"net/url"
	"slices"
	"time"

	sdk "github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/tinfoilsh/confidential-agent-monitor/core/facts"
)

var errURL = errors.New("MCP requires an http:// or https:// server URL")

type Setup struct {
	URL    string    `json:"url"`
	Pin    *Snapshot `json:"pin"`
	Preset *Preset   `json:"-"`
}

type Client struct {
	HTTP      *http.Client
	Token     func(context.Context) (string, error)
	Expose    func(current *Snapshot) (tools []*sdk.Tool, instructions string)
	Timeout   time.Duration
	TLS       func(ctx context.Context, host string) *tls.Config
	ServeHTTP func(ctx context.Context, conn net.Conn, server *http.Server) error

	ClientInfo, ServerInfo *sdk.Implementation
	Streamable             *sdk.StreamableHTTPOptions
}

type Session struct {
	setup        *Setup
	client       Client
	current      *Snapshot
	session      *sdk.ClientSession
	tools        []*sdk.Tool
	instructions string
}

func Parse(config, definition json.RawMessage) (*Setup, error) {
	setup := new(Setup)
	return setup, Decode(config, definition, setup, setup)
}

func Decode(config, definition json.RawMessage, into any, setup *Setup) error {
	if err := facts.DecodeNumbers(config, into); err != nil {
		return err
	}
	var preset struct {
		MCP *Preset `json:"mcp"`
	}
	if len(definition) != 0 {
		if err := json.Unmarshal(definition, &preset); err != nil {
			return err
		}
	}
	u, err := url.Parse(setup.URL)
	if err != nil || u.Scheme != "http" && u.Scheme != "https" || u.Host == "" || u.Query().Has("password") {
		return errURL
	}
	if _, password := u.User.Password(); password {
		return errURL
	}
	setup.Preset = preset.MCP
	return nil
}

func (s *Setup) Hosts() []string {
	u, _ := url.Parse(s.URL)
	return []string{u.Hostname()}
}

func Open(ctx context.Context, setup *Setup, c Client) (*Session, error) {
	next := &Session{setup: setup, client: c}
	if err := next.connect(ctx); err != nil {
		next.Close()
		return nil, err
	}
	return next, nil
}

type bearer struct {
	token func(context.Context) (string, error)
	base  http.RoundTripper
}

func (b bearer) RoundTrip(r *http.Request) (*http.Response, error) {
	token, err := b.token(r.Context())
	if err != nil {
		return nil, err
	}
	r = r.Clone(r.Context())
	r.Header.Set("Authorization", "Bearer "+token)
	resp, err := b.base.RoundTrip(r)
	if err != nil {
		if ctxErr := r.Context().Err(); ctxErr != nil {
			return nil, ctxErr
		}
		return nil, errors.New("the MCP request failed")
	}
	return resp, nil
}

func (m *Session) Close() error {
	if m.session != nil {
		m.session.Close()
	}
	return nil
}

func (m *Session) Snapshot() *Snapshot { return m.current }

func (m *Session) Serve(ctx context.Context, conn net.Conn, _, host string, port uint32, gate func(context.Context, facts.Event) error) {
	c := conn
	if port == 443 {
		c = tls.Server(conn, m.client.TLS(ctx, host))
	}
	m.client.ServeHTTP(ctx, c, &http.Server{Handler: sdk.NewStreamableHTTPHandler(func(*http.Request) *sdk.Server {
		server := sdk.NewServer(m.client.ServerInfo, &sdk.ServerOptions{Instructions: m.instructions})
		for _, t := range m.tools {
			server.AddTool(t, func(ctx context.Context, req *sdk.CallToolRequest) (*sdk.CallToolResult, error) {
				if err := gate(ctx, facts.Capture((&Request{Tool: t.Name, Arguments: req.Params.Arguments, ReadOnly: t.Annotations != nil && t.Annotations.ReadOnlyHint}).Describe(m.setup.Preset))); err != nil {
					log.Printf("%s: blocked %s: %v", m.setup.URL, t.Name, err)
					return &sdk.CallToolResult{IsError: true, Content: []sdk.Content{&sdk.TextContent{Text: "blocked by policy: " + err.Error()}}}, nil
				}
				return m.session.CallTool(ctx, &sdk.CallToolParams{Name: t.Name, Arguments: req.Params.Arguments})
			})
		}
		return server
	}, m.client.Streamable)})
}

func (m *Session) connect(ctx context.Context) error {
	ctx, cancel := context.WithTimeout(ctx, m.client.Timeout)
	defer cancel()
	client := m.client.HTTP
	if m.client.Token != nil {
		if u, err := url.Parse(m.setup.URL); err != nil || u.Scheme != "https" {
			return errors.New("an MCP token needs an https server URL")
		}
		authorized := *client
		authorized.Transport = bearer{m.client.Token, client.Transport}
		client = &authorized
	}
	session, err := sdk.NewClient(m.client.ClientInfo, nil).
		Connect(ctx, &sdk.StreamableClientTransport{Endpoint: m.setup.URL, HTTPClient: client}, nil)
	if err != nil {
		return err
	}
	cur, err := inspect(ctx, session)
	if err != nil {
		session.Close()
		return err
	}
	m.current, m.session = cur, session
	tools, instructions := m.client.Expose(cur)
	m.tools, m.instructions = slices.Clone(tools), instructions
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
	log.Printf("%s: exposing %d of %d tools", m.setup.URL, len(m.tools), len(cur.Tools))
	return nil
}

type Request struct {
	Tool      string          `json:"tool"`
	Arguments json.RawMessage `json:"arguments"`
	ReadOnly  bool            `json:"read_only"`
}

func (r *Request) Describe(p *Preset) (facts.Observation, error) {
	f := facts.Observation{Details: Details{MCP: &MCPFacts{Tool: r.Tool, Arguments: r.Arguments, ReadOnly: r.ReadOnly}}, Title: "Use " + r.Tool}
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
		scope, err := facts.Select(p.scope, args)
		maps.Copy(f.Parameters, scope)
		f.Scope = facts.Project(scope, p.Grant)
		return f, err
	}
	return f, nil
}

type Preset struct {
	Scope    map[string]facts.Selector `json:"scope,omitempty"`
	Grant    []string                  `json:"grant,omitempty"`
	Sends    json.RawMessage           `json:"sends,omitempty"`
	Observes json.RawMessage           `json:"observes,omitempty"`
	scope    []facts.Compiled
}

func (p *Preset) UnmarshalJSON(raw []byte) error {
	type plain Preset
	err := facts.DecodeNumbers(raw, (*plain)(p))
	if err == nil {
		p.scope, err = facts.Compile(p.Scope)
	}
	for _, name := range p.Grant {
		if _, ok := p.Scope[name]; err == nil && !ok {
			err = errors.New("grant names missing scope " + name)
		}
	}
	return err
}
