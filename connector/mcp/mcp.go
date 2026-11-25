package mcp

import (
	"cmp"
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
	"github.com/tinfoilsh/confidential-agent-monitor/connector/catalog"
	"github.com/tinfoilsh/confidential-agent-monitor/core/connector"
	"github.com/tinfoilsh/confidential-agent-monitor/core/facts"
	"github.com/tinfoilsh/confidential-agent-monitor/core/transport/netx"
)

const basicUser = "user"

var (
	errURL             = errors.New("MCP requires an http:// or https:// server URL")
	bearerToken        = &Placement{Header: "Authorization", Prefix: "Bearer "}
	destructiveEffects = []string{"delete"}
)

type Setup struct {
	URL    string    `json:"url"`
	Pin    *Snapshot `json:"pin"`
	Preset *Preset   `json:"-"`

	actions map[string]catalogAction
}

type catalogAction struct {
	Effects []string `json:"effects"`
}

type Client struct {
	HTTP    *http.Client
	Token   func(context.Context) (string, error)
	Place   *Placement
	Expose  func(current *Snapshot) (tools []*sdk.Tool, instructions string)
	Timeout time.Duration
	TLS     func(ctx context.Context, host string) *tls.Config

	Name, Version string
}

func (c Client) info() *sdk.Implementation {
	return &sdk.Implementation{Name: c.Name, Version: c.Version}
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
		MCP     *Preset `json:"mcp"`
		Catalog struct {
			Actions map[string]catalogAction `json:"actions"`
		} `json:"catalog"`
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
	setup.Preset, setup.actions = preset.MCP, preset.Catalog.Actions
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
	place *Placement
	base  http.RoundTripper
}

func (b bearer) RoundTrip(r *http.Request) (*http.Response, error) {
	token, err := b.token(r.Context())
	if err != nil {
		return nil, err
	}
	r = r.Clone(r.Context())
	switch p := cmp.Or(b.place, bearerToken); {
	case p.Header != "":
		r.Header.Set(p.Header, p.Prefix+token)
	case p.Query != "":
		query := r.URL.Query()
		query.Set(p.Query, token)
		r.URL.RawQuery = query.Encode()
	case p.Basic == basicUser:
		r.SetBasicAuth(token, "")
	default:
		r.SetBasicAuth("", token)
	}
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

func (m *Session) Serve(ctx context.Context, conn net.Conn, _ string, target connector.Target, gate connector.Gate) {
	c := conn
	if target.Port == 443 {
		c = tls.Server(conn, m.client.TLS(ctx, target.Host))
	}
	netx.ServeConn(ctx, c, &http.Server{Handler: sdk.NewStreamableHTTPHandler(func(*http.Request) *sdk.Server {
		server := sdk.NewServer(m.client.info(), &sdk.ServerOptions{Instructions: m.instructions})
		for _, t := range m.tools {
			server.AddTool(t, func(ctx context.Context, req *sdk.CallToolRequest) (*sdk.CallToolResult, error) {
				readOnly, destructive := toolHints(t)
				if err := gate(ctx, facts.Capture((&Request{Tool: t.Name, Arguments: req.Params.Arguments, ReadOnly: readOnly, Destructive: destructive}).Describe(m.setup))); err != nil {
					log.Printf("%s: blocked %s: %v", m.setup.URL, t.Name, err)
					return &sdk.CallToolResult{IsError: true, Content: []sdk.Content{&sdk.TextContent{Text: "blocked by policy: " + err.Error()}}}, nil
				}
				return m.session.CallTool(ctx, &sdk.CallToolParams{Name: t.Name, Arguments: req.Params.Arguments})
			})
		}
		return server
	}, &sdk.StreamableHTTPOptions{Stateless: true, PropagateRequestCancellation: true, DisableLocalhostProtection: true})})
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
		authorized.Transport = bearer{m.client.Token, m.client.Place, client.Transport}
		client = &authorized
	}
	session, err := sdk.NewClient(m.client.info(), nil).
		Connect(ctx, &sdk.StreamableClientTransport{Endpoint: m.setup.URL, HTTPClient: client, DisableStandaloneSSE: true}, nil)
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
	Tool        string          `json:"tool"`
	Arguments   json.RawMessage `json:"arguments"`
	ReadOnly    bool            `json:"read_only"`
	Destructive bool            `json:"destructive"`
}

func (r *Request) Describe(s *Setup) (facts.Observation, error) {
	f := facts.Observation{Details: Details{MCP: &MCPFacts{Tool: r.Tool, Arguments: r.Arguments, ReadOnly: r.ReadOnly}}, Title: "Use " + r.Tool}
	var args any
	if err := facts.DecodeNumbers(r.Arguments, &args); err != nil {
		return f, err
	}
	f.Parameters = map[string]any{"arguments": args}
	f.Details.(Details).MCP.Arguments = args
	f.Operation = toolOperation(r.Tool, r.ReadOnly, r.Destructive, s.actions)
	if p := s.Preset; p != nil {
		scope, err := facts.Select(p.scope, args)
		maps.Copy(f.Parameters, scope)
		f.Scope = facts.Project(scope, p.Grant)
		return f, err
	}
	return f, nil
}

func toolHints(t *sdk.Tool) (readOnly, destructive bool) {
	hints := cmp.Or(t.Annotations, &sdk.ToolAnnotations{})
	return hints.ReadOnlyHint, hints.DestructiveHint != nil && *hints.DestructiveHint
}

// A tool sits under read or use by its read-only hint; a destructive one deletes unless the catalog states its action's effects.
func toolOperation(tool string, readOnly, destructive bool, actions map[string]catalogAction) *facts.Operation {
	op := &facts.Operation{Action: "use." + tool}
	if readOnly {
		op.Action = "read." + tool
	}
	if destructive && !readOnly && actions[op.Action].Effects == nil {
		op.Effects = destructiveEffects
	}
	return op
}

func Operations(config, definition json.RawMessage) (map[string]catalog.OperationSummary, error) {
	var setup struct {
		Pin Snapshot `json:"pin"`
	}
	var preset struct {
		Catalog struct {
			Actions map[string]catalogAction `json:"actions"`
		} `json:"catalog"`
	}
	if err := errors.Join(json.Unmarshal(config, &setup), json.Unmarshal(definition, &preset)); err != nil {
		return nil, err
	}
	ops := map[string]catalog.OperationSummary{}
	for _, t := range setup.Pin.Tools {
		readOnly, destructive := toolHints(t)
		op := toolOperation(t.Name, readOnly, destructive, preset.Catalog.Actions)
		ops[op.Action] = catalog.OperationSummary{Action: op.Action, Title: cmp.Or(t.Title, t.Name), Effects: op.Effects}
	}
	return ops, nil
}

type Preset struct {
	Scope    map[string]facts.Selector `json:"scope,omitempty"`
	Grant    []string                  `json:"grant,omitempty"`
	Sends    json.RawMessage           `json:"sends,omitempty"`
	Observes json.RawMessage           `json:"observes,omitempty"`
	Token    *Placement                `json:"token,omitempty"`
	scope    []facts.Compiled
}

type Placement struct {
	Header string `json:"header,omitempty"`
	Prefix string `json:"prefix,omitempty"`
	Query  string `json:"query,omitempty"`
	Basic  string `json:"basic,omitempty"`
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
