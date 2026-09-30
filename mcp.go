package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
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
	pinSuffix         = ".pin.json"
	readHeaderTimeout = 30 * time.Second
)

type mcpServer struct {
	URL      string                 `yaml:"url"`
	Token    *credential.Credential `yaml:"token"`
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
	for name, s := range m.mcp {
		go func() {
			if err := m.connectMCP(name, s); err != nil {
				log.Printf("%s: %v", name, err)
			}
		}()
	}
	server := &http.Server{
		ReadHeaderTimeout: readHeaderTimeout,
		ConnContext: func(ctx context.Context, c net.Conn) context.Context {
			return context.WithValue(ctx, principalKey{}, connector.StreamOf(c).Conn.(channelConn).principal)
		},
		Handler: mcp.NewStreamableHTTPHandler(m.unified, &mcp.StreamableHTTPOptions{Stateless: true}),
	}
	go func() { log.Fatal(server.Serve(m.gateway)) }()
}

func (m *monitor) connectMCP(name string, s *mcpServer) error {
	ctx, cancel := context.WithTimeout(context.Background(), connector.DialTimeout)
	defer cancel()
	pin, err := m.readPin(name)
	if err != nil {
		return err
	}
	session, err := m.dialMCP(ctx, s)
	if err != nil {
		return err
	}
	u, err := sentinel.NewUpstream(ctx, name, session, pin, func() *sentinel.Policy { return m.policy })
	if err != nil {
		session.Close()
		return err
	}
	s.upstream.Store(u)
	return nil
}

func (m *monitor) dialMCP(ctx context.Context, s *mcpServer) (*mcp.ClientSession, error) {
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.Proxy = nil
	transport.DialContext = m.Dialer.DialContext
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
	for name, s := range m.mcp {
		if u := s.upstream.Load(); u != nil && p.reaches(name) {
			u.Register(server, name+toolSeparator, map[string]any{"principal": p, "connection": name, "protocol": protocolMCP})
		}
	}
	return server
}

// pin shows how the server's tools differ from its pin and pins them as they are once the owner agrees.
func (m *monitor) pin(name string) error {
	s := m.mcp[name]
	if s == nil {
		return fmt.Errorf("no mcp server %s", name)
	}
	old, err := m.readPin(name)
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), connector.DialTimeout)
	defer cancel()
	session, err := m.dialMCP(ctx, s)
	if err != nil {
		return err
	}
	defer session.Close()
	cur, err := sentinel.Inspect(ctx, session)
	if err != nil {
		return err
	}
	changes := old.Diff(cur)
	if len(changes) == 0 {
		fmt.Println("the pin matches the server")
		return nil
	}
	fmt.Println(strings.Join(changes, "\n"))
	fmt.Print("pin these tools? [y/N] ")
	var answer string
	fmt.Scanln(&answer)
	if answer != "y" {
		return errors.New("not pinned")
	}
	raw, err := json.MarshalIndent(cur, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(m.state, name+pinSuffix), raw, secretMode)
}

// A server with no pin exposes no tools.
func (m *monitor) readPin(name string) (*sentinel.Snapshot, error) {
	raw, err := os.ReadFile(filepath.Join(m.state, name+pinSuffix))
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	pin := &sentinel.Snapshot{}
	return pin, json.Unmarshal(raw, pin)
}
