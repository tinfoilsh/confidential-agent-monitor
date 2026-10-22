package tinfoil

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	sdk "github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/tinfoilsh/monitor/connector"
	"github.com/tinfoilsh/monitor/connector/mcp"
	"github.com/tinfoilsh/monitor/connector/rpc"
	"github.com/tinfoilsh/monitor/internal/sentinel"
)

// Exercise the production worker RPC, including its certificate and gate callbacks.
// Only the process launcher is replaced with local listeners.
type testLauncher struct{ t *testing.T }

func (l testLauncher) Start(ctx context.Context, config []byte, callbacks http.Handler) (rpc.Endpoint, error) {
	host := httptest.NewServer(callbacks)
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		host.Close()
		return rpc.Endpoint{}, err
	}
	ctx, cancel := context.WithCancel(ctx)
	dial := func(address string) rpc.DialFunc {
		return func(ctx context.Context) (net.Conn, error) { return (&net.Dialer{}).DialContext(ctx, "tcp", address) }
	}
	done := make(chan struct{})
	go func() {
		defer close(done)
		defer host.Close()
		err := rpc.Serve(ctx, map[string]connector.Definition{"mcp": mcp.Definition}, bytes.NewReader(config), listener, dial(strings.TrimPrefix(host.URL, "http://")))
		if err != nil && ctx.Err() == nil {
			l.t.Errorf("worker failed: %v", err)
		}
	}()
	return rpc.Endpoint{Dial: dial(listener.Addr().String()), Done: done, Close: cancel}, nil
}

func TestMCPHTTPS(t *testing.T) {
	const host = "team-websearch.monitor"
	serverTLS, roots := testTLS(t, host)
	for _, test := range []struct {
		name         string
		port         uint32
		worker, deny bool
	}{
		{name: "HTTPS", port: 443},
		{name: "HTTPS denied", port: 443, deny: true},
		{name: "HTTPS worker", port: 443, worker: true},
		{name: "HTTPS worker denied", port: 443, worker: true, deny: true},
		{name: "existing HTTP", port: 80},
		{name: "existing loopback tunnel", port: 1},
	} {
		t.Run(test.name, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
			defer cancel()
			var calls, gates atomic.Int32
			upstream := sdk.NewServer(&sdk.Implementation{Name: "test-search", Version: "1"}, nil)
			tool := &sdk.Tool{Name: "search", InputSchema: map[string]any{"type": "object"}}
			upstream.AddTool(tool, func(context.Context, *sdk.CallToolRequest) (*sdk.CallToolResult, error) {
				calls.Add(1)
				return &sdk.CallToolResult{Content: []sdk.Content{&sdk.TextContent{Text: "search result"}}}, nil
			})
			endpoint := httptest.NewServer(sdk.NewStreamableHTTPHandler(func(*http.Request) *sdk.Server { return upstream }, &sdk.StreamableHTTPOptions{Stateless: true}))
			defer endpoint.Close()
			pin := &sentinel.Snapshot{Tools: []*sdk.Tool{tool}}
			env := &connector.Env{TLS: serverTLS, Dialer: &net.Dialer{}}
			var server connector.Server
			var run func(context.Context, *connector.Env, func(context.Context)) error
			if test.worker {
				config, err := json.Marshal(map[string]any{"url": endpoint.URL, "pin": pin})
				if err != nil {
					t.Fatal(err)
				}
				proxy := &rpc.Proxy{Kind: "mcp", Config: config, Definition: mcp.Definition, Launcher: testLauncher{t}}
				server, run = proxy, proxy.Run
			} else {
				proxy := &MCP{Server: mcp.Server{URL: endpoint.URL, Pin: pin}}
				server = proxy
				run = func(ctx context.Context, _ *connector.Env, serve func(context.Context)) error {
					return proxy.RunWithClient(ctx, endpoint.Client(), serve)
				}
			}
			ready, done := make(chan struct{}), make(chan error, 1)
			go func() { done <- run(ctx, env, func(ctx context.Context) { close(ready); <-ctx.Done() }) }()
			select {
			case <-ready:
			case err := <-done:
				t.Fatalf("connector failed before readiness: %v", err)
			case <-ctx.Done():
				t.Fatal(ctx.Err())
			}
			t.Cleanup(func() { cancel(); <-done })
			var streams sync.WaitGroup
			transport := &http.Transport{TLSClientConfig: &tls.Config{RootCAs: roots}, DialContext: func(context.Context, string, string) (net.Conn, error) {
				client, peer := net.Pipe()
				stream := connector.NewStream(ctx, peer)
				stream.Name, stream.Port = "team-websearch", test.port
				stream.Gate = func(_ context.Context, request connector.Request) error {
					gates.Add(1)
					if request.(*mcp.Request).Tool != "search" {
						t.Error("policy gate received the wrong tool")
					}
					if test.deny {
						return errors.New("search denied")
					}
					return nil
				}
				streams.Add(1)
				go func() { defer streams.Done(); defer stream.Close(); server.Serve(stream, env) }()
				return client, nil
			}}
			t.Cleanup(func() { transport.CloseIdleConnections(); cancel(); streams.Wait() })
			scheme := "http"
			if test.port == 443 {
				scheme = "https"
			}
			client := sdk.NewClient(&sdk.Implementation{Name: "test-client", Version: "1"}, nil)
			session, err := client.Connect(ctx, &sdk.StreamableClientTransport{Endpoint: scheme + "://" + host + "/mcp", HTTPClient: &http.Client{Transport: transport}}, nil)
			if err != nil {
				t.Fatal(err)
			}
			defer session.Close()
			tools, err := session.ListTools(ctx, nil)
			if err != nil || len(tools.Tools) != 1 || tools.Tools[0].Name != "search" {
				t.Fatalf("approved tools were not exposed: %v", err)
			}
			result, err := session.CallTool(ctx, &sdk.CallToolParams{Name: "search", Arguments: map[string]any{}})
			if err != nil || result.IsError != test.deny || gates.Load() != 1 {
				t.Fatalf("tool call did not respect policy: result=%v, err=%v, gates=%d", result, err, gates.Load())
			}
			wantCalls := int32(1)
			if test.deny {
				wantCalls = 0
			}
			if calls.Load() != wantCalls {
				t.Fatalf("upstream calls = %d, want %d", calls.Load(), wantCalls)
			}
		})
	}
}
