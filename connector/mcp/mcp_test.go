package mcp_test

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"slices"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	sdk "github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/tinfoilsh/confidential-agent-monitor/connector/mcp"
	"github.com/tinfoilsh/confidential-agent-monitor/core/facts"
	"github.com/tinfoilsh/confidential-agent-monitor/core/transport/netx"
)

type contentTypes struct {
	base http.RoundTripper
	mu   sync.Mutex
	seen []string
}

func (c *contentTypes) RoundTrip(r *http.Request) (*http.Response, error) {
	resp, err := c.base.RoundTrip(r)
	if err == nil && r.Method == http.MethodPost {
		c.mu.Lock()
		c.seen = append(c.seen, resp.Header.Get("Content-Type"))
		c.mu.Unlock()
	}
	return resp, err
}

func TestSessionUsesSuppliedSDKSettingsAndGatesCalls(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
	defer cancel()
	var calls atomic.Int32
	var upstreamClient atomic.Value
	server := sdk.NewServer(&sdk.Implementation{Name: "upstream", Version: "1"}, nil)
	sdk.AddTool(server, &sdk.Tool{Name: "echo"}, func(_ context.Context, req *sdk.CallToolRequest, in struct {
		Text string `json:"text"`
	}) (*sdk.CallToolResult, any, error) {
		calls.Add(1)
		upstreamClient.Store(req.Session.InitializeParams().ClientInfo.Name)
		return &sdk.CallToolResult{Content: []sdk.Content{&sdk.TextContent{Text: in.Text}}}, nil, nil
	})
	upstream := httptest.NewServer(sdk.NewStreamableHTTPHandler(func(*http.Request) *sdk.Server { return server }, nil))
	defer upstream.Close()

	setup, err := mcp.Parse(json.RawMessage(`{"url":"`+upstream.URL+`"}`), nil)
	if err != nil {
		t.Fatal(err)
	}
	session, err := mcp.Open(ctx, setup, mcp.Client{
		HTTP:       upstream.Client(),
		Expose:     func(cur *mcp.Snapshot) ([]*sdk.Tool, string) { return cur.Tools, cur.Instructions },
		Timeout:    10 * time.Second,
		ServeHTTP:  netx.ServeConn,
		ClientInfo: &sdk.Implementation{Name: "custom-client", Version: "7"},
		ServerInfo: &sdk.Implementation{Name: "custom-server", Version: "8"},
		Streamable: &sdk.StreamableHTTPOptions{Stateless: true, JSONResponse: true},
	})
	if err != nil {
		t.Fatal(err)
	}
	defer session.Close()

	var deny atomic.Bool
	gate := func(context.Context, facts.Event) error {
		if deny.Load() {
			return errors.New("denied for test")
		}
		return nil
	}
	recorder := &contentTypes{base: &http.Transport{DialContext: func(context.Context, string, string) (net.Conn, error) {
		agent, stream := net.Pipe()
		go session.Serve(ctx, stream, "", "service.test", 80, gate)
		return agent, nil
	}}}
	agent, err := sdk.NewClient(&sdk.Implementation{Name: "agent", Version: "1"}, nil).Connect(ctx,
		&sdk.StreamableClientTransport{Endpoint: "http://service.test/", HTTPClient: &http.Client{Transport: recorder}}, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer agent.Close()
	if info := agent.InitializeResult().ServerInfo; info.Name != "custom-server" || info.Version != "8" {
		t.Fatalf("agent saw server %+v", info)
	}

	call := &sdk.CallToolParams{Name: "echo", Arguments: map[string]any{"text": "hi"}}
	deny.Store(true)
	if result, err := agent.CallTool(ctx, call); err != nil || !result.IsError || calls.Load() != 0 {
		t.Fatalf("denied call: result=%+v err=%v upstream calls=%d", result, err, calls.Load())
	}
	deny.Store(false)
	result, err := agent.CallTool(ctx, call)
	if err != nil || result.IsError || calls.Load() != 1 || result.Content[0].(*sdk.TextContent).Text != "hi" {
		t.Fatalf("allowed call: result=%+v err=%v upstream calls=%d", result, err, calls.Load())
	}
	if name := upstreamClient.Load(); name != "custom-client" {
		t.Fatalf("upstream saw client %v", name)
	}
	recorder.mu.Lock()
	defer recorder.mu.Unlock()
	if !slices.Contains(recorder.seen, "application/json") || slices.Contains(recorder.seen, "text/event-stream") {
		t.Fatalf("supplied JSONResponse ignored: %q", recorder.seen)
	}
}
