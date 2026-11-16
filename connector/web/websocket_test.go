package web_test

import (
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/coder/websocket"
	"github.com/tinfoilsh/confidential-agent-monitor/connector/web"
	"github.com/tinfoilsh/confidential-agent-monitor/core/facts"
	"github.com/tinfoilsh/confidential-agent-monitor/core/transport/netx"
)

func TestWebSocketAcceptOptionsAndUpstreamReadLimit(t *testing.T) {
	const kib = 1 << 10
	for _, c := range []struct {
		name      string
		accept    websocket.AcceptOptions
		origin    string
		limit     int64
		size      int
		delivered bool
	}{
		{name: "at limit", limit: kib, size: kib, delivered: true},
		{name: "over limit", limit: kib, size: kib + 1},
		{name: "unbounded beyond native default", limit: -1, size: 64 * kib, delivered: true},
		{name: "cross-origin refused by default", origin: "https://elsewhere.test", limit: -1, size: 1},
		{name: "cross-origin allowed by options", accept: websocket.AcceptOptions{OriginPatterns: []string{"elsewhere.test"}}, origin: "https://elsewhere.test", limit: -1, size: 1, delivered: true},
	} {
		t.Run(c.name, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
			defer cancel()
			payload := strings.Repeat("x", c.size)
			upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				conn, err := websocket.Accept(w, r, &websocket.AcceptOptions{InsecureSkipVerify: true})
				if err != nil {
					return
				}
				defer conn.CloseNow()
				conn.Write(r.Context(), websocket.MessageText, []byte(payload))
				conn.Read(r.Context())
			}))
			defer upstream.Close()
			setup, err := web.New(nil, nil, []string{"example.test"}, web.Slots{
				Claim:  func(string, uint32) int { return -1 },
				Covers: func(string, string) bool { return false },
				Bind: func(*http.Request, string, func(string) string) ([]string, func(*http.Request, func(context.Context, string) (string, error)) (*http.Request, error), error) {
					return nil, nil, nil
				},
			})
			if err != nil {
				t.Fatal(err)
			}
			handler := web.Handler{Setup: setup, MaxBody: kib, ServeHTTP: netx.ServeConn, Accept: c.accept, UpstreamReadLimit: c.limit,
				Transport: &http.Transport{DialContext: func(ctx context.Context, network, _ string) (net.Conn, error) {
					return (&net.Dialer{}).DialContext(ctx, network, upstream.Listener.Addr().String())
				}},
			}
			agentTransport := &http.Transport{DialContext: func(context.Context, string, string) (net.Conn, error) {
				agent, stream := net.Pipe()
				go handler.Serve(ctx, stream, "", "example.test", 80, func(context.Context, facts.Event) error { return nil })
				return agent, nil
			}}
			defer agentTransport.CloseIdleConnections()
			agent, _, err := websocket.Dial(ctx, "ws://example.test/socket", &websocket.DialOptions{
				HTTPClient: &http.Client{Transport: agentTransport}, HTTPHeader: http.Header{"Origin": {c.origin}},
			})
			var got []byte
			if err == nil {
				defer agent.CloseNow()
				agent.SetReadLimit(-1)
				_, got, err = agent.Read(ctx)
			}
			if delivered := err == nil && string(got) == payload; delivered != c.delivered {
				t.Fatalf("delivered = %v, want %v (%v)", delivered, c.delivered, err)
			}
		})
	}
}
