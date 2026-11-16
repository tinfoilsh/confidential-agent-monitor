package browser

import (
	"context"
	"net"
	"net/http"
	"net/http/httputil"

	"github.com/tinfoilsh/confidential-agent-monitor/connector"
	"github.com/tinfoilsh/confidential-agent-monitor/core/netx"
)

// proxy captures this Chrome session's network capability. CONNECT remains in
// its handler until both directions end, so resource shutdown joins every tunnel.
func (b *session) proxy(ctx context.Context, capabilities *connector.Env) (net.Listener, error) {
	ln, err := net.Listen("tcp", loopback)
	if err != nil {
		return nil, err
	}
	env := *capabilities
	transport := env.Transport()
	b.cleanup = append(b.cleanup, transport.CloseIdleConnections)
	proxy := &httputil.ReverseProxy{Transport: transport, Director: func(*http.Request) {}}
	connect := netx.Connect(netx.Dial(env.Dialer))
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodConnect {
			connect.ServeHTTP(w, r)
		} else {
			proxy.ServeHTTP(w, r)
		}
	})
	b.workers.Go(func() {
		netx.ServeListener(ctx, ln, &http.Server{Handler: handler})
	})
	return ln, nil
}
