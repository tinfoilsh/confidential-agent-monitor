//go:build monitor_dev

package browser

import (
	"context"
	"io"
	"net"
	"net/http"
	"net/http/httputil"

	"github.com/tinfoilsh/monitor/connector"
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
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodConnect {
			proxy.ServeHTTP(w, r)
			return
		}
		up, err := env.Dialer.DialContext(r.Context(), "tcp", r.URL.Host)
		if err != nil {
			http.Error(w, "upstream connection failed", http.StatusBadGateway)
			return
		}
		defer up.Close()
		client, buffered, err := w.(http.Hijacker).Hijack()
		if err != nil {
			return
		}
		defer client.Close()
		stop := context.AfterFunc(r.Context(), func() { client.Close(); up.Close() })
		defer stop()
		if _, err := io.WriteString(client, "HTTP/1.1 200 Connection Established\r\n\r\n"); err != nil {
			return
		}
		if _, err := io.CopyN(up, buffered.Reader, int64(buffered.Reader.Buffered())); err != nil {
			return
		}
		connector.Relay(r.Context(), client, up)
	})
	b.workers.Go(func() {
		connector.ServeListener(ctx, ln, &http.Server{Handler: handler})
	})
	return ln, nil
}
