package browser

import (
	"context"
	"net"
	"net/http"
)

// proxy serves this Chrome session's network capability. CONNECT remains in
// its handler until both directions end, so resource shutdown joins every tunnel.
func (b *Session) proxy(ctx context.Context) (net.Listener, error) {
	ln, err := net.Listen("tcp", loopback)
	if err != nil {
		return nil, err
	}
	b.workers.Go(func() {
		b.ServeListener(ctx, ln, &http.Server{Handler: b.Proxy})
	})
	return ln, nil
}
