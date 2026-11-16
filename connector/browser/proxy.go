package browser

import (
	"context"
	"net"
	"net/http"
)

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
