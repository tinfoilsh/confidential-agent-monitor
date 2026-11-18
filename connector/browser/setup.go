package browser

import (
	"context"
	"net"
	"net/http"

	"github.com/tinfoilsh/confidential-agent-monitor/core/connector"
)

func Open(ctx context.Context, browser Browser) (*Session, error) {
	life, cancel := context.WithCancel(context.Background())
	next := &Session{Browser: browser, cancel: cancel}
	stop := context.AfterFunc(ctx, cancel)
	err := next.start(life)
	stop()
	if err == nil {
		err = ctx.Err()
	}
	if err != nil {
		next.close()
		return nil, err
	}
	return next, nil
}

func (b *Session) Close() error {
	b.life.Lock()
	defer b.life.Unlock()
	return b.close()
}

func (b *Session) Serve(ctx context.Context, conn net.Conn, _ string, _ connector.Target, gate connector.Gate) {
	b.life.RLock()
	defer b.life.RUnlock()
	b.serve(ctx, conn, gate)
}

func (b *Session) Control() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b.life.RLock()
		defer b.life.RUnlock()
		b.control().ServeHTTP(w, r)
	})
}
