package browser

import (
	"context"
	"net"
	"net/http"

	"github.com/tinfoilsh/confidential-agent-monitor/core/facts"
)

// Open starts one Chrome session. Its command/control synchronization remains
// inside that session; closing it retires its network proxy and callbacks too.
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

// Close waits for streams and controls to leave, since commands start workers that close joins.
func (b *Session) Close() error {
	b.life.Lock()
	defer b.life.Unlock()
	return b.close()
}

func (b *Session) Serve(ctx context.Context, conn net.Conn, _, _ string, _ uint32, gate func(context.Context, facts.Event) error) {
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
