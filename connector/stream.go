package connector

import (
	"context"
	"errors"
	"github.com/tinfoilsh/confidential-agent-monitor/core/facts"
	"io"
	"net"
	"net/http"

	"github.com/tinfoilsh/confidential-agent-monitor/core/netx"
)

// ServeHTTP serves the requests on c, the stream itself or TLS over it, until the stream ends.
func ServeHTTP(s *Stream, c net.Conn, handler http.Handler) {
	netx.ServeConn(s.Context, c, &http.Server{Handler: handler})
}

// Listen yields c once and then waits for s to end, for servers that only accept listeners.
func Listen(s *Stream, c net.Conn) net.Listener { return netx.Listen(s.Context, c) }

// Domain suffixes the names agents use to address Monitor services directly.
const Domain = ".perimeter"

// Stream carries an authenticated connection and its blocking authorization gate.
type Stream struct {
	Context context.Context
	cancel  context.CancelFunc
	stop    func() bool
	net.Conn
	Name string
	// Host is empty when the agent addressed the connection by name under Domain.
	Host string
	Port uint32
	// Gate waits for authorization, including any owner approval, and persists
	// observations before returning. A successful call admits exactly this
	// captured operation; subsequent operations must pass the gate again.
	// Calls from either direction may run concurrently. Input must remain
	// unchanged until Gate returns, and forwarding must use the admitted input.
	// A settings change closes the stream unless its principal still reaches the
	// connection and its admission and latest gated operation would both still be
	// allowed without approval.
	Gate Gate
}

// Gate admits exactly the captured operation, after any approval, or refuses it.
type Gate func(context.Context, facts.Event) error

// NewStream carries c until ctx ends or the stream closes.
func NewStream(ctx context.Context, c net.Conn) *Stream {
	ctx, cancel := context.WithCancel(ctx)
	stop := context.AfterFunc(ctx, func() { c.Close() })
	return &Stream{Context: ctx, cancel: cancel, Conn: c, stop: stop, Gate: func(context.Context, facts.Event) error {
		return errors.New("authorization gate missing")
	}}
}

func (s *Stream) Close() error {
	s.cancel()
	s.stop()
	return s.Conn.Close()
}

// Interrupt closes an upstream if its stream ends, including during handshakes.
func (s *Stream) Interrupt(c io.Closer) func() {
	stop := context.AfterFunc(s.Context, func() { c.Close() })
	return func() { stop(); c.Close() }
}

// PumpReplies runs a protocol reply loop until the stream ends, then joins it.
func PumpReplies(s *Stream, pump func()) func() {
	done := make(chan struct{})
	go func() { defer close(done); pump(); s.Close() }()
	return func() { s.Close(); <-done }
}
