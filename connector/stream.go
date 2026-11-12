package connector

import (
	"context"
	"errors"
	"github.com/tinfoilsh/monitor/facts"
	"io"
	"net"
	"net/http"
	"sync"
	"time"

	"golang.org/x/crypto/ssh"
)

// ServeHTTP serves the requests on c, the stream itself or TLS over it, until the stream ends.
func ServeHTTP(s *Stream, c net.Conn, handler http.Handler) {
	server := &http.Server{Handler: handler, ConnState: func(_ net.Conn, state http.ConnState) {
		if state == http.StateClosed {
			s.Close()
		}
	}}
	ServeListener(s.Context, Listen(s, c), server)
}

// ServeListener cancels and joins active handlers, including handlers that keep
// upgraded streams inside their call. Such streams must observe request context.
func ServeListener(ctx context.Context, ln net.Listener, server *http.Server) error {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	var active sync.RWMutex
	handler := server.Handler
	server.BaseContext = func(net.Listener) context.Context { return ctx }
	server.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		active.RLock()
		defer active.RUnlock()
		if ctx.Err() != nil {
			http.Error(w, "service stopped", http.StatusServiceUnavailable)
			return
		}
		handler.ServeHTTP(w, r)
	})
	stop := context.AfterFunc(ctx, func() { server.Close() })
	err := server.Serve(ln)
	cancel()
	server.Close()
	stop()
	active.Lock()
	active.Unlock()
	if errors.Is(err, http.ErrServerClosed) {
		return nil
	}
	return err
}

// Listen yields c once and then waits for s to end, for servers that only accept listeners.
func Listen(s *Stream, c net.Conn) net.Listener { return &listener{s, c} }

type listener struct {
	s    *Stream
	next net.Conn
}

func (l *listener) Accept() (net.Conn, error) {
	if c := l.next; c != nil {
		l.next = nil
		return c, nil
	}
	<-l.s.Context.Done()
	return nil, net.ErrClosed
}

func (l *listener) Close() error { return l.s.Close() }

func (*listener) Addr() net.Addr { return &net.TCPAddr{} }

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
	// A settings change closes the stream unless its latest gated operation
	// would still be allowed.
	Gate func(context.Context, facts.Event) error
}

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

// Bind derives a context from ctx that also ends when other does.
func Bind(ctx, other context.Context) (context.Context, context.CancelFunc) {
	ctx, cancel := context.WithCancel(ctx)
	stop := context.AfterFunc(other, cancel)
	return ctx, func() { stop(); cancel() }
}

const relayDrainTimeout = 10 * time.Second

// Relay preserves half-close so a caller can finish sending while still
// receiving a reply. A fully closed SSH peer's buffered data drains before both
// sides close, with a deadline for stalled readers. Cancellation and I/O errors
// close both directions immediately.
func Relay(ctx context.Context, a, b net.Conn) {
	closeBoth := func() { a.Close(); b.Close() }
	stop := context.AfterFunc(ctx, closeBoth)
	defer stop()
	fromA, fromB := make(chan struct{}), make(chan struct{})
	defer func() { closeBoth(); <-fromA; <-fromB }()
	copyTo := func(dst, src net.Conn, done chan<- struct{}) {
		defer close(done)
		_, err := io.Copy(dst, src)
		if writer, ok := dst.(interface{ CloseWrite() error }); err == nil && ok {
			if writer.CloseWrite() == nil {
				return
			}
		}
		closeBoth()
	}
	go copyTo(b, a, fromA)
	go copyTo(a, b, fromB)
	done := make(chan struct{})
	go func() { <-fromA; <-fromB; close(done) }()
	var aClosed, bClosed, drained <-chan struct{}
	if channel, ok := a.(ChannelConn); ok {
		aClosed = channel.Closed()
	}
	if channel, ok := b.(ChannelConn); ok {
		bClosed = channel.Closed()
	}
	select {
	case <-done:
		return
	case <-ctx.Done():
		return
	case <-aClosed:
		drained = fromA
	case <-bClosed:
		drained = fromB
	}
	timer := time.NewTimer(relayDrainTimeout)
	defer timer.Stop()
	select {
	case <-drained:
	case <-ctx.Done():
	case <-timer.C:
	}
}

// PumpReplies runs a protocol reply loop until the stream ends, then joins it.
func PumpReplies(s *Stream, pump func()) func() {
	done := make(chan struct{})
	go func() { defer close(done); pump(); s.Close() }()
	return func() { s.Close(); <-done }
}

type ChannelConn struct {
	ssh.Channel
	reader net.Conn
	closed <-chan struct{}
}

// HTTP hijacking interrupts a pending read using a deadline. SSH channels have
// no deadlines, so give stream consumers an interruptible, bounded read pipe.
// Writes and half-close continue to use the SSH channel directly. Channel
// requests are rejected; their closure distinguishes full closure from EOF.
func NewChannelConn(ch ssh.Channel, requests <-chan *ssh.Request) ChannelConn {
	r, w := net.Pipe()
	go func() { defer w.Close(); io.Copy(w, ch) }()
	closed := make(chan struct{})
	go func() { ssh.DiscardRequests(requests); close(closed) }()
	return ChannelConn{Channel: ch, reader: r, closed: closed}
}

// Closed reports full SSH channel closure; a peer's CloseWrite leaves it open.
func (c ChannelConn) Closed() <-chan struct{} { return c.closed }

func (c ChannelConn) Read(p []byte) (int, error) {
	if c.reader != nil {
		return c.reader.Read(p)
	}
	return c.Channel.Read(p)
}

func (c ChannelConn) Close() error {
	if c.reader != nil {
		c.reader.Close()
	}
	return c.Channel.Close()
}

func (ChannelConn) LocalAddr() net.Addr             { return &net.TCPAddr{} }
func (ChannelConn) RemoteAddr() net.Addr            { return &net.TCPAddr{} }
func (c ChannelConn) SetDeadline(t time.Time) error { return c.SetReadDeadline(t) }
func (c ChannelConn) SetReadDeadline(t time.Time) error {
	if c.reader != nil {
		return c.reader.SetReadDeadline(t)
	}
	return nil
}
func (ChannelConn) SetWriteDeadline(time.Time) error { return nil }
