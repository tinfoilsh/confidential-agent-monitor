package connector

import (
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"time"

	"golang.org/x/crypto/ssh"
)

// ServeHTTP serves the requests on c, the stream itself or TLS over it, until the stream ends.
func ServeHTTP(s *Stream, c net.Conn, handler http.Handler) {
	server := &http.Server{Handler: handler, BaseContext: func(net.Listener) context.Context { return s.Context }, ConnState: func(_ net.Conn, state http.ConnState) {
		if state == http.StateClosed {
			s.Close()
		}
	}}
	defer server.Shutdown(context.Background())
	server.Serve(Listen(s, c))
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

// Stream carries an authenticated connection and its blocking authorization gate.
type Stream struct {
	Context context.Context
	cancel  context.CancelFunc
	stop    func() bool
	net.Conn
	Name string
	Host string
	Port uint32
	// Gate waits for authorization, including any owner approval, and persists
	// observations before returning. A successful call admits exactly this
	// captured operation; subsequent operations must pass the gate again.
	// Calls from either direction may run concurrently. Input must remain
	// unchanged until Gate returns, and forwarding must use the admitted input.
	Gate func(context.Context, Request) error
}

// NewStream carries c until ctx ends or the stream closes.
func NewStream(ctx context.Context, c net.Conn) *Stream {
	ctx, cancel := context.WithCancel(ctx)
	stop := context.AfterFunc(ctx, func() { c.Close() })
	return &Stream{Context: ctx, cancel: cancel, Conn: c, stop: stop, Gate: func(context.Context, Request) error {
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

// Relay preserves half-close so a caller can finish sending while still
// receiving a reply. Cancellation and I/O errors close both directions.
func Relay(ctx context.Context, a, b net.Conn) {
	closeBoth := func() { a.Close(); b.Close() }
	stop := context.AfterFunc(ctx, closeBoth)
	defer stop()
	defer closeBoth()
	done := make(chan struct{})
	copyTo := func(dst, src net.Conn) {
		_, err := io.Copy(dst, src)
		if writer, ok := dst.(interface{ CloseWrite() error }); err == nil && ok {
			if writer.CloseWrite() == nil {
				return
			}
		}
		closeBoth()
	}
	go func() { defer close(done); copyTo(a, b) }()
	copyTo(b, a)
	<-done
}

// PumpReplies runs a protocol reply loop until the stream ends, then joins it.
func PumpReplies(s *Stream, pump func()) func() {
	done := make(chan struct{})
	go func() { defer close(done); pump(); s.Close() }()
	return func() { s.Close(); <-done }
}

// CloseFunc adapts a library's close function to stream lifetime management.
type CloseFunc func()

func (close CloseFunc) Close() error { close(); return nil }

type ChannelConn struct {
	ssh.Channel
	reader net.Conn
}

// HTTP hijacking interrupts a pending read using a deadline. SSH channels have
// no deadlines, so give stream consumers an interruptible, bounded read pipe.
// Writes and half-close continue to use the SSH channel directly.
func NewChannelConn(ch ssh.Channel) ChannelConn {
	r, w := net.Pipe()
	go func() { defer w.Close(); io.Copy(w, ch) }()
	return ChannelConn{Channel: ch, reader: r}
}

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
