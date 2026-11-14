// Package netx relays bytes and serves HTTP over connections of any transport.
package netx

import (
	"bufio"
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"sync"
	"time"

	"golang.org/x/crypto/ssh"
)

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

// ServeConn serves server on c as ServeListener does, until ctx ends or c closes, then closes c.
func ServeConn(ctx context.Context, c net.Conn, server *http.Server) error {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	server.ConnState = func(_ net.Conn, state http.ConnState) {
		if state == http.StateClosed {
			cancel()
		}
	}
	return ServeListener(ctx, Listen(ctx, c), server)
}

// Listen yields c once and then waits for ctx to end, for servers that only accept listeners. Closing it closes c.
func Listen(ctx context.Context, c net.Conn) net.Listener { return &listener{ctx, c, c} }

type listener struct {
	ctx        context.Context
	conn, next net.Conn
}

func (l *listener) Accept() (net.Conn, error) {
	if c := l.next; c != nil {
		l.next = nil
		return c, nil
	}
	<-l.ctx.Done()
	return nil, net.ErrClosed
}

func (l *listener) Close() error { return l.conn.Close() }

func (*listener) Addr() net.Addr { return &net.TCPAddr{} }

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
	if channel, ok := a.(interface{ Closed() <-chan struct{} }); ok {
		aClosed = channel.Closed()
	}
	if channel, ok := b.(interface{ Closed() <-chan struct{} }); ok {
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

const established = "HTTP/1.1 200 Connection Established\r\n\r\n"

func Hijack(w http.ResponseWriter, head string) (net.Conn, error) {
	c, rw, err := w.(http.Hijacker).Hijack()
	if err != nil {
		return nil, err
	}
	if _, err = rw.WriteString(head); err == nil {
		err = rw.Flush()
	}
	if err != nil {
		c.Close()
		return nil, err
	}
	return Buffered(c, rw.Reader), nil
}

// Tunnel answers a CONNECT and relays it to upstream, which it closes on every path.
func Tunnel(w http.ResponseWriter, r *http.Request, upstream net.Conn) {
	client, err := Hijack(w, established)
	if err != nil {
		upstream.Close()
		return
	}
	Relay(r.Context(), client, upstream)
}

func Buffered(c net.Conn, r *bufio.Reader) net.Conn { return &bufferedConn{Conn: c, reader: r} }

type bufferedConn struct {
	net.Conn
	reader *bufio.Reader
}

func (c *bufferedConn) Read(b []byte) (int, error) {
	// Drain the handshake prefix, then leave net/http's connection reader behind.
	// A later protocol read deadline must not cancel the hijacked request context.
	if buffered := c.reader.Buffered(); buffered > 0 {
		return c.reader.Read(b[:min(len(b), buffered)])
	}
	return c.Conn.Read(b)
}

func (c *bufferedConn) CloseWrite() error {
	if writer, ok := c.Conn.(interface{ CloseWrite() error }); ok {
		return writer.CloseWrite()
	}
	return errors.New("connection does not support half-close")
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
