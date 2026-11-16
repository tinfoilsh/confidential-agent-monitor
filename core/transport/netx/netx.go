package netx

import (
	"bufio"
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"strconv"
	"sync"
	"time"
)

type Open = func(ctx context.Context, host string, port uint32, accept func() (net.Conn, error)) error

func Dial(dial func(ctx context.Context, network, address string) (net.Conn, error), drain time.Duration) Open {
	return func(ctx context.Context, host string, port uint32, accept func() (net.Conn, error)) error {
		upstream, err := dial(ctx, "tcp", net.JoinHostPort(host, strconv.FormatUint(uint64(port), 10)))
		if err != nil {
			return err
		}
		conn, err := accept()
		if err != nil {
			upstream.Close()
			return err
		}
		Relay(ctx, conn, upstream, drain)
		return nil
	}
}

func Connect(open Open) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		host, port, err := net.SplitHostPort(r.Host)
		number, invalid := strconv.ParseUint(port, 10, 16)
		if r.Method != http.MethodConnect || err != nil || invalid != nil {
			http.Error(w, "CONNECT to host:port required", http.StatusBadRequest)
			return
		}
		accepted := false
		err = open(r.Context(), host, uint32(number), func() (net.Conn, error) {
			accepted = true
			return Hijack(w, established)
		})
		if err != nil && !accepted {
			http.Error(w, "stream refused", http.StatusBadGateway)
		}
	})
}

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

func Listen(ctx context.Context, c net.Conn) net.Listener {
	ctx, cancel := context.WithCancel(ctx)
	return &listener{ctx, cancel, c, c}
}

type listener struct {
	ctx        context.Context
	cancel     context.CancelFunc
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

func (l *listener) Close() error { l.cancel(); return l.conn.Close() }

func (*listener) Addr() net.Addr { return &net.TCPAddr{} }

func Bind(ctx, other context.Context) (context.Context, context.CancelFunc) {
	ctx, cancel := context.WithCancel(ctx)
	stop := context.AfterFunc(other, cancel)
	return ctx, func() { stop(); cancel() }
}

func Relay(ctx context.Context, a, b net.Conn, drain time.Duration) {
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
	timer := time.NewTimer(drain)
	defer timer.Stop()
	select {
	case <-drained:
	case <-ctx.Done():
	case <-timer.C:
	}
}

const established = "HTTP/1.1 200 Connection Established\r\n\r\n"

func Hijack(w http.ResponseWriter, head string) (net.Conn, error) {
	hijacker, ok := w.(http.Hijacker)
	if !ok {
		return nil, errors.New("response writer does not support hijacking")
	}
	c, rw, err := hijacker.Hijack()
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

func Buffered(c net.Conn, r *bufio.Reader) net.Conn { return &bufferedConn{Conn: c, reader: r} }

type bufferedConn struct {
	net.Conn
	reader *bufio.Reader
}

func (c *bufferedConn) Read(b []byte) (int, error) {
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
