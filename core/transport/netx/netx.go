package netx

import (
	"bufio"
	"cmp"
	"context"
	"encoding/binary"
	"errors"
	"io"
	"math"
	"net"
	"net/http"
	"net/netip"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"code.dny.dev/ssrf"
)

type Open = func(ctx context.Context, network, host string, port uint32, accept func() (net.Conn, error)) error

// NetworkHeader names a CONNECT stream's network: tcp when absent, or udp for a stream that carries Datagrams.
const NetworkHeader = "X-Monitor-Network"

func Dial(dial func(ctx context.Context, network, address string) (net.Conn, error), drain time.Duration) Open {
	return func(ctx context.Context, network, host string, port uint32, accept func() (net.Conn, error)) error {
		upstream, err := dial(ctx, network, net.JoinHostPort(host, strconv.FormatUint(uint64(port), 10)))
		if err != nil {
			return err
		}
		conn, err := accept()
		if err != nil {
			upstream.Close()
			return err
		}
		if strings.HasPrefix(network, "udp") {
			conn = Datagrams(conn)
		}
		Relay(ctx, conn, upstream, drain)
		return nil
	}
}

// Guard is a net.Dialer Control that refuses private and reserved destinations unless a prefix in allowed holds them.
func Guard(allowed []netip.Prefix, network string) func(network, address string, c syscall.RawConn) error {
	var v4, v6 []netip.Prefix
	for _, p := range allowed {
		if p.Addr().Is4() {
			v4 = append(v4, p)
		} else {
			v6 = append(v6, p)
		}
	}
	return ssrf.New(ssrf.WithAnyPort(), ssrf.WithNetworks(network+"4", network+"6"), ssrf.WithAllowedV4Prefixes(v4...), ssrf.WithAllowedV6Prefixes(v6...)).Safe
}

func Transport(dial func(ctx context.Context, network, address string) (net.Conn, error)) *http.Transport {
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.Proxy = nil
	transport.DialContext = dial
	return transport
}

func RefuseRedirects(*http.Request, []*http.Request) error {
	return errors.New("redirects are refused")
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
		err = open(r.Context(), cmp.Or(r.Header.Get(NetworkHeader), "tcp"), host, uint32(number), func() (net.Conn, error) {
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

const maxFrame = math.MaxUint16

var errFrame = errors.New("datagram exceeds the frame limit")

// Datagrams carries whole datagrams over a stream, each after its big-endian 16-bit length.
func Datagrams(c net.Conn) net.Conn { return datagrams{c} }

type datagrams struct{ net.Conn }

func (c datagrams) Read(p []byte) (int, error) {
	var length [2]byte
	if _, err := io.ReadFull(c.Conn, length[:]); err != nil {
		return 0, err
	}
	n := int(binary.BigEndian.Uint16(length[:]))
	if n > len(p) {
		if _, err := io.CopyN(io.Discard, c.Conn, int64(n)); err != nil {
			return 0, err
		}
		return 0, io.ErrShortBuffer
	}
	return io.ReadFull(c.Conn, p[:n])
}

func (c datagrams) Write(p []byte) (int, error) {
	if len(p) > maxFrame {
		return 0, errFrame
	}
	if _, err := c.Conn.Write(append(binary.BigEndian.AppendUint16(make([]byte, 0, 2+len(p)), uint16(len(p))), p...)); err != nil {
		return 0, err
	}
	return len(p), nil
}

// Without these io.Copy, and so Relay, drops empty datagrams and splits large ones.
func (c datagrams) ReadFrom(r io.Reader) (int64, error) { return copyDatagrams(c, r) }

func (c datagrams) WriteTo(w io.Writer) (int64, error) { return copyDatagrams(w, c) }

func copyDatagrams(dst io.Writer, src io.Reader) (int64, error) {
	var copied int64
	datagram := make([]byte, maxFrame)
	for {
		n, err := src.Read(datagram)
		if n == 0 && errors.Is(err, io.EOF) {
			return copied, nil
		}
		if err == nil || errors.Is(err, io.EOF) {
			_, err = dst.Write(datagram[:n])
		}
		if err != nil {
			return copied, err
		}
		copied += int64(n)
	}
}

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
