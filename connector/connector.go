package connector

import (
	"context"
	"crypto/tls"
	"errors"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"sync"
	"time"

	"code.dny.dev/ssrf"
	"github.com/tinfoilsh/monitor/facts"
	"golang.org/x/crypto/ssh"
)

const DialTimeout = 30 * time.Second

// Server handles independent streams; Runner owns a persistent protocol runtime.
type Server interface{ Serve(*Stream, *Env) }
type Runner interface {
	Run(context.Context, *Env, *Listener, func()) error
}

type Env struct {
	TLS     *tls.Config
	HostKey ssh.Signer
	Dialer  *net.Dialer
}

func (e *Env) Transport() *http.Transport {
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.Proxy = nil
	transport.DialContext = e.Dialer.DialContext
	return transport
}

// Client is for requests the monitor makes itself, such as OAuth. A redirect could carry a credential elsewhere, so it fails.
func (e *Env) Client() *http.Client {
	return &http.Client{
		Transport:     e.Transport(),
		CheckRedirect: func(*http.Request, []*http.Request) error { return errors.New("redirects are refused") },
	}
}

type streamKey struct{}

func RequestStream(r *http.Request) *Stream { return r.Context().Value(streamKey{}).(*Stream) }

func ServeHTTP(ctx context.Context, in net.Listener, ready func(), handler http.Handler) error {
	server := &http.Server{
		ReadHeaderTimeout: DialTimeout,
		BaseContext:       func(net.Listener) context.Context { return ctx },
		ConnContext: func(ctx context.Context, c net.Conn) context.Context {
			return context.WithValue(ctx, streamKey{}, StreamOf(c))
		},
		Handler: handler,
	}
	defer server.Shutdown(context.Background())
	ready()
	return server.Serve(in)
}

// The guard checks the resolved address, so DNS cannot steer an upstream into a refused range.
func NewDialer(allowed []netip.Prefix) *net.Dialer {
	var v4, v6 []netip.Prefix
	for _, p := range allowed {
		if p.Addr().Is4() {
			v4 = append(v4, p)
		} else {
			v6 = append(v6, p)
		}
	}
	guard := ssrf.New(ssrf.WithAnyPort(), ssrf.WithAllowedV4Prefixes(v4...), ssrf.WithAllowedV6Prefixes(v6...))
	return &net.Dialer{Timeout: DialTimeout, Control: guard.Safe}
}

type Stream struct {
	Context context.Context
	cancel  context.CancelFunc
	net.Conn
	Name string
	Host string
	Port uint32
	// The error joins the message of every rule that denied the event.
	Gate func(Request) error
}

func NewStream(ctx context.Context) *Stream {
	ctx, cancel := context.WithCancel(ctx)
	return &Stream{Context: ctx, cancel: cancel}
}

func (s *Stream) Close() error {
	s.cancel()
	if s.Conn != nil {
		return s.Conn.Close()
	}
	return nil
}

// Interrupt closes an upstream if its stream ends, including during handshakes.
func (s *Stream) Interrupt(c io.Closer) func() {
	stop := context.AfterFunc(s.Context, func() { c.Close() })
	return func() { stop(); c.Close() }
}

// ParseURL validates a destination whose password is supplied separately.
func ParseURL(raw string) (*url.URL, error) {
	u, err := url.Parse(raw)
	if err != nil {
		return nil, err
	}
	if u.Scheme == "" || u.Host == "" {
		return nil, errors.New("destination requires a URL with a scheme and host")
	}
	if _, set := u.User.Password(); set || u.Query().Has("password") {
		return nil, errors.New("use secrets.password for URL authentication")
	}
	return u, nil
}

func address(u *url.URL, secure, port, securePort string) string {
	if u.Port() != "" {
		return u.Host
	}
	if u.Scheme == secure {
		port = securePort
	}
	return net.JoinHostPort(u.Hostname(), port)
}

func DialURL(ctx context.Context, d *net.Dialer, u *url.URL, secure, port, securePort string) (net.Conn, error) {
	target := address(u, secure, port, securePort)
	if u.Scheme == secure {
		return (&tls.Dialer{NetDialer: d, Config: &tls.Config{ServerName: u.Hostname()}}).DialContext(ctx, "tcp", target)
	}
	return d.DialContext(ctx, "tcp", target)
}

// Listener closes every admitted or queued stream when canceled.
type Listener struct {
	conns  chan *Stream
	ctx    context.Context
	cancel context.CancelFunc
}

func NewListener(ctx context.Context) *Listener {
	ctx, cancel := context.WithCancel(ctx)
	return &Listener{conns: make(chan *Stream), ctx: ctx, cancel: cancel}
}
func (l *Listener) Accept() (net.Conn, error) {
	select {
	case c := <-l.conns:
		return c, nil
	case <-l.ctx.Done():
		return nil, net.ErrClosed
	}
}
func (l *Listener) Close() error { l.cancel(); return nil }
func (*Listener) Addr() net.Addr { return &net.TCPAddr{} }

func (l *Listener) Hand(s *Stream) {
	stop := context.AfterFunc(l.ctx, func() { s.Close() })
	defer stop()
	defer s.Close()
	select {
	case l.conns <- s:
		<-s.Context.Done()
	case <-s.Context.Done():
	}
}

// PumpReplies runs a protocol reply loop until the stream ends, then joins it.
func PumpReplies(s *Stream, pump func()) func() {
	done := make(chan struct{})
	go func() { defer close(done); pump(); s.Close() }()
	return func() { s.Close(); <-done }
}

// ServeStreams adapts blocking stream handlers and waits for every handler on exit.
func ServeStreams(in *Listener, ready func(), serve func(*Stream)) error {
	var workers sync.WaitGroup
	defer workers.Wait()
	ready()
	for {
		c, err := in.Accept()
		if err != nil {
			return err
		}
		workers.Go(func() {
			s := StreamOf(c)
			defer s.Close()
			serve(s)
		})
	}
}

func StreamOf(c net.Conn) *Stream {
	if tc, ok := c.(*tls.Conn); ok {
		c = tc.NetConn()
	}
	return c.(*Stream)
}

// Request retains parsed input while an approval is pending. Describe must be
// pure: the monitor calls it again with current settings before execution.
type Request interface {
	Describe(Context) (facts.Facts, error)
}

// PolicyOptions contains settings used only by policy, never connection setup.
type PolicyOptions struct {
	Private []string `json:"private,omitempty"`
	Address string   `json:"address,omitempty"`
	Origin  string   `json:"origin,omitempty"`
}

// Context contains current settings and the preset for the connection protocol.
type Context struct {
	Title, Connection  string
	Label, Observation facts.Label
	Config             any
	Options            PolicyOptions
	Spec               any
}

// CloseFunc adapts a library's close function to stream lifetime management.
type CloseFunc func()

func (close CloseFunc) Close() error { close(); return nil }
