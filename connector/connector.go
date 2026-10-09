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
	"time"

	"code.dny.dev/ssrf"
	"github.com/tinfoilsh/monitor/facts"
	"golang.org/x/crypto/ssh"
)

const DialTimeout = 30 * time.Second

// Server handles one stream. A Runner also holds what its streams share: it calls serve once ready, which returns after the last stream.
type Server interface{ Serve(*Stream, *Env) }
type Runner interface {
	Run(ctx context.Context, e *Env, serve func()) error
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

// ServeHTTP serves the requests on c, the stream itself or TLS over it, until the stream ends.
func ServeHTTP(s *Stream, c net.Conn, handler http.Handler) {
	server := &http.Server{Handler: handler, BaseContext: func(net.Listener) context.Context { return s.Context }}
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

// NewStream carries c until ctx ends or the stream closes.
func NewStream(ctx context.Context, c net.Conn) *Stream {
	ctx, cancel := context.WithCancel(ctx)
	context.AfterFunc(ctx, func() { c.Close() })
	return &Stream{Context: ctx, cancel: cancel, Conn: c}
}

func (s *Stream) Close() error {
	s.cancel()
	return s.Conn.Close()
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

// PumpReplies runs a protocol reply loop until the stream ends, then joins it.
func PumpReplies(s *Stream, pump func()) func() {
	done := make(chan struct{})
	go func() { defer close(done); pump(); s.Close() }()
	return func() { s.Close(); <-done }
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
	Title, Connection string
	Config            any
	Options           PolicyOptions
	Spec              any
}

// CloseFunc adapts a library's close function to stream lifetime management.
type CloseFunc func()

func (close CloseFunc) Close() error { close(); return nil }
