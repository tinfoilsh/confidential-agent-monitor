package connector

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"sync"
	"time"

	"code.dny.dev/ssrf"
	"golang.org/x/crypto/ssh"
)

const DialTimeout = 30 * time.Second

// A connector either runs a server or handles individual streams.
type Connector interface {
	// Fields declares credentials and redacted values at relative JSON paths.
	Fields() []Field
}

type runner interface {
	Run(context.Context, *Env, *Listener, func()) error
}

type streamHandler interface{ Serve(*Stream, *Env) }

// Run owns resources and waits for stream handlers to finish on cancellation.
func Run(c Connector, ctx context.Context, e *Env, in *Listener, ready func()) error {
	if r, ok := c.(runner); ok {
		return r.Run(ctx, e, in, ready)
	}
	return ServeStreams(in, ready, func(s *Stream) { c.(streamHandler).Serve(s, e) })
}

// Status is shown to the owner.
type Reporter interface{ Status() any }

type Claimer interface {
	Claim(host string, port uint32) int
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
	Gate func(Event) error
}

func NewStream(ctx context.Context) *Stream {
	ctx, cancel := context.WithCancel(ctx)
	return &Stream{Context: ctx, cancel: cancel}
}

func (s *Stream) Close() error {
	if s.cancel != nil {
		s.cancel()
	}
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

type Event struct {
	HTTP     *HTTPLayer     `json:"http,omitempty"`
	GraphQL  *GraphQLLayer  `json:"graphql,omitempty"`
	SSH      *SSHLayer      `json:"ssh,omitempty"`
	Command  *ArgvLayer     `json:"command,omitempty"`
	Payload  *GitLayer      `json:"payload,omitempty"`
	Sign     *SignLayer     `json:"sign,omitempty"`
	Postgres *PostgresLayer `json:"postgres,omitempty"`
	Redis    *RedisLayer    `json:"redis,omitempty"`
	SMTP     *SMTPLayer     `json:"smtp,omitempty"`
	Mail     *MailLayer     `json:"mail,omitempty"`
	IMAP     *IMAPLayer     `json:"imap,omitempty"`
	MCP      *MCPLayer      `json:"mcp,omitempty"`
	Browser  *BrowserLayer  `json:"browser,omitempty"`
}

type ArgvLayer struct {
	Argv []string `json:"argv"`
}

// Command is named as Redis ACLs name it, with a container's subcommand: CLIENT|SETNAME.
type RedisLayer struct {
	Command string   `json:"command"`
	Argv    []string `json:"argv"`
}

// HTTPLayer is the request before substitution; secrets names the placeholders it carried.
type HTTPLayer struct {
	Method   string      `json:"method"`
	Origin   string      `json:"origin"`
	Host     string      `json:"host"`
	Path     string      `json:"path"`
	Query    url.Values  `json:"query"`
	Headers  http.Header `json:"headers"`
	Secrets  []string    `json:"secrets"`
	BodyKind string      `json:"body_kind"`
	Body     any         `json:"body,omitempty"`
	Form     url.Values  `json:"form,omitempty"`
	// HeaderJSON holds single header values that are JSON objects, as Dropbox-API-Arg is.
	HeaderJSON map[string]any `json:"header_json,omitempty"`
}

// GraphQLLayer is the selected operation; each root field carries its argument values after variables apply.
type GraphQLLayer struct {
	Kind   string         `json:"kind"`
	Fields []GraphQLField `json:"fields"`
}

type GraphQLField struct {
	Name      string         `json:"name"`
	Arguments map[string]any `json:"arguments"`
}

type SSHLayer struct {
	Request   string  `json:"request"`
	Command   string  `json:"command,omitempty"`
	Subsystem string  `json:"subsystem,omitempty"`
	Term      string  `json:"term,omitempty"`
	Env       *SSHEnv `json:"env,omitempty"`
}

type SSHEnv struct {
	Name  string `json:"name"`
	Value string `json:"value"`
}

type GitLayer struct {
	Type       string   `json:"type"`
	Tree       string   `json:"tree,omitempty"`
	Object     string   `json:"object,omitempty"`
	ObjectType string   `json:"object_type,omitempty"`
	Tag        string   `json:"tag,omitempty"`
	Parents    []string `json:"parents"`
	Author     string   `json:"author,omitempty"`
	Committer  string   `json:"committer,omitempty"`
	Tagger     string   `json:"tagger,omitempty"`
	Message    string   `json:"message"`
}

type SignLayer struct {
	Agent     string `json:"agent"`
	Key       string `json:"key,omitempty"`
	Purpose   string `json:"purpose,omitempty"`
	Namespace string `json:"namespace,omitempty"`
	User      string `json:"user,omitempty"`
	Hash      string `json:"hash,omitempty"`
	Op        string `json:"op,omitempty"`
}

type IMAPLayer struct {
	Command string `json:"command"`
	Args    string `json:"args"`
	Mailbox string `json:"mailbox,omitempty"`
}

type SMTPLayer struct {
	From string   `json:"from"`
	To   []string `json:"to"`
}

type MailLayer struct {
	From        []string `json:"from"`
	To          []string `json:"to"`
	Cc          []string `json:"cc"`
	Subject     string   `json:"subject"`
	Attachments []string `json:"attachments"`
}

// ReadOnly is the pinned tool's hint, which the owner approved with the pin.
type MCPLayer struct {
	Tool      string          `json:"tool"`
	Arguments json.RawMessage `json:"arguments"`
	ReadOnly  bool            `json:"read_only"`
}

// BrowserLayer names the page a command acts on: the destination of navigate, otherwise the current page.
type BrowserLayer struct {
	Command string   `json:"command"`
	URL     string   `json:"url"`
	Host    string   `json:"host"`
	Text    string   `json:"text,omitempty"`
	Secrets []string `json:"secrets,omitempty"`
}

type PostgresLayer struct {
	SQL string `json:"sql"`
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
		return nil, errors.New("use the password field for URL authentication")
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

func NewListener() *Listener {
	ctx, cancel := context.WithCancel(context.Background())
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
	closeStream := sync.OnceFunc(func() { s.Close() })
	stop := context.AfterFunc(l.ctx, closeStream)
	context.AfterFunc(s.Context, func() { stop(); closeStream() })
	select {
	case l.conns <- s:
	case <-l.ctx.Done():
		s.Close()
	case <-s.Context.Done():
		s.Close()
	}
}

// CopyReplies returns cleanup that closes both sides and joins the reply pump.
func CopyReplies(s *Stream, up net.Conn, replies io.Reader) func() {
	done := make(chan struct{})
	go func() { defer close(done); io.Copy(s, replies); s.Close() }()
	return func() { s.Close(); up.Close(); <-done }
}

// ServeStreams adapts blocking stream handlers and waits for every handler on exit.
func ServeStreams(in *Listener, ready func(), serve func(*Stream)) error {
	var workers sync.WaitGroup
	defer workers.Wait()
	defer in.Close()
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
