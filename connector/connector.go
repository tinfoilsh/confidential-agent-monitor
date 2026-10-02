package connector

import (
	"crypto/tls"
	"encoding/json"
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

// Serve owns the stream, but returning does not end its lifetime.
type Connector interface {
	Serve(s *Stream)
}

// Start runs once, before the connector receives any stream.
type Starter interface{ Start(*Env) }

// Stop runs once, after the connector is replaced; streams it already accepted may finish.
type Stopper interface{ Stop() }

type Claimer interface {
	Claim(host string, port uint32) int
}

type Env struct {
	TLS     *tls.Config
	HostKey ssh.Signer
	Dialer  *net.Dialer
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
	net.Conn
	*Env
	Name string
	Host string
	Port uint32
	// The error joins the message of every rule that denied the event.
	Gate func(Event) error
}

type Event struct {
	HTTP     *HTTPLayer     `json:"http,omitempty"`
	GraphQL  *GraphQLLayer  `json:"graphql,omitempty"`
	SSH      *SSHLayer      `json:"ssh,omitempty"`
	Command  *ArgvLayer     `json:"command,omitempty"`
	Payload  *GitLayer      `json:"payload,omitempty"`
	Sign     *SignLayer     `json:"sign,omitempty"`
	Postgres *PostgresLayer `json:"postgres,omitempty"`
	Redis    *ArgvLayer     `json:"redis,omitempty"`
	SMTP     *SMTPLayer     `json:"smtp,omitempty"`
	Mail     *MailLayer     `json:"mail,omitempty"`
	IMAP     *IMAPLayer     `json:"imap,omitempty"`
	MCP      *MCPLayer      `json:"mcp,omitempty"`
}

type ArgvLayer struct {
	Argv []string `json:"argv"`
}

// HTTPLayer is the request before substitution; secrets names the placeholders it carried.
type HTTPLayer struct {
	Method  string      `json:"method"`
	Host    string      `json:"host"`
	Path    string      `json:"path"`
	Query   url.Values  `json:"query"`
	Headers http.Header `json:"headers"`
	Secrets []string    `json:"secrets"`
	Body    any         `json:"body,omitempty"`
}

type GraphQLLayer struct {
	Kind  string   `json:"kind"`
	Roots []string `json:"roots"`
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

type PostgresLayer struct {
	SQL string `json:"sql"`
}

type Endpoint struct{ url.URL }

func (e *Endpoint) UnmarshalText(text []byte) error {
	u, err := url.Parse(string(text))
	if err != nil {
		return err
	}
	e.URL = *u
	return nil
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

func DialURL(d *net.Dialer, u *url.URL, secure, port, securePort string) (net.Conn, error) {
	target := address(u, secure, port, securePort)
	if u.Scheme == secure {
		return tls.DialWithDialer(d, "tcp", target, &tls.Config{ServerName: u.Hostname()})
	}
	return d.Dial("tcp", target)
}

// Listener feeds streams to library servers that only serve a net.Listener.
type Listener struct {
	conns chan net.Conn
	done  chan struct{}
	once  sync.Once
}

func NewListener() *Listener { return &Listener{conns: make(chan net.Conn), done: make(chan struct{})} }

func (l *Listener) Accept() (net.Conn, error) {
	select {
	case c := <-l.conns:
		return c, nil
	case <-l.done:
		return nil, net.ErrClosed
	}
}

func (l *Listener) Close() error    { l.once.Do(func() { close(l.done) }); return nil }
func (*Listener) Addr() net.Addr    { return &net.TCPAddr{} }
func (l *Listener) Serve(s *Stream) { l.Hand(s) }

// Hand closes c instead once the listener is closed.
func (l *Listener) Hand(c net.Conn) {
	select {
	case l.conns <- c:
	case <-l.done:
		c.Close()
	}
}

func StreamOf(c net.Conn) *Stream {
	if tc, ok := c.(*tls.Conn); ok {
		c = tc.NetConn()
	}
	return c.(*Stream)
}
