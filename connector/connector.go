package connector

import (
	"crypto/tls"
	"net"
	"net/netip"
	"net/url"
	"time"

	"code.dny.dev/ssrf"
	"golang.org/x/crypto/ssh"
)

const dialTimeout = 30 * time.Second

// Serve owns the stream, but returning does not end its lifetime.
type Connector interface {
	Serve(s *Stream)
}

// Start runs once, before the connector receives any stream.
type Starter interface{ Start(*Env) }

type Claimer interface {
	Claim(host string, port uint32) int
}

// The kind is also the protocol policies see.
var Kinds = map[string]func() Connector{
	"http":      func() Connector { return new(HTTP) },
	"ssh":       func() Connector { return new(SSH) },
	"cli":       func() Connector { return new(CLI) },
	"ssh-agent": func() Connector { return new(SSHAgent) },
	"gpg-agent": func() Connector { return new(GPGAgent) },
	"imap":      func() Connector { return new(IMAP) },
	"smtp":      func() Connector { return new(SMTP) },
	"postgres":  func() Connector { return new(Postgres) },
	"redis":     func() Connector { return new(Redis) },
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
	return &net.Dialer{Timeout: dialTimeout, Control: guard.Safe}
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
	HTTP     *httpLayer     `json:"http,omitempty"`
	GraphQL  *graphqlLayer  `json:"graphql,omitempty"`
	SSH      *sshLayer      `json:"ssh,omitempty"`
	Command  *argvLayer     `json:"command,omitempty"`
	Payload  *gitLayer      `json:"payload,omitempty"`
	Sign     *signLayer     `json:"sign,omitempty"`
	Postgres *postgresLayer `json:"postgres,omitempty"`
	Redis    *argvLayer     `json:"redis,omitempty"`
	SMTP     *smtpLayer     `json:"smtp,omitempty"`
	Mail     *mailLayer     `json:"mail,omitempty"`
	IMAP     *imapLayer     `json:"imap,omitempty"`
}

type argvLayer struct {
	Argv []string `json:"argv"`
}

type endpoint struct{ url.URL }

func (e *endpoint) UnmarshalText(text []byte) error {
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

func dialURL(d *net.Dialer, u *url.URL, secure, port, securePort string) (net.Conn, error) {
	target := address(u, secure, port, securePort)
	if u.Scheme == secure {
		return tls.DialWithDialer(d, "tcp", target, &tls.Config{ServerName: u.Hostname()})
	}
	return d.Dial("tcp", target)
}

// chanListener feeds streams to library servers that only serve a net.Listener.
type chanListener chan net.Conn

func (l chanListener) Accept() (net.Conn, error) { return <-l, nil }
func (chanListener) Close() error                { return nil }
func (chanListener) Addr() net.Addr              { return &net.TCPAddr{} }

func streamOf(c net.Conn) *Stream {
	if tc, ok := c.(*tls.Conn); ok {
		c = tc.NetConn()
	}
	return c.(*Stream)
}
