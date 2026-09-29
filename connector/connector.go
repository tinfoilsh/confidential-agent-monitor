// Package connector terminates each protocol a tunnelled stream speaks, asks the policy
// before each operation, and attaches the stored credential upstream.
package connector

import (
	"context"
	"crypto/tls"
	"net"
	"net/url"
	"time"

	"golang.org/x/crypto/ssh"
)

const dialTimeout = 30 * time.Second

// Connector owns each stream it receives, closing it directly or handing it to a protocol server.
// Returning from Serve does not end the stream's lifetime.
type Connector interface {
	Serve(s *Stream)
}

// Starter initializes its listener and server before launching the serving goroutine.
// When Start returns, the connector is ready to receive streams.
type Starter interface{ Start(*Env) }

type Claimer interface {
	Claim(host string, port uint32) int
}

// Kinds maps each connection kind to its config type. The kind is also the protocol policies see.
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
}

// Stream is one channel the tunnel opened to Host:Port for the connection Name.
type Stream struct {
	net.Conn
	*Env
	Name string
	Host string
	Port uint32
	// Gate evaluates one event on this stream. The error carries the message of every rule that denied it.
	Gate func(Event) error
}

// Event is the layers of one policy input; each connector fills the ones it terminates.
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

// endpoint is an upstream URL holding the stored credential, parsed when the config loads.
type endpoint struct{ url.URL }

func (e *endpoint) UnmarshalText(text []byte) error {
	u, err := url.Parse(string(text))
	if err != nil {
		return err
	}
	e.URL = *u
	return nil
}

// address fills in the scheme's default port when the URL names none.
func address(u *url.URL, secure, port, securePort string) string {
	if u.Port() != "" {
		return u.Host
	}
	if u.Scheme == secure {
		port = securePort
	}
	return net.JoinHostPort(u.Hostname(), port)
}

func dialURL(u *url.URL, secure, port, securePort string) (net.Conn, error) {
	ctx, cancel := context.WithTimeout(context.Background(), dialTimeout)
	defer cancel()
	target := address(u, secure, port, securePort)
	if u.Scheme == secure {
		return (&tls.Dialer{Config: &tls.Config{ServerName: u.Hostname()}}).DialContext(ctx, "tcp", target)
	}
	return (&net.Dialer{}).DialContext(ctx, "tcp", target)
}

// chanListener hands dispatched channels to a server that wants a net.Listener.
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
