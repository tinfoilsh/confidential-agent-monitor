// Package connector defines protocol servers, captured requests and their host-provided capabilities.
package connector

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"net"
	"net/http"
	"net/url"

	"github.com/tinfoilsh/monitor/connector/credential"
	"github.com/tinfoilsh/monitor/facts"
	"golang.org/x/crypto/ssh"
)

// Server handles one stream. A Runner calls serve inline once ready.
// serve stops accepting work when its context ends and returns after the last operation.
type Server interface{ Serve(*Stream, *Env) }

type Runner interface {
	Run(ctx context.Context, e *Env, serve func(context.Context)) error
}

type Preparer interface{ Prepare() error }

type Controller interface{ Control() http.Handler }

type SecretHolder interface {
	SecretValues() map[string]*credential.Value
}

// Claimer scores how well it serves a forwarded target; a negative score declines it.
type Claimer interface {
	Claim(host string, port uint32) int
}

func Decode(raw []byte, s Server) error {
	if err := facts.DecodeNumbers(raw, s); err != nil {
		return err
	}
	if p, ok := s.(Preparer); ok {
		return p.Prepare()
	}
	return nil
}

// Definition registers a connector and the request types it can submit.
type Definition struct {
	// PerMessage promises that each operation is gated against captured input.
	// Such streams can stay open across label changes and gate the next operation.
	// Opaque sessions keep the default: close when another operation changes the label.
	PerMessage bool
	HostKey    bool
	NewConfig  func() Server
	Requests   []Request
	Settings   any // Optional pointer to deployment settings, filled before NewConfig in a worker.
}

// Control handles private host HTTP after owner authentication.
func Control(s Server) http.Handler {
	if c, ok := s.(Controller); ok {
		return c.Control()
	}
	return http.NotFoundHandler()
}

// Detailer reports fixed startup details after the connector becomes ready.
type Detailer interface {
	Details() json.RawMessage
}

type Env struct {
	TLS     *tls.Config
	HostKey ssh.Signer
	Dialer  Dialer
}

type Dialer interface {
	DialContext(context.Context, string, string) (net.Conn, error)
}

// Request carries parsed input to the monitor. Describe interprets it once
// against the current settings, without executing it or mutating the input.
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

type Endpoint struct {
	SecretConfig
	url.URL `json:"-"`
	Address string `json:"url"`
	User    string `json:"user"`
}

func (e *Endpoint) Prepare() error {
	u, err := ParseURL(e.Address)
	if err != nil {
		return err
	}
	if e.User != "" {
		u.User = url.User(e.User)
	}
	e.URL = *u
	return nil
}

// SecretConfig owns the credential handles shared with the connection runtime.
type SecretConfig struct {
	Secrets map[string]*credential.Value `json:"secrets,omitempty"`
}

func (c *SecretConfig) SecretValues() map[string]*credential.Value {
	if c.Secrets == nil {
		c.Secrets = map[string]*credential.Value{}
	}
	return c.Secrets
}

// Secret returns an empty value for optional, unconfigured authentication.
func (c *SecretConfig) Secret(ctx context.Context, name string) (string, error) {
	if value := c.Secrets[name]; value != nil {
		return value.Value(ctx)
	}
	return "", nil
}
