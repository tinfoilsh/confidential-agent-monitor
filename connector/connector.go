// Package connector defines protocol servers, captured requests and their host-provided capabilities.
package connector

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"net"
	"net/http"

	"github.com/tinfoilsh/monitor/facts"
	"golang.org/x/crypto/ssh"
)

// Server handles one stream. A Runner calls serve inline once ready.
// serve stops accepting work when its context ends and returns after the last operation.
type Server interface{ Serve(*Stream, *Env) }

type Runner interface {
	Run(ctx context.Context, e *Env, serve func(context.Context)) error
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
	if c, ok := s.(interface{ Control() http.Handler }); ok {
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
