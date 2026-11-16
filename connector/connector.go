// Package connector defines protocol servers, captured requests and their host-provided capabilities.
package connector

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"io"
	"maps"
	"net"
	"net/http"
	"net/url"

	"github.com/tinfoilsh/confidential-agent-monitor/core/facts"
	"golang.org/x/crypto/ssh"
)

// Handler serves the streams of one installed setup, which never changes under it. The host
// opens a handler for each new setup and closes the previous one, if it is an io.Closer,
// after canceling its streams; Close may overlap their return.
type Handler interface {
	ServeStream(*Stream)
}

type HandlerFunc func(*Stream)

func (f HandlerFunc) ServeStream(s *Stream) { f(s) }

// Open installs a setup's parsed data and secret handles; its context bounds installation, not the handler's lifetime.
type Open func(context.Context, Prepared, map[string]Secret, *Env) (Handler, error)

// A Secret is a credential a connection was granted; the host passes one for every name
// in Prepared.SecretNames. Placeholder is the public reference agents send in its place.
type Secret interface {
	Configured() bool
	Value(context.Context) (string, error)
	Placeholder() string
}

// Prepared is a pure parser result. The host records Source for isolated
// execution; Value belongs to the concrete protocol.
type Prepared struct {
	Source      Setup
	Value       any
	Claim       func(string, uint32) int
	Discovery   Discovery
	Operations  map[string]facts.OperationSummary // Optional, pure catalog projection; nil means no operation listing.
	SecretNames []string
	// Hosts lists the upstream hosts and host patterns the setup names.
	Hosts []string
}

type Controller interface{ Control() http.Handler }

// Kind registers a concrete connector.
type Kind struct {
	// PerMessage promises that each operation is gated against captured input.
	// Such streams can stay open across label changes and gate the next operation.
	// Opaque sessions keep the default: close when another operation changes the label.
	PerMessage  bool
	UsesHostKey bool
	// Placeholders lists credential placeholders for agents to send in place of secrets.
	Placeholders bool
	// Host reaches host resources outside Env, so only local development registers it.
	Host     bool
	Parse    func(Setup) (Prepared, error)
	Open     Open
	Settings any // Optional pointer to deployment settings, filled before Parse in a worker.
}

// Instance is one kind's handler run outside a Monitor, as a worker or a test host runs it.
type Instance struct {
	Handler
	Prepared Prepared
	// Gate admits the operations of streams that Open serves.
	Gate Gate
}

// Start parses setup and opens a handler of kind for it.
func Start(ctx context.Context, kind Kind, setup Setup, secrets map[string]Secret, env *Env) (*Instance, error) {
	prepared, err := kind.Parse(setup)
	if err != nil {
		return nil, err
	}
	prepared.Source = setup
	h, err := kind.Open(ctx, prepared, secrets, env)
	if err != nil {
		return nil, err
	}
	return &Instance{Handler: h, Prepared: prepared}, nil
}

// Serve runs conn as a stream to host:port until it ends; host is empty for a stream addressed by name.
func (i *Instance) Serve(ctx context.Context, conn net.Conn, name, host string, port uint32, gate Gate) {
	s := NewStream(ctx, conn)
	defer s.Close()
	s.Name, s.Host, s.Port, s.Gate = name, host, port, gate
	i.ServeStream(s)
}

// Open serves a stream to a target the setup claims under i.Gate, as a Monitor does after admission.
func (i *Instance) Open(ctx context.Context, host string, port uint32, accept func() (net.Conn, error)) error {
	if i.Prepared.Claim == nil || i.Prepared.Claim(host, port) < 0 {
		return errors.New("this service does not serve the target")
	}
	conn, err := accept()
	if err == nil {
		i.Serve(ctx, conn, "", host, port, i.Gate)
	}
	return err
}

func (i *Instance) Close() error { return Close(i.Handler) }

// Close closes h if it owns resources.
func Close(h Handler) error {
	if closer, ok := h.(io.Closer); ok {
		return closer.Close()
	}
	return nil
}

// Control handles private host HTTP after owner authentication.
func Control(h Handler) http.Handler {
	if c, ok := h.(Controller); ok {
		return c.Control()
	}
	return http.NotFoundHandler()
}

// Detailer reports fixed startup details after the connector becomes ready.
type Detailer interface {
	Details() json.RawMessage
}

type Readier interface{ Ready() error }

type Env struct {
	TLS     *tls.Config // Handshakes must run directly on the *Stream, which the certificate is issued for.
	HostKey ssh.Signer
	Dialer  Dialer
}

type Dialer interface {
	DialContext(context.Context, string, string) (net.Conn, error)
}

type Setup struct {
	Config, Definition, Options json.RawMessage
	Vocabulary                  facts.Vocabulary
}

type Discovery struct {
	Hosts []string
	Slots any
}

type Endpoint struct {
	SecretConfig
	URL    url.URL `json:"-"`
	RawURL string  `json:"url"`
	User   string  `json:"user"`
}

func (e *Endpoint) Parse() error {
	u, err := ParseURL(e.RawURL)
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
	Semantics `json:"-"`
	Secrets   map[string]Secret `json:"-"`
}

// Semantics is the connector's immutable, connection-scoped preset projection.
// It contains neither access rules nor mutable global configuration.
type Semantics struct {
	Title           string
	Catalog         struct{ Actions map[string]facts.Action }
	Address, Origin string
}

type semantic interface{ semantics() *Semantics }

func (c *Semantics) semantics() *Semantics { return c }

// ParseSetup decodes the protocol configuration, its selected preset fields and
// local semantic options once each, without opening resources or reading secrets.
func ParseSetup(setup Setup, config any, preset semantic) error {
	if err := facts.DecodeNumbers(setup.Config, config); err != nil {
		return err
	}
	if len(setup.Definition) != 0 {
		if err := json.Unmarshal(setup.Definition, preset); err != nil {
			return err
		}
	}
	var options struct{ Address, Origin string }
	if len(setup.Options) != 0 {
		if err := json.Unmarshal(setup.Options, &options); err != nil {
			return err
		}
	}
	semantics := preset.semantics()
	semantics.Address, semantics.Origin = options.Address, options.Origin
	return nil
}

func (c *Semantics) Capture(f facts.Facts) facts.Event { return c.CaptureResult(f, nil) }

func (c *Semantics) CaptureResult(f facts.Facts, invalid error) facts.Event {
	if f.Operation != nil {
		f.Operation = f.Operation.Resolve(c.Catalog.Actions)
	}
	return facts.Capture(f, invalid)
}

// Secret returns an empty value for a declared but unconfigured credential.
func (c *SecretConfig) Secret(ctx context.Context, name string) (string, error) {
	return c.Secrets[name].Value(ctx)
}

func (c *SecretConfig) Bind(secrets map[string]Secret) { c.Secrets = maps.Clone(secrets) }
