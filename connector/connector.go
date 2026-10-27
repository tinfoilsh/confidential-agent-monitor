// Package connector defines protocol servers, captured requests and their host-provided capabilities.
package connector

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"net/url"

	"github.com/tinfoilsh/monitor/connector/credential"
	"github.com/tinfoilsh/monitor/facts"
	"golang.org/x/crypto/ssh"
)

// Server owns resources across setup changes. Update installs parsed data and
// scoped handles; its context bounds installation, not the installed lifetime.
// The host serializes Update and final Close. Update may overlap admitted uses;
// final Close follows their cancellation and return.
type Server interface {
	Serve(*Stream, *Env)
	Update(context.Context, Prepared, map[string]*credential.Value, *Env) error
}

// Prepared is a pure parser result. Source is sent to isolated execution; Value
// belongs to the concrete protocol. A nil Secrets slice means no credential scope.
type Prepared struct {
	Source      Setup
	Value       any
	Claim       func(string, uint32) int
	Discovery   Discovery
	SecretNames []string
}

type Controller interface{ Control() http.Handler }

// Kind registers a concrete connector.
type Kind struct {
	// PerMessage promises that each operation is gated against captured input.
	// Such streams can stay open across label changes and gate the next operation.
	// Opaque sessions keep the default: close when another operation changes the label.
	PerMessage  bool
	UsesHostKey bool
	Parse       func(Setup) (Prepared, error)
	New         func() Server
	Settings    any // Optional pointer to deployment settings, filled before Parse in a worker.
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

type Setup struct {
	Config, Definition, Options json.RawMessage
}

type Discovery struct {
	Hosts        []string
	Slots        any
	Placeholders map[string]string
}

type Endpoint struct {
	SecretConfig
	url.URL `json:"-"`
	Address string `json:"url"`
	User    string `json:"user"`
}

func (e *Endpoint) Parse() error {
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
	Semantics `json:"-"`
	Secrets   map[string]*credential.Value `json:"secrets,omitempty"`
}

// Semantics is the connector's immutable, connection-scoped preset projection.
// It contains neither access rules nor mutable global configuration.
type Semantics struct {
	Title           string
	Catalog         struct{ Actions map[string]facts.Action }
	Address, Origin string
}

// ParseSetup decodes the protocol configuration, its selected preset fields and
// local semantic options once each, without opening resources or reading secrets.
func ParseSetup(setup Setup, config, preset any, semantics *Semantics) error {
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
	semantics.Address, semantics.Origin = options.Address, options.Origin
	return nil
}

// Declarations accepts empty source slots, never source-embedded credential values.
func (c *SecretConfig) Declarations(required ...string) ([]string, error) {
	names := append(make([]string, 0, len(c.Secrets)+len(required)), required...)
	for name, value := range c.Secrets {
		if value != nil && value.Raw() != nil {
			return nil, errors.New("set credentials through account settings")
		}
		names = append(names, name)
	}
	c.Secrets = nil
	return names, nil
}

func (c *Semantics) Capture(f facts.Facts, err error) facts.Event {
	if f.Operation != nil {
		f.Operation = f.Operation.Resolve(c.Catalog.Actions)
	}
	return facts.Capture(f, err)
}

// Secret returns an empty value for optional, unconfigured authentication.
func (c *SecretConfig) Secret(ctx context.Context, name string) (string, error) {
	if value := c.Secrets[name]; value != nil {
		return value.Value(ctx)
	}
	return "", nil
}
