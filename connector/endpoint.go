package connector

import (
	"context"
	"net/url"

	"github.com/tinfoilsh/monitor/connector/credential"
	"github.com/tinfoilsh/monitor/facts"
)

type Endpoint struct {
	SecretConfig
	url.URL `json:"-"`
	Address string `json:"url"`
	User    string `json:"user"`
}

func (e *Endpoint) UnmarshalJSON(raw []byte) error {
	type plain Endpoint
	if err := facts.DecodeNumbers(raw, (*plain)(e)); err != nil {
		return err
	}
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
