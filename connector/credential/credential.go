package credential

import (
	"context"

	"golang.org/x/oauth2"
	"gopkg.in/yaml.v3"
)

type oauth struct {
	TokenURL     string `yaml:"token_url"`
	ClientID     string `yaml:"client_id"`
	ClientSecret string `yaml:"client_secret"`
	RefreshToken string `yaml:"refresh_token"`
}

// A Credential is a fixed string, or an access token refreshed from an oauth block when it expires.
type Credential struct {
	value  string
	tokens oauth2.TokenSource
}

func (c *Credential) UnmarshalYAML(n *yaml.Node) error {
	if n.Kind == yaml.ScalarNode {
		return n.Decode(&c.value)
	}
	var v struct {
		OAuth oauth `yaml:"oauth"`
	}
	if err := n.Decode(&v); err != nil {
		return err
	}
	config := &oauth2.Config{ClientID: v.OAuth.ClientID, ClientSecret: v.OAuth.ClientSecret, Endpoint: oauth2.Endpoint{TokenURL: v.OAuth.TokenURL}}
	c.tokens = config.TokenSource(context.Background(), &oauth2.Token{RefreshToken: v.OAuth.RefreshToken})
	return nil
}

func (c *Credential) Value() (string, error) {
	if c.tokens == nil {
		return c.value, nil
	}
	t, err := c.tokens.Token()
	if err != nil {
		return "", err
	}
	return t.AccessToken, nil
}
