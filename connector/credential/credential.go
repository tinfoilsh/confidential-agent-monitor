// Package credential holds connector credentials: strings, files read at each use and OAuth grants.
package credential

import (
	"context"
	"encoding/json"
	jsonv2 "encoding/json/v2"
	"errors"
	"fmt"
	"net/http"
	"os"
	"strings"
	"time"

	"golang.org/x/oauth2"
)

var errNotConfigured = errors.New("credential is not configured")

// Value is a string, a file or an OAuth grant; the zero Value is an unset credential.
// Disclosure is controlled by field metadata.
type Value struct {
	configured bool
	text       string
	resolve    func() (string, error)
	grant      *Grant
	token      *oauth2.Token
	gate       chan struct{}
	save       func(context.Context, json.RawMessage) error
	client     *http.Client
	timeout    time.Duration
}

func Static(text string) *Value { return &Value{configured: true, text: text} }

// File reads name under root at each use, so whatever rotates the file rotates the credential.
func File(root *os.Root, name string) *Value {
	return &Value{configured: true, resolve: func() (string, error) {
		secret, err := root.ReadFile(name)
		return strings.TrimRight(string(secret), "\r\n"), err
	}}
}

type OAuthOptions struct {
	// Client refreshes the grant; without one, a grant cannot refresh.
	Client *http.Client
	// Save persists a rotated grant before Value returns its token.
	Save func(context.Context, json.RawMessage) error
	// Timeout bounds one Value call, including its refresh.
	Timeout time.Duration
}

func OAuth(grant json.RawMessage, o OAuthOptions) (*Value, error) {
	g, err := DecodeGrant(grant)
	if err != nil {
		return nil, err
	}
	return &Value{configured: true, grant: g, gate: make(chan struct{}, 1), save: o.Save, client: o.Client, timeout: o.Timeout,
		token: &oauth2.Token{AccessToken: g.AccessToken, RefreshToken: g.RefreshToken, Expiry: g.Expiry}}, nil
}

func DecodeGrant(raw json.RawMessage) (*Grant, error) {
	var g Grant
	if err := jsonv2.Unmarshal(raw, &g, jsonv2.RejectUnknownMembers(true)); err != nil {
		return nil, err
	}
	if err := g.validate(); err != nil {
		return nil, err
	}
	return &g, nil
}

func (v *Value) Configured() bool { return v != nil && v.configured }

func (v *Value) Value(ctx context.Context) (string, error) {
	if v == nil {
		return "", errNotConfigured
	}
	if v.resolve != nil {
		return v.resolve()
	}
	if v.grant == nil {
		return v.text, nil
	}
	ctx, cancel := context.WithTimeout(ctx, v.timeout)
	defer cancel()
	select {
	case v.gate <- struct{}{}:
	case <-ctx.Done():
		return "", ctx.Err()
	}
	defer func() { <-v.gate }()
	grant := *v.grant
	t := v.token
	if !t.Valid() {
		if t.RefreshToken == "" {
			return "", errNotConfigured
		}
		var err error
		t, err = grant.refresh(ctx, v.client, t)
		if err != nil {
			return "", Scrub(ctx, "refresh", err)
		}
		if err := grant.acceptToken(t, true); err != nil {
			return "", err
		}
		v.token = t
	}
	if v.grant.RefreshToken != t.RefreshToken || v.grant.AccessToken != t.AccessToken || !v.grant.Expiry.Equal(t.Expiry) || v.grant.Scope != grant.Scope {
		if err := grant.acceptToken(t, true); err != nil {
			return "", err
		}
		if err := v.save(ctx, encodeGrant(grant)); err != nil {
			return "", err
		}
		*v.grant = grant
	}
	return t.AccessToken, nil
}

// DescribeOAuth reports, without exposing tokens, whether a grant can supply a token
// without a new sign-in, and its verified OIDC account.
func DescribeOAuth(grant json.RawMessage) (ready bool, account string, err error) {
	g, err := DecodeGrant(grant)
	if err != nil {
		return false, "", err
	}
	if g.OIDC != nil {
		account = g.OIDC.Email
	}
	token := oauth2.Token{AccessToken: g.AccessToken, RefreshToken: g.RefreshToken, Expiry: g.Expiry}
	return g.RefreshToken != "" || token.Valid(), account, nil
}

// Scrub keeps provider responses and request URLs out of errors, since either may hold a secret.
func Scrub(ctx context.Context, step string, err error) error {
	if ctx.Err() != nil {
		return ctx.Err()
	}
	var provider *oauth2.RetrieveError
	if errors.As(err, &provider) && provider.Response != nil {
		return fmt.Errorf("oauth %s failed with status %d", step, provider.Response.StatusCode)
	}
	return fmt.Errorf("oauth %s failed", step)
}
