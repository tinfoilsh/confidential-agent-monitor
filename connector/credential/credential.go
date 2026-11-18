package credential

import (
	"bytes"
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

var (
	errNotConfigured = errors.New("credential is not configured")
	errShape         = errors.New("credential must be a string, an oauth grant or a file under -secrets")
)

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

func File(root *os.Root, name string) *Value {
	return &Value{configured: true, resolve: func() (string, error) {
		secret, err := root.ReadFile(name)
		return strings.TrimRight(string(secret), "\r\n"), err
	}}
}

type OAuthOptions struct {
	Client  *http.Client
	Save    func(context.Context, json.RawMessage) error
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

type stored struct {
	text  *string
	file  string
	oauth json.RawMessage
}

func decode(raw json.RawMessage) (stored, error) {
	var c stored
	if bytes.Equal(raw, []byte("null")) {
		return c, nil
	}
	var text string
	if json.Unmarshal(raw, &text) == nil {
		c.text = &text
		return c, nil
	}
	var record struct {
		OAuth json.RawMessage `json:"oauth"`
		File  string          `json:"file"`
	}
	if err := jsonv2.Unmarshal(raw, &record, jsonv2.RejectUnknownMembers(true)); err != nil {
		return c, err
	}
	if bytes.Equal(record.OAuth, []byte("null")) {
		record.OAuth = nil
	}
	if (record.OAuth == nil) == (record.File == "") {
		return c, errShape
	}
	c.file, c.oauth = record.File, record.OAuth
	return c, nil
}

func encodeOAuth(grant json.RawMessage) json.RawMessage {
	raw, _ := json.Marshal(map[string]json.RawMessage{"oauth": grant})
	return raw
}

type Options struct {
	Files   *os.Root
	Client  *http.Client
	Timeout time.Duration
	Save    func(ctx context.Context, before, after json.RawMessage) error
}

// Parse binds a stored credential: a string, a file under Files, or an OAuth grant whose refreshed form Save stores in place of the one before it.
func Parse(raw json.RawMessage, o Options) (*Value, error) {
	if raw == nil {
		return new(Value), nil
	}
	c, err := decode(raw)
	switch {
	case err != nil:
		return nil, err
	case c.oauth != nil:
		before := raw
		return OAuth(c.oauth, OAuthOptions{Client: o.Client, Timeout: o.Timeout,
			Save: func(ctx context.Context, grant json.RawMessage) error {
				after := encodeOAuth(grant)
				if err := o.Save(ctx, before, after); err != nil {
					return err
				}
				before = after
				return nil
			}})
	case c.file != "":
		if o.Files == nil {
			return nil, errShape
		}
		return File(o.Files, c.file), nil
	case c.text != nil:
		return Static(*c.text), nil
	}
	return new(Value), nil
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

func Describe(raw json.RawMessage) (kind, account string) {
	c, err := decode(raw)
	if err != nil || c.text == nil && c.file == "" && c.oauth == nil {
		return "unset", ""
	}
	if c.oauth == nil {
		return "static", ""
	}
	g, err := DecodeGrant(c.oauth)
	if err != nil {
		return "unset", ""
	}
	if g.OIDC != nil {
		account = g.OIDC.Email
	}
	token := oauth2.Token{AccessToken: g.AccessToken, RefreshToken: g.RefreshToken, Expiry: g.Expiry}
	if g.RefreshToken != "" || token.Valid() {
		return "oauth", account
	}
	return "oauth-required", account
}

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
