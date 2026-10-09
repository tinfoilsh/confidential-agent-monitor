package credential

import (
	"bytes"
	"context"
	"encoding/json"
	jsonv2 "encoding/json/v2"
	"errors"
	"fmt"
	"net/http"
	"sync"
	"time"

	"golang.org/x/oauth2"
)

var ErrNotConfigured = errors.New("credential is not configured")

// Value is a string or an OAuth grant. Disclosure is controlled by field metadata.
// Client is the guarded client that refreshes the grant; without one, a grant cannot refresh.
type Value struct {
	raw     json.RawMessage
	text    string
	grant   *oauth
	token   *oauth2.Token
	refresh sync.Once
	gate    chan struct{}
	Save    func(context.Context, json.RawMessage, json.RawMessage) error
	Client  *http.Client
}

func (v *Value) UnmarshalJSON(raw []byte) error {
	*v = Value{raw: bytes.Clone(raw)}
	if bytes.Equal(raw, []byte("null")) {
		v.raw = nil
		return nil
	}
	if json.Unmarshal(raw, &v.text) == nil {
		return nil
	}
	var cfg struct {
		OAuth *oauth `json:"oauth"`
	}
	if err := jsonv2.Unmarshal(raw, &cfg, jsonv2.RejectUnknownMembers(true)); err != nil {
		return err
	}
	if cfg.OAuth == nil {
		return errors.New("credential must be a string or an oauth grant")
	}
	if err := cfg.OAuth.validate(); err != nil {
		return err
	}
	v.grant = cfg.OAuth
	v.token = &oauth2.Token{AccessToken: v.grant.AccessToken, RefreshToken: v.grant.RefreshToken, Expiry: v.grant.Expiry}
	return nil
}

func (v *Value) lock(ctx context.Context) error {
	v.refresh.Do(func() { v.gate = make(chan struct{}, 1) })
	select {
	case v.gate <- struct{}{}:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

// Raw waits for a refresh in progress, which may rotate the record.
func (v *Value) Raw() json.RawMessage {
	v.lock(context.Background())
	defer func() { <-v.gate }()
	return v.raw
}

func (v *Value) Value(ctx context.Context) (string, error) {
	if v == nil {
		return "", ErrNotConfigured
	}
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	if err := v.lock(ctx); err != nil {
		return "", err
	}
	defer func() { <-v.gate }()
	if v.grant == nil {
		return v.text, nil
	}
	grant := *v.grant
	t := v.token
	if !t.Valid() {
		if t.RefreshToken == "" {
			return "", ErrNotConfigured
		}
		var err error
		config := grant.config("")
		if t, err = config.TokenSource(context.WithValue(ctx, oauth2.HTTPClient, v.Client), t).Token(); err != nil {
			return "", scrub(ctx, "refresh", err)
		}
		v.token = t
	}
	if grant.RefreshToken != t.RefreshToken {
		grant.RefreshToken = t.RefreshToken
		raw := encodeGrant(grant)
		if err := v.Save(ctx, v.raw, raw); err != nil {
			return "", err
		}
		*v.grant, v.raw = grant, raw
	}
	return t.AccessToken, nil
}

// Replace serializes owner changes with provider refresh. The persisted compare
// prevents a completed sign-in from overwriting a newer credential.
func (v *Value) Replace(ctx context.Context, before, after json.RawMessage) error {
	var next Value
	if err := json.Unmarshal(after, &next); err != nil {
		return err
	}
	if err := v.lock(ctx); err != nil {
		return err
	}
	defer func() { <-v.gate }()
	if err := v.Save(ctx, before, after); err != nil {
		return err
	}
	v.raw, v.text, v.grant, v.token = next.raw, next.text, next.grant, next.token
	return nil
}

// Describe returns only the status needed by the owner editor.
func Describe(raw json.RawMessage) string {
	var v Value
	if json.Unmarshal(raw, &v) != nil || bytes.Equal(raw, []byte("null")) {
		return "unset"
	}
	if v.grant == nil {
		return "static"
	}
	if v.grant.RefreshToken != "" || v.token.Valid() {
		return "oauth"
	}
	return "oauth-required"
}

// scrub keeps provider responses and request URLs out of errors, since either may hold a secret.
func scrub(ctx context.Context, step string, err error) error {
	if ctx.Err() != nil {
		return ctx.Err()
	}
	var provider *oauth2.RetrieveError
	if errors.As(err, &provider) && provider.Response != nil {
		return fmt.Errorf("oauth %s failed with status %d", step, provider.Response.StatusCode)
	}
	return fmt.Errorf("oauth %s failed", step)
}
