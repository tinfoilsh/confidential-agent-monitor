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
	"sync"
	"time"

	"golang.org/x/oauth2"
)

var errNotConfigured = errors.New("credential is not configured")

// Files, when set at start, is the one directory that file credentials are read from.
var Files *os.Root

// Value is a string, an OAuth grant or a file. Disclosure is controlled by field metadata.
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
	resolve func(context.Context) (string, error)

	// Placeholder is a stable reference supplied by Monitor, never the credential itself.
	Placeholder string `json:"-"`
}

// Remote resolves a connection-scoped handle without moving its stored OAuth
// grant or refresh token into the connector's process.
func Remote(configured bool, resolve func(context.Context) (string, error)) *Value {
	v := &Value{resolve: resolve}
	if configured {
		v.raw = json.RawMessage(`""`)
	}
	return v
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
		File  string `json:"file"`
	}
	if err := jsonv2.Unmarshal(raw, &cfg, jsonv2.RejectUnknownMembers(true)); err != nil {
		return err
	}
	if cfg.File != "" && cfg.OAuth == nil && Files != nil {
		// Read at each use, so whatever rotates the file rotates the credential.
		v.resolve = func(context.Context) (string, error) {
			secret, err := Files.ReadFile(cfg.File)
			return strings.TrimRight(string(secret), "\r\n"), err
		}
		return nil
	}
	if cfg.OAuth == nil || cfg.File != "" {
		return errors.New("credential must be a string, an oauth grant or a file under -secrets")
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

// Configured waits for a refresh in progress, which may rotate the record.
func (v *Value) Configured() bool {
	if v == nil {
		return false
	}
	v.lock(context.Background())
	defer func() { <-v.gate }()
	return len(v.raw) > 0
}

func (v *Value) Value(ctx context.Context) (string, error) {
	if v == nil {
		return "", errNotConfigured
	}
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	if v.resolve != nil {
		return v.resolve(ctx)
	}
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
			return "", errNotConfigured
		}
		var err error
		t, err = grant.refresh(ctx, v.Client, t)
		if err != nil {
			return "", scrub(ctx, "refresh", err)
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
		raw := encodeGrant(grant)
		if err := v.Save(ctx, v.raw, raw); err != nil {
			return "", err
		}
		*v.grant, v.raw = grant, raw
	}
	return t.AccessToken, nil
}

// Describe returns only the status needed by the owner editor and the verified
// OIDC account, without exposing tokens.
func Describe(raw json.RawMessage) (kind, account string) {
	var v Value
	if json.Unmarshal(raw, &v) != nil || bytes.Equal(raw, []byte("null")) {
		return "unset", ""
	}
	if v.grant == nil {
		return "static", ""
	}
	if v.grant.OIDC != nil {
		account = v.grant.OIDC.Email
	}
	if v.grant.RefreshToken != "" || v.token.Valid() {
		return "oauth", account
	}
	return "oauth-required", account
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
