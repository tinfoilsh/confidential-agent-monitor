package credential

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"time"

	"golang.org/x/oauth2"
)

var ErrNotConfigured = errors.New("credential is not configured")

// Value is a string or an OAuth grant. Disclosure is controlled by field metadata.
type Value struct {
	raw     json.RawMessage
	text    string
	grant   *oauth
	token   *oauth2.Token
	refresh chan struct{}
	Save    func(context.Context, json.RawMessage, json.RawMessage) error
}

func (v *Value) UnmarshalJSON(raw []byte) error {
	*v = Value{raw: bytes.Clone(raw)}
	if json.Unmarshal(raw, &v.text) == nil {
		return nil
	}
	var cfg struct {
		OAuth *oauth `json:"oauth"`
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&cfg); err != nil {
		return err
	}
	if cfg.OAuth == nil {
		return errors.New("credential must be a string or an oauth grant")
	}
	v.grant = cfg.OAuth
	v.token = &oauth2.Token{RefreshToken: v.grant.RefreshToken}
	v.refresh = make(chan struct{}, 1)
	return nil
}

func (v *Value) Raw() json.RawMessage { return v.raw }

func (v *Value) Value(ctx context.Context) (string, error) {
	if v == nil {
		return "", ErrNotConfigured
	}
	if v.grant == nil {
		if bytes.Equal(v.raw, []byte("null")) {
			return "", ErrNotConfigured
		}
		return v.text, nil
	}
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	select {
	case v.refresh <- struct{}{}:
		defer func() { <-v.refresh }()
	case <-ctx.Done():
		return "", ctx.Err()
	}
	grant := *v.grant
	t := v.token
	if !t.Valid() {
		if t.RefreshToken == "" {
			return "", ErrNotConfigured
		}
		var err error
		config := oauth2.Config{ClientID: grant.ClientID, ClientSecret: grant.ClientSecret, Endpoint: oauth2.Endpoint{TokenURL: grant.TokenURL}}
		if t, err = config.TokenSource(ctx, t).Token(); err != nil {
			return "", err
		}
		v.token = t
	}
	if grant.RefreshToken != t.RefreshToken {
		grant.RefreshToken = t.RefreshToken
		raw := encodeGrant(grant)
		if v.Save != nil {
			if err := v.Save(ctx, v.raw, raw); err != nil {
				return "", err
			}
		}
		*v.grant, v.raw = grant, raw
	}
	return t.AccessToken, nil
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
	if v.grant.RefreshToken != "" {
		return "oauth"
	}
	return "oauth-required"
}
