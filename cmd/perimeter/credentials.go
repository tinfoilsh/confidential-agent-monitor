package main

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base32"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"time"

	oauthauth "github.com/modelcontextprotocol/go-sdk/auth"
	"github.com/modelcontextprotocol/go-sdk/oauthex"
	"github.com/tinfoilsh/confidential-agent-monitor/cmd/perimeter/format"
	"github.com/tinfoilsh/confidential-agent-monitor/connector/credential"
	"golang.org/x/oauth2"
)

const (
	credentialTimeout = 30 * time.Second
	signInClient      = "Perimeter"
)

var signInLimits = credential.SignInLimits{Timeout: 30 * time.Second, Lifetime: 10 * time.Minute, MaxDeviceExpiry: 24 * time.Hour, MaxDeviceInterval: 3600,
	MaxResponseBytes: 1 << 20, MaxClientIDBytes: 512}

var errCredentialChanged = errors.New("credential changed; start again")

var (
	errOAuthLoopback     = errors.New("this service only accepts sign-ins from a loopback address; open this Perimeter on your own computer to sign in")
	errOAuthRegistration = errors.New("this service does not register clients automatically; enter the client ID and secret of an OAuth app registered with it")
)

func beginOAuth(ctx context.Context, client *http.Client, raw json.RawMessage, redirect string) (*credential.SignIn, error) {
	g, err := credential.DecodeGrant(raw)
	if err != nil {
		return nil, err
	}
	if c := g.DefaultClient; c != nil && g.ClientID == "" {
		g.ClientID, g.ClientSecret = c.ClientID, c.ClientSecret
		g.Loopback = g.Loopback || c.Loopback
	}
	if g.DeviceAuthURL != "" {
		return credential.NewDeviceSignIn(ctx, client, *g, signInLimits)
	}
	if g.Loopback && !credential.IsLoopback(redirect) {
		return nil, errOAuthLoopback
	}
	if g.AuthURL == "" {
		if err := discoverOAuth(ctx, client, g, redirect); errors.Is(err, errOAuthRegistration) || errors.Is(err, errOAuthLoopback) {
			return nil, err
		} else if err != nil {
			return nil, credential.Scrub(ctx, "discovery", err)
		}
	}
	return credential.NewAuthCodeSignIn(client, *g, redirect, signInLimits, oauth2.AccessTypeOffline)
}

func discoverOAuth(ctx context.Context, client *http.Client, g *credential.Grant, redirect string) error {
	prm, err := credential.ProtectedResource(ctx, client, g.Resource, signInLimits.MaxResponseBytes)
	if err != nil {
		return err
	}
	u, err := url.Parse(g.Resource)
	if err != nil {
		return err
	}
	server, scopes := u.Scheme+"://"+u.Host, []string(nil)
	if prm != nil {
		if len(prm.AuthorizationServers) == 0 {
			return fmt.Errorf("%s names no authorization server", g.Resource)
		}
		g.Resource = prm.Resource
		server = strings.TrimSuffix(prm.AuthorizationServers[0], "/")
		scopes = slices.Clone(prm.ScopesSupported)
	}
	if err := credential.CheckEndpoints(server); err != nil {
		return err
	}

	asm, err := oauthauth.GetAuthServerMetadata(ctx, server, client)
	if err != nil {
		if issuer := credential.PublishedIssuer(ctx, client, server, signInLimits.MaxResponseBytes); issuer != "" {
			server = strings.TrimSuffix(issuer, "/")
			asm, err = oauthauth.GetAuthServerMetadata(ctx, server, client)
		}
	}
	if err != nil {
		return err
	}
	if asm == nil || asm.AuthorizationEndpoint == "" || asm.TokenEndpoint == "" {
		return fmt.Errorf("%s names no authorization or token endpoint", server)
	}
	if err := credential.CheckEndpoints(asm.AuthorizationEndpoint, asm.TokenEndpoint, asm.RegistrationEndpoint); err != nil {
		return err
	}
	g.AuthURL, g.TokenURL = asm.AuthorizationEndpoint, asm.TokenEndpoint
	if g.Scope == "" {
		if slices.Contains(asm.ScopesSupported, "offline_access") && !slices.Contains(scopes, "offline_access") {
			scopes = append(scopes, "offline_access")
		}
		g.Scope = strings.Join(scopes, " ")
	}

	if g.ClientID != "" {
		if methods := asm.TokenEndpointAuthMethodsSupported; g.AuthStyle == "" && len(methods) > 0 && !slices.Contains(methods, "client_secret_basic") {
			g.AuthStyle = "params"
		}
		return nil
	}
	if asm.RegistrationEndpoint == "" {
		return errOAuthRegistration
	}
	registration := &oauthex.ClientRegistrationMetadata{
		RedirectURIs: []string{redirect}, ClientName: signInClient, GrantTypes: []string{"authorization_code"}, ResponseTypes: []string{"code"},
	}
	if slices.Contains(asm.GrantTypesSupported, "refresh_token") {
		registration.GrantTypes = append(registration.GrantTypes, "refresh_token")
	}
	if slices.Contains(asm.TokenEndpointAuthMethodsSupported, "none") {
		registration.TokenEndpointAuthMethod = "none"
	}
	reg, err := oauthex.RegisterClient(ctx, asm.RegistrationEndpoint, registration, client)
	var refused *oauthex.ClientRegistrationError
	if errors.As(err, &refused) && refused.ErrorCode == "invalid_redirect_uri" && !credential.IsLoopback(redirect) {
		return errOAuthLoopback
	}
	if err != nil {
		return err
	}
	g.ClientID, g.ClientSecret = reg.ClientID, reg.ClientSecret
	switch reg.TokenEndpointAuthMethod {
	case "none", "client_secret_post":
		g.AuthStyle = "params"
	case "client_secret_basic":
		g.AuthStyle = "header"
	}
	return nil
}

func bindCredential(raw json.RawMessage, client *http.Client, save func(ctx context.Context, before, after json.RawMessage) error) (*credential.Value, error) {
	if raw == nil {
		return new(credential.Value), nil
	}
	c, err := format.DecodeCredential(raw)
	switch {
	case err != nil:
		return nil, err
	case c.OAuth != nil:
		before := raw
		return credential.OAuth(c.OAuth, credential.OAuthOptions{Client: client, Timeout: credentialTimeout,
			Save: func(ctx context.Context, grant json.RawMessage) error {
				after := format.OAuthCredential(grant)
				if err := save(ctx, before, after); err != nil {
					return err
				}
				before = after
				return nil
			}})
	case c.File != "":
		if secretFiles == nil {
			return nil, format.ErrCredentialShape
		}
		return credential.File(secretFiles, c.File), nil
	case c.Text != nil:
		return credential.Static(*c.Text), nil
	}
	return new(credential.Value), nil
}

func describeCredential(raw json.RawMessage) (kind, account string) {
	c, err := format.DecodeCredential(raw)
	if err != nil || c.Text == nil && c.File == "" && c.OAuth == nil {
		return "unset", ""
	}
	if c.OAuth == nil {
		return "static", ""
	}
	ready, account, err := credential.DescribeOAuth(c.OAuth)
	switch {
	case err != nil:
		return "unset", ""
	case ready:
		return "oauth", account
	}
	return "oauth-required", account
}

func placeholder(k format.Keys, id format.SecretID) string {
	mac := hmac.New(sha256.New, []byte(k.CAKey))
	mac.Write([]byte("monitor credential placeholder v1\x00"))
	raw, _ := json.Marshal([]string{id.Connection, "", id.Name})
	mac.Write(raw)
	suffix := strings.ToLower(base32.StdEncoding.EncodeToString(mac.Sum(nil))[:9])
	return "tfm_" + id.Connection + "_" + suffix
}

func (s held) unchanged(id format.SecretID, value *credential.Value, before json.RawMessage) bool {
	c := s.settings.Load().connections[id.Connection]
	return c != nil && c.secrets[id.Name] == value && bytes.Equal(s.doc.Credentials.Get(id), before)
}

func (s *state) replaceValue(ctx context.Context, id format.SecretID, value *credential.Value, before, after json.RawMessage) error {
	err := errCredentialChanged
	s.locked(func(h held) {
		if h.unchanged(id, value, before) {
			next := h.doc
			next.Credentials = next.Credentials.Clone()
			next.Credentials.Set(id, bytes.Clone(after))
			err = h.commit(ctx, next)
		}
	})
	return err
}

func (s *state) signInCredential(connection, name string) (json.RawMessage, func(context.Context, json.RawMessage) error, error) {
	id := format.SecretID{Connection: connection, Name: name}
	var value *credential.Value
	var before json.RawMessage
	s.locked(func(h held) {
		if c := s.settings.Load().connections[connection]; c != nil {
			value = c.secrets[name]
		}
		before = bytes.Clone(h.doc.Credentials.Get(id))
	})
	if value == nil {
		return nil, nil, errors.New("credential does not exist")
	}
	return before, func(ctx context.Context, raw json.RawMessage) error {
		return s.writeSettings(ctx, settingsWrite{credentials: format.Secrets{connection: {name: raw}}, check: func(h held) error {
			if !h.unchanged(id, value, before) {
				return errCredentialChanged
			}
			return nil
		}})
	}, nil
}

type signInInput struct {
	Redirect   string          `json:"redirect"`
	Name       string          `json:"name"`
	Credential json.RawMessage `json:"credential"`
}

func (s *state) startSignIn(r *http.Request, req signInInput) (any, error) {
	raw, save, err := s.signInCredential(r.PathValue("name"), req.Name)
	if err != nil {
		return nil, err
	}
	if req.Credential != nil {
		raw = req.Credential
	}
	c, err := format.DecodeCredential(raw)
	if err == nil && c.OAuth == nil {
		err = errors.New("the secret is not an oauth grant")
	}
	if err != nil {
		return nil, err
	}
	from, _ := callerFrom(r.Context())
	client := s.settings.Load().client()
	sign, err := s.signIns.Start(r.Context(), func(ctx context.Context) (*credential.SignIn, error) {
		return beginOAuth(ctx, client, c.OAuth, req.Redirect)
	}, from.Session, func(ctx context.Context, grant json.RawMessage) error {
		return save(ctx, format.OAuthCredential(grant))
	})
	if err != nil {
		return nil, err
	}
	if sign.UserCode != "" {
		return map[string]any{"url": sign.URL, "state": sign.State, "user_code": sign.UserCode, "expires": sign.Expires}, nil
	}
	return map[string]string{"url": sign.URL}, nil
}

func (s *state) finishSignIn(r *http.Request, req credential.SignInResult) (any, error) {
	from, _ := callerFrom(r.Context())
	pending, err := s.signIns.Finish(r.Context(), r.PathValue("state"), from.Session, req)
	if pending {
		return map[string]bool{"pending": true}, nil
	}
	if err == nil && req.Cancel {
		return nil, nil
	}
	return s.viewAfter(r, err)
}
