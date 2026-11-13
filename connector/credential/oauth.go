package credential

import (
	"cmp"
	"context"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"time"
	"unicode"

	"github.com/modelcontextprotocol/go-sdk/auth"
	"github.com/modelcontextprotocol/go-sdk/oauthex"
	"golang.org/x/oauth2"
)

const (
	offlineAccess     = "offline_access"
	maxDeviceExpiry   = 24 * time.Hour
	maxDeviceInterval = 3600
)

var (
	prompts    = []string{"", "none", "login", "consent", "select_account"}
	authStyles = map[string]oauth2.AuthStyle{"": oauth2.AuthStyleAutoDetect, "header": oauth2.AuthStyleInHeader, "params": oauth2.AuthStyleInParams}
)

var errNoRegistration = errors.New("this service does not register clients automatically; enter the client ID and secret of an OAuth app registered with it")

var errLoopback = errors.New("this service does not accept sign-ins from this page; open this Perimeter with tinfoil perimeter open to sign in on your computer")

// A grant without an AuthURL is signed in at the authorization server its Resource names (RFC 9728).
// A grant without a refresh token keeps its access token until Expiry, then needs a new sign-in.
type oauth struct {
	AuthorizeParams map[string]string     `json:"authorize_params,omitempty"`
	Registration    *callbackRegistration `json:"callback_registration,omitempty"`
	OIDC            *oidc                 `json:"oidc,omitempty"`
	RequiredScopes  []string              `json:"required_scopes,omitempty"`
	AuthURL         string                `json:"auth_url"`
	DeviceAuthURL   string                `json:"device_auth_url,omitempty"`
	TokenURL        string                `json:"token_url"`
	ClientID        string                `json:"client_id"`
	ClientSecret    string                `json:"client_secret"`
	RefreshToken    string                `json:"refresh_token"`
	Scope           string                `json:"scope"`
	Resource        string                `json:"resource"`
	Prompt          string                `json:"prompt,omitempty"`
	AuthStyle       string                `json:"auth_style,omitempty"`
	TokenType       string                `json:"token_type,omitempty"`
	Loopback        bool                  `json:"loopback,omitempty"`
	DefaultClient   *defaultClient        `json:"default_client,omitempty"`
	AccessToken     string                `json:"access_token,omitempty"`
	Expiry          time.Time             `json:"expiry,omitzero"`
}

// A preset's own OAuth app signs in when the owner names no client.
type defaultClient struct {
	ClientID     string `json:"client_id"`
	ClientSecret string `json:"client_secret,omitempty"`
	Loopback     bool   `json:"loopback,omitempty"`
}

// These parameters apply until the authorization callback issues a client ID.
// OIDC verification binds the issued ID to its authenticated account.
type callbackRegistration struct {
	ClientID        string            `json:"client_id"`
	AuthorizeParams map[string]string `json:"authorize_params,omitempty"`
}

func (o *oauth) validate() error {
	if o.DeviceAuthURL != "" && (o.ClientID == "" || o.TokenURL == "" || o.OIDC != nil || o.Registration != nil) {
		return errors.New("device sign-in requires a client ID and token URL, without OIDC or callback registration")
	}
	params := []map[string]string{o.AuthorizeParams}
	if o.Registration != nil {
		if o.Registration.ClientID == "" || o.OIDC == nil || o.ClientSecret != "" || o.AuthURL == "" || o.TokenURL == "" {
			return errors.New("callback registration requires a public client and OIDC verification")
		}
		params = append(params, o.Registration.AuthorizeParams)
	}
	for _, fields := range params {
		for key := range fields {
			if slices.Contains([]string{"client_id", "client_secret", "redirect_uri", "response_type", "state", "nonce", "code_challenge", "code_challenge_method", "scope", "resource", "id_token_hint"}, key) {
				return errors.New("authorization parameters cannot override OAuth security fields")
			}
		}
	}
	if o.OIDC != nil {
		if o.OIDC.Issuer == "" || o.OIDC.JWKSURL == "" || !slices.Contains(strings.Fields(o.Scope), "openid") {
			return errors.New("OIDC requires issuer, jwks_url, and the openid scope")
		}
		if err := secure(o.OIDC.Issuer, o.OIDC.JWKSURL); err != nil {
			return err
		}
	}
	if _, ok := authStyles[o.AuthStyle]; !ok || !slices.Contains(prompts, o.Prompt) {
		return errors.New("oauth prompt or auth_style is not supported")
	}
	return secure(o.AuthURL, o.DeviceAuthURL, o.TokenURL, o.Resource)
}

// secure requires https without user information or fragments, and never quotes an endpoint that may hold a password.
func secure(endpoints ...string) error {
	for _, endpoint := range endpoints {
		u, err := url.Parse(endpoint)
		if endpoint != "" && (err != nil || u.Scheme != "https" || u.Host == "" || u.User != nil || u.Fragment != "" || strings.Contains(endpoint, "#")) {
			return errors.New("oauth endpoints must be https URLs without user information or fragments")
		}
	}
	return nil
}

func (o *oauth) config(redirect string) oauth2.Config {
	return oauth2.Config{
		ClientID: o.ClientID, ClientSecret: o.ClientSecret, RedirectURL: redirect, Scopes: strings.Fields(o.Scope),
		Endpoint: oauth2.Endpoint{AuthURL: o.AuthURL, DeviceAuthURL: o.DeviceAuthURL, TokenURL: o.TokenURL, AuthStyle: authStyles[o.AuthStyle]},
	}
}

func encodeGrant(grant oauth) json.RawMessage {
	raw, _ := json.Marshal(map[string]oauth{"oauth": grant})
	return raw
}

// A SignIn waits for an authorization callback or device approval. The device
// code stays private; only URL, State, UserCode and Expires go to the owner UI.
type SignIn struct {
	URL, State string
	UserCode   string
	Expires    time.Time
	device     *oauth2.DeviceAuthResponse
	grant      oauth
	config     *oauth2.Config
	client     *http.Client
	verifier   string
	opts       []oauth2.AuthCodeOption
	nonce      string
}

// NewSignIn starts the configured OAuth flow, registering a client first when the secret names only its resource.
func NewSignIn(ctx context.Context, client *http.Client, secret json.RawMessage, redirect string) (*SignIn, error) {
	var v Value
	if err := json.Unmarshal(secret, &v); err != nil {
		return nil, err
	}
	if v.grant == nil {
		return nil, errors.New("the secret is not an oauth grant")
	}
	s := &SignIn{State: rand.Text(), grant: *v.grant, client: client, verifier: oauth2.GenerateVerifier()}
	if c := s.grant.DefaultClient; c != nil && s.grant.ClientID == "" {
		s.grant.ClientID, s.grant.ClientSecret, s.grant.Loopback = c.ClientID, c.ClientSecret, s.grant.Loopback || c.Loopback
	}
	if s.grant.DeviceAuthURL != "" {
		config := s.grant.config("")
		s.config = &config
		return s, s.startDevice(ctx)
	}
	if s.grant.Loopback && !loopback(redirect) {
		return nil, errLoopback
	}
	if s.grant.AuthURL == "" {
		if err := s.register(ctx, redirect); errors.Is(err, errNoRegistration) || errors.Is(err, errLoopback) {
			return nil, err
		} else if err != nil {
			return nil, scrub(ctx, "discovery", err)
		}
	}
	if s.grant.Resource != "" {
		s.opts = append(s.opts, oauth2.SetAuthURLParam("resource", s.grant.Resource))
	}
	config := s.grant.config(redirect)
	registering := s.grant.Registration != nil && s.grant.ClientID == ""
	if registering {
		config.ClientID = s.grant.Registration.ClientID
	}
	s.config = &config
	opts := append(slices.Clone(s.opts), oauth2.S256ChallengeOption(s.verifier), oauth2.AccessTypeOffline)
	if s.grant.Prompt != "" {
		opts = append(opts, oauth2.SetAuthURLParam("prompt", s.grant.Prompt))
	}
	if s.grant.OIDC != nil {
		s.nonce = rand.Text()
		opts = append(opts, oauth2.SetAuthURLParam("nonce", s.nonce))
		if s.grant.OIDC.IDToken != "" {
			opts = append(opts, oauth2.SetAuthURLParam("id_token_hint", s.grant.OIDC.IDToken))
		}
	}
	u, err := url.Parse(s.config.AuthCodeURL(s.State, opts...))
	if err != nil {
		return nil, scrub(ctx, "authorization", err)
	}
	query := u.Query()
	params := []map[string]string{s.grant.AuthorizeParams}
	if registering {
		params = append(params, s.grant.Registration.AuthorizeParams)
	}
	for _, fields := range params {
		for key, value := range fields {
			if value == "" {
				query.Del(key)
			} else {
				query.Set(key, value)
			}
		}
	}
	u.RawQuery = query.Encode()
	s.URL = u.String()
	return s, nil
}

func (s *SignIn) startDevice(ctx context.Context) error {
	form := url.Values{"client_id": {s.grant.ClientID}, "scope": {s.grant.Scope}}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, s.grant.DeviceAuthURL, strings.NewReader(form.Encode()))
	if err != nil {
		return scrub(ctx, "device authorization", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")
	resp, err := s.client.Do(req)
	if err != nil {
		return scrub(ctx, "device authorization", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("oauth device authorization failed with status %d", resp.StatusCode)
	}
	var device oauth2.DeviceAuthResponse
	if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&device); err != nil {
		return errors.New("oauth returned an invalid device authorization")
	}
	if device.DeviceCode == "" || device.UserCode == "" || device.VerificationURI == "" ||
		!device.Expiry.After(time.Now()) || time.Until(device.Expiry) > maxDeviceExpiry || device.Interval < 0 || device.Interval > maxDeviceInterval {
		return errors.New("oauth returned an invalid device authorization")
	}
	if err := secure(device.VerificationURI); err != nil {
		return err
	}
	s.device, s.URL, s.UserCode, s.Expires = &device, device.VerificationURI, device.UserCode, device.Expiry
	return nil
}

// WaitDevice respects the provider's polling interval and slow_down responses.
func (s *SignIn) WaitDevice(ctx context.Context) (json.RawMessage, error) {
	t, err := s.config.DeviceAccessToken(context.WithValue(ctx, oauth2.HTTPClient, s.client), s.device)
	if err != nil {
		if errors.Is(err, context.Canceled) {
			return nil, context.Canceled
		}
		if errors.Is(err, context.DeadlineExceeded) {
			return nil, errors.New("sign-in code expired; start again")
		}
		var provider *oauth2.RetrieveError
		if errors.As(err, &provider) {
			switch provider.ErrorCode {
			case "access_denied":
				return nil, errors.New("sign-in was declined; start again to retry")
			case "expired_token":
				return nil, errors.New("sign-in code expired; start again")
			}
		}
		return nil, scrub(ctx, "device sign-in", err)
	}
	grant := s.grant
	if err := grant.acceptToken(t, false); err != nil {
		return nil, err
	}
	return encodeGrant(grant), nil
}

// register discovers the resource's authorization server (RFC 9728, RFC 8414) and, unless the grant names a client, registers with it (RFC 7591).
func (s *SignIn) register(ctx context.Context, redirect string) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, s.grant.Resource, nil)
	if err != nil {
		return err
	}
	u := req.URL
	origin := u.Scheme + "://" + u.Host
	var metadata []string
	resp, err := s.client.Do(req)
	if err != nil {
		return err
	}
	resp.Body.Close()
	challenges, _ := oauthex.ParseWWWAuthenticate(resp.Header.Values("WWW-Authenticate"))
	for _, c := range challenges {
		if m := c.Params["resource_metadata"]; m != "" {
			metadata = append(metadata, m)
		}
	}
	metadata = append(metadata, origin+"/.well-known/oauth-protected-resource"+u.Path, origin+"/.well-known/oauth-protected-resource")
	// Without resource metadata the origin is the authorization server, as in MCP 2025-03-26.
	server, scopes := origin, []string(nil)
	for _, m := range metadata {
		var prm oauthex.ProtectedResourceMetadata
		if secure(m) != nil || !s.getJSON(ctx, m, &prm) {
			continue
		}
		// Metadata covers its resource and the paths beneath it on the same origin.
		named, err := url.Parse(prm.Resource)
		if err != nil || secure(prm.Resource) != nil || named.Host != u.Host || !strings.HasPrefix(strings.TrimSuffix(u.Path, "/")+"/", strings.TrimSuffix(named.Path, "/")+"/") {
			continue
		}
		if len(prm.AuthorizationServers) == 0 {
			return fmt.Errorf("%s names no authorization server", s.grant.Resource)
		}
		s.grant.Resource, server, scopes = prm.Resource, strings.TrimSuffix(prm.AuthorizationServers[0], "/"), prm.ScopesSupported
		break
	}
	if err := secure(server); err != nil {
		return err
	}
	asm, err := auth.GetAuthServerMetadata(ctx, server, s.client)
	// Metadata naming another issuer leads to it, and that issuer's own metadata must name itself.
	var other oauthex.AuthServerMeta
	if a, _ := url.Parse(server); err != nil && s.getJSON(ctx, a.Scheme+"://"+a.Host+"/.well-known/oauth-authorization-server"+a.Path, &other) && other.Issuer != "" && secure(other.Issuer) == nil {
		server = strings.TrimSuffix(other.Issuer, "/")
		asm, err = auth.GetAuthServerMetadata(ctx, server, s.client)
	}
	if err != nil {
		return err
	}
	if asm == nil || asm.AuthorizationEndpoint == "" || asm.TokenEndpoint == "" {
		return fmt.Errorf("%s names no authorization or token endpoint", server)
	}
	if err := secure(asm.AuthorizationEndpoint, asm.TokenEndpoint, asm.RegistrationEndpoint); err != nil {
		return err
	}
	s.grant.AuthURL, s.grant.TokenURL = asm.AuthorizationEndpoint, asm.TokenEndpoint
	if s.grant.Scope == "" {
		if slices.Contains(asm.ScopesSupported, offlineAccess) && !slices.Contains(scopes, offlineAccess) {
			scopes = append(scopes, offlineAccess)
		}
		s.grant.Scope = strings.Join(scopes, " ")
	}
	if s.grant.ClientID != "" {
		if methods := asm.TokenEndpointAuthMethodsSupported; s.grant.AuthStyle == "" && len(methods) > 0 && !slices.Contains(methods, "client_secret_basic") {
			s.grant.AuthStyle = "params"
		}
		return nil
	}
	if asm.RegistrationEndpoint == "" {
		return errNoRegistration
	}
	registration := &oauthex.ClientRegistrationMetadata{
		RedirectURIs: []string{redirect}, ClientName: "Perimeter", GrantTypes: []string{"authorization_code"},
		ResponseTypes: []string{"code"},
	}
	if slices.Contains(asm.GrantTypesSupported, "refresh_token") {
		registration.GrantTypes = append(registration.GrantTypes, "refresh_token")
	}
	// Monitor is a public PKCE client. Some MCP providers support only "none";
	// omitting it would request the RFC 7591 default, client_secret_basic.
	if slices.Contains(asm.TokenEndpointAuthMethodsSupported, "none") {
		registration.TokenEndpointAuthMethod = "none"
	}
	reg, err := oauthex.RegisterClient(ctx, asm.RegistrationEndpoint, registration, s.client)
	var refused *oauthex.ClientRegistrationError
	if errors.As(err, &refused) && refused.ErrorCode == "invalid_redirect_uri" && !loopback(redirect) {
		return errLoopback
	}
	if err != nil {
		return err
	}
	s.grant.ClientID, s.grant.ClientSecret = reg.ClientID, reg.ClientSecret
	switch reg.TokenEndpointAuthMethod {
	case "none", "client_secret_post":
		s.grant.AuthStyle = "params"
	case "client_secret_basic":
		s.grant.AuthStyle = "header"
	}
	return nil
}

func loopback(redirect string) bool {
	u, err := url.Parse(redirect)
	return err == nil && (u.Hostname() == "localhost" || net.ParseIP(u.Hostname()).IsLoopback())
}

func (s *SignIn) getJSON(ctx context.Context, u string, v any) bool {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return false
	}
	resp, err := s.client.Do(req)
	if err != nil {
		return false
	}
	defer resp.Body.Close()
	return resp.StatusCode == http.StatusOK && json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(v) == nil
}

// Exchange returns the replacement record for the authorized scope.
func (s *SignIn) Exchange(ctx context.Context, code, clientID string) (json.RawMessage, error) {
	if code == "" {
		return nil, errors.New("the sign-in callback has no authorization code")
	}
	grant, config := s.grant, *s.config
	if grant.Registration != nil && grant.ClientID == "" {
		if clientID == "" || clientID == grant.Registration.ClientID || len(clientID) > 512 || strings.ContainsAny(clientID, " \r\n\t") {
			return nil, errors.New("authorization did not return an issued client ID; start sign-in again")
		}
		grant.ClientID, config.ClientID = clientID, clientID
	} else if clientID != "" && clientID != grant.ClientID {
		return nil, errors.New("authorization returned a different client registration")
	}
	t, err := config.Exchange(context.WithValue(ctx, oauth2.HTTPClient, s.client), code, append(slices.Clone(s.opts), oauth2.VerifierOption(s.verifier))...)
	if err != nil {
		return nil, scrub(ctx, "exchange", err)
	}
	if err := grant.acceptToken(t, false); err != nil {
		return nil, err
	}
	if grant.OIDC != nil {
		identity := *grant.OIDC
		if err := identity.verify(ctx, s.client, t, grant.ClientID, s.nonce); err != nil {
			return nil, err
		}
		grant.OIDC = &identity
	}
	return encodeGrant(grant), nil
}

func (o *oauth) acceptToken(t *oauth2.Token, refresh bool) error {
	if t.AccessToken == "" || !strings.EqualFold(t.Type(), cmp.Or(o.TokenType, "Bearer")) {
		return errors.New("oauth returned an invalid bearer token")
	}
	scope, _ := t.Extra("scope").(string)
	// GitHub returns comma-separated scopes; other providers use spaces.
	scope = strings.Join(strings.FieldsFunc(scope, func(r rune) bool { return r == ',' || unicode.IsSpace(r) }), " ")
	if scope == "" && refresh {
		scope = o.Scope
	}
	for _, required := range o.RequiredScopes {
		if !slices.Contains(strings.Fields(scope), required) {
			return errors.New("required OAuth permissions were not granted; sign in again")
		}
	}
	if scope != "" {
		o.Scope = scope
	}
	o.AccessToken, o.RefreshToken, o.Expiry = t.AccessToken, t.RefreshToken, t.Expiry
	return nil
}

// oauth2.TokenSource handles token formats, client authentication, and rotation,
// but does not send RFC 8707 resource indicators on refresh requests.
type resourceTransport struct {
	http.RoundTripper
	endpoint, resource string
}

func (t resourceTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	if r.Method == http.MethodPost && r.URL.String() == t.endpoint {
		body, err := io.ReadAll(r.Body)
		r.Body.Close()
		if err != nil {
			return nil, err
		}
		form, err := url.ParseQuery(string(body))
		if err != nil {
			return nil, err
		}
		form.Set("resource", t.resource)
		r = r.Clone(r.Context())
		encoded := form.Encode()
		r.GetBody = func() (io.ReadCloser, error) { return io.NopCloser(strings.NewReader(encoded)), nil }
		r.Body, _ = r.GetBody()
		r.ContentLength = int64(len(encoded))
	}
	return t.RoundTripper.RoundTrip(r)
}

func (o *oauth) refresh(ctx context.Context, client *http.Client, token *oauth2.Token) (*oauth2.Token, error) {
	if client == nil {
		return nil, errors.New("no client can refresh this grant")
	}
	if o.Resource != "" {
		copy := *client
		transport := copy.Transport
		if transport == nil {
			transport = http.DefaultTransport
		}
		copy.Transport = resourceTransport{transport, o.TokenURL, o.Resource}
		client = &copy
	}
	config := o.config("")
	return config.TokenSource(context.WithValue(ctx, oauth2.HTTPClient, client), token).Token()
}
