package credential

import (
	"context"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"time"

	"github.com/modelcontextprotocol/go-sdk/auth"
	"github.com/modelcontextprotocol/go-sdk/oauthex"
	"golang.org/x/oauth2"
)

const offlineAccess = "offline_access"

var (
	prompts    = []string{"", "none", "login", "consent", "select_account"}
	authStyles = map[string]oauth2.AuthStyle{"": oauth2.AuthStyleAutoDetect, "header": oauth2.AuthStyleInHeader, "params": oauth2.AuthStyleInParams}
)

// A grant without an AuthURL is signed in at the authorization server its Resource names (RFC 9728).
// A grant without a refresh token keeps its access token until Expiry, then needs a new sign-in.
type oauth struct {
	AuthorizeParams map[string]string     `json:"authorize_params,omitempty"`
	Registration    *callbackRegistration `json:"callback_registration,omitempty"`
	OIDC            *oidc                 `json:"oidc,omitempty"`
	RequiredScopes  []string              `json:"required_scopes,omitempty"`
	AuthURL         string                `json:"auth_url"`
	TokenURL        string                `json:"token_url"`
	ClientID        string                `json:"client_id"`
	ClientSecret    string                `json:"client_secret"`
	RefreshToken    string                `json:"refresh_token"`
	Scope           string                `json:"scope"`
	Resource        string                `json:"resource"`
	Prompt          string                `json:"prompt,omitempty"`
	AuthStyle       string                `json:"auth_style,omitempty"`
	AccessToken     string                `json:"access_token,omitempty"`
	Expiry          time.Time             `json:"expiry,omitzero"`
}

// These parameters apply until the authorization callback issues a client ID.
// OIDC verification binds the issued ID to its authenticated account.
type callbackRegistration struct {
	ClientID        string            `json:"client_id"`
	AuthorizeParams map[string]string `json:"authorize_params,omitempty"`
}

func (o *oauth) validate() error {
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
	return secure(o.AuthURL, o.TokenURL, o.Resource)
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
		Endpoint: oauth2.Endpoint{AuthURL: o.AuthURL, TokenURL: o.TokenURL, AuthStyle: authStyles[o.AuthStyle]},
	}
}

func encodeGrant(grant oauth) json.RawMessage {
	raw, _ := json.Marshal(map[string]oauth{"oauth": grant})
	return raw
}

// A SignIn is an authorization code flow waiting for the provider to redirect back with a code.
type SignIn struct {
	URL, State string
	grant      oauth
	config     *oauth2.Config
	client     *http.Client
	verifier   string
	opts       []oauth2.AuthCodeOption
	nonce      string
}

// NewSignIn starts the flow for an oauth secret, registering a client first when the secret names only its resource.
func NewSignIn(ctx context.Context, client *http.Client, secret json.RawMessage, redirect string) (*SignIn, error) {
	var v Value
	if err := json.Unmarshal(secret, &v); err != nil {
		return nil, err
	}
	if v.grant == nil {
		return nil, errors.New("the secret is not an oauth grant")
	}
	s := &SignIn{State: rand.Text(), grant: *v.grant, client: client, verifier: oauth2.GenerateVerifier()}
	if s.grant.AuthURL == "" {
		if err := s.register(ctx, redirect); err != nil {
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

// register discovers the resource's authorization server (RFC 9728, RFC 8414) and registers with it (RFC 7591).
func (s *SignIn) register(ctx context.Context, redirect string) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, s.grant.Resource, nil)
	if err != nil {
		return err
	}
	u := req.URL
	metadata := u.Scheme + "://" + u.Host + "/.well-known/oauth-protected-resource" + u.Path
	resp, err := s.client.Do(req)
	if err != nil {
		return err
	}
	resp.Body.Close()
	challenges, _ := oauthex.ParseWWWAuthenticate(resp.Header.Values("WWW-Authenticate"))
	for _, c := range challenges {
		if m := c.Params["resource_metadata"]; m != "" {
			metadata = m
		}
	}
	if err := secure(metadata); err != nil {
		return err
	}
	prm, err := oauthex.GetProtectedResourceMetadata(ctx, metadata, s.grant.Resource, s.client)
	if err != nil {
		return err
	}
	if len(prm.AuthorizationServers) == 0 {
		return fmt.Errorf("%s names no authorization server", s.grant.Resource)
	}
	if err := secure(prm.AuthorizationServers[0]); err != nil {
		return err
	}
	asm, err := auth.GetAuthServerMetadata(ctx, prm.AuthorizationServers[0], s.client)
	if err != nil {
		return err
	}
	if asm == nil || asm.RegistrationEndpoint == "" {
		return fmt.Errorf("%s does not register clients", prm.AuthorizationServers[0])
	}
	if asm.AuthorizationEndpoint == "" || asm.TokenEndpoint == "" {
		return fmt.Errorf("%s names no authorization or token endpoint", prm.AuthorizationServers[0])
	}
	if err := secure(asm.AuthorizationEndpoint, asm.TokenEndpoint, asm.RegistrationEndpoint); err != nil {
		return err
	}
	reg, err := oauthex.RegisterClient(ctx, asm.RegistrationEndpoint, &oauthex.ClientRegistrationMetadata{
		RedirectURIs: []string{redirect}, ClientName: "Monitor", GrantTypes: []string{"authorization_code", "refresh_token"},
	}, s.client)
	if err != nil {
		return err
	}
	s.grant.AuthURL, s.grant.TokenURL, s.grant.ClientID, s.grant.ClientSecret = asm.AuthorizationEndpoint, asm.TokenEndpoint, reg.ClientID, reg.ClientSecret
	if s.grant.Scope == "" {
		scopes := prm.ScopesSupported
		if slices.Contains(asm.ScopesSupported, offlineAccess) && !slices.Contains(scopes, offlineAccess) {
			scopes = append(scopes, offlineAccess)
		}
		s.grant.Scope = strings.Join(scopes, " ")
	}
	return nil
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
	if t.AccessToken == "" || !strings.EqualFold(t.Type(), "Bearer") {
		return errors.New("oauth returned an invalid bearer token")
	}
	scope, _ := t.Extra("scope").(string)
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
	if o.Resource != "" {
		if client == nil {
			client = http.DefaultClient
		}
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
