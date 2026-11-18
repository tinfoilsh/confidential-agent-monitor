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
	"sync"
	"time"
	"unicode"

	oauthauth "github.com/modelcontextprotocol/go-sdk/auth"
	"github.com/modelcontextprotocol/go-sdk/oauthex"
	"golang.org/x/oauth2"
)

const httpsPort = "443"

var (
	prompts    = []string{"", "none", "login", "consent", "select_account"}
	authStyles = map[string]oauth2.AuthStyle{"": oauth2.AuthStyleAutoDetect, "header": oauth2.AuthStyleInHeader, "params": oauth2.AuthStyleInParams}
)

var (
	ErrLoopback     = errors.New("this service only accepts sign-ins from a loopback address")
	errRegistration = errors.New("this service does not register clients automatically; enter the client ID and secret of an OAuth app registered with it")
	errSignInGone   = errors.New("sign-in expired or already completed; start again")
)

type Grant struct {
	AuthorizeParams map[string]string     `json:"authorize_params,omitempty"`
	Registration    *CallbackRegistration `json:"callback_registration,omitempty"`
	OIDC            *OIDC                 `json:"oidc,omitempty"`
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
	DefaultClient   *DefaultClient        `json:"default_client,omitempty"`
	AccessToken     string                `json:"access_token,omitempty"`
	Expiry          time.Time             `json:"expiry,omitzero"`
}

type DefaultClient struct {
	ClientID     string `json:"client_id"`
	ClientSecret string `json:"client_secret,omitempty"`
	Loopback     bool   `json:"loopback,omitempty"`
}

type CallbackRegistration struct {
	ClientID        string            `json:"client_id"`
	AuthorizeParams map[string]string `json:"authorize_params,omitempty"`
}

func (o *Grant) validate() error {
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
		if err := CheckEndpoints(o.OIDC.Issuer, o.OIDC.JWKSURL); err != nil {
			return err
		}
	}
	if _, ok := authStyles[o.AuthStyle]; !ok || !slices.Contains(prompts, o.Prompt) {
		return errors.New("oauth prompt or auth_style is not supported")
	}
	return CheckEndpoints(o.AuthURL, o.DeviceAuthURL, o.TokenURL, o.Resource)
}

func CheckEndpoints(endpoints ...string) error {
	for _, endpoint := range endpoints {
		u, err := url.Parse(endpoint)
		if endpoint != "" && (err != nil || u.Scheme != "https" || u.Host == "" || u.User != nil || u.Fragment != "" || strings.Contains(endpoint, "#")) {
			return errors.New("oauth endpoints must be https URLs without user information or fragments")
		}
	}
	return nil
}

func (o *Grant) config(redirect string) oauth2.Config {
	return oauth2.Config{
		ClientID: o.ClientID, ClientSecret: o.ClientSecret, RedirectURL: redirect, Scopes: strings.Fields(o.Scope),
		Endpoint: oauth2.Endpoint{AuthURL: o.AuthURL, DeviceAuthURL: o.DeviceAuthURL, TokenURL: o.TokenURL, AuthStyle: authStyles[o.AuthStyle]},
	}
}

func encodeGrant(grant Grant) json.RawMessage {
	raw, _ := json.Marshal(grant)
	return raw
}

func snapshot(grant Grant) (*Grant, error) {
	raw, err := json.Marshal(grant)
	if err != nil {
		return nil, err
	}
	return DecodeGrant(raw)
}

type SignIn struct {
	URL, State string
	UserCode   string
	Expires    time.Time
	device     *oauth2.DeviceAuthResponse
	grant      Grant
	config     *oauth2.Config
	client     *http.Client
	verifier   string
	opts       []oauth2.AuthCodeOption
	nonce      string
	limits     SignInLimits
}

func newDeviceSignIn(ctx context.Context, client *http.Client, grant Grant, limits SignInLimits) (*SignIn, error) {
	g, err := snapshot(grant)
	if err != nil {
		return nil, err
	}
	if g.DeviceAuthURL == "" {
		return nil, errors.New("device sign-in requires a device authorization URL")
	}
	s := &SignIn{State: rand.Text(), grant: *g, client: client, limits: limits}
	config := s.grant.config("")
	s.config = &config
	return s, s.startDevice(ctx)
}

func newAuthCodeSignIn(client *http.Client, grant Grant, redirect string, limits SignInLimits, opts ...oauth2.AuthCodeOption) (*SignIn, error) {
	g, err := snapshot(grant)
	if err != nil {
		return nil, err
	}
	if g.AuthURL == "" {
		return nil, errors.New("authorization code sign-in requires an authorization URL")
	}
	s := &SignIn{State: rand.Text(), grant: *g, client: client, verifier: oauth2.GenerateVerifier(), limits: limits}
	if s.grant.Resource != "" {
		s.opts = append(s.opts, oauth2.SetAuthURLParam("resource", s.grant.Resource))
	}
	config := s.grant.config(redirect)
	registering := s.grant.Registration != nil && s.grant.ClientID == ""
	if registering {
		config.ClientID = s.grant.Registration.ClientID
	}
	s.config = &config
	opts = append(slices.Concat(opts, s.opts), oauth2.S256ChallengeOption(s.verifier), oauth2.SetAuthURLParam("state", s.State))
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
		return nil, errors.New("oauth authorization failed")
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
		return Scrub(ctx, "device authorization", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")
	resp, err := s.client.Do(req)
	if err != nil {
		return Scrub(ctx, "device authorization", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("oauth device authorization failed with status %d", resp.StatusCode)
	}
	var device oauth2.DeviceAuthResponse
	if err := json.NewDecoder(io.LimitReader(resp.Body, s.limits.MaxResponseBytes)).Decode(&device); err != nil {
		return errors.New("oauth returned an invalid device authorization")
	}
	if device.DeviceCode == "" || device.UserCode == "" || device.VerificationURI == "" ||
		!device.Expiry.After(time.Now()) || time.Until(device.Expiry) > s.limits.MaxDeviceExpiry || device.Interval < 0 || device.Interval > int64(s.limits.MaxDeviceInterval) {
		return errors.New("oauth returned an invalid device authorization")
	}
	if err := CheckEndpoints(device.VerificationURI); err != nil {
		return err
	}
	s.device, s.URL, s.UserCode, s.Expires = &device, device.VerificationURI, device.UserCode, device.Expiry
	return nil
}

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
		return nil, Scrub(ctx, "device sign-in", err)
	}
	grant := s.grant
	if err := grant.acceptToken(t, false); err != nil {
		return nil, err
	}
	return encodeGrant(grant), nil
}

func protectedResource(ctx context.Context, client *http.Client, resource string, maxBytes int64) (*oauthex.ProtectedResourceMetadata, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, resource, nil)
	if err != nil {
		return nil, Scrub(ctx, "discovery", err)
	}
	u := req.URL
	origin := u.Scheme + "://" + u.Host
	var metadata []string
	resp, err := client.Do(req)
	if err != nil {
		return nil, Scrub(ctx, "discovery", err)
	}
	resp.Body.Close()
	challenges, _ := oauthex.ParseWWWAuthenticate(resp.Header.Values("WWW-Authenticate"))
	for _, c := range challenges {
		if m := c.Params["resource_metadata"]; m != "" {
			metadata = append(metadata, m)
		}
	}
	metadata = append(metadata, origin+"/.well-known/oauth-protected-resource"+u.Path, origin+"/.well-known/oauth-protected-resource")
	for _, m := range metadata {
		var prm oauthex.ProtectedResourceMetadata
		if CheckEndpoints(m) != nil || !getJSON(ctx, client, m, maxBytes, &prm) {
			continue
		}
		named, err := url.Parse(prm.Resource)
		if err != nil || CheckEndpoints(prm.Resource) != nil || !strings.EqualFold(named.Hostname(), u.Hostname()) || cmp.Or(named.Port(), httpsPort) != cmp.Or(u.Port(), httpsPort) || !strings.HasPrefix(strings.TrimSuffix(u.Path, "/")+"/", strings.TrimSuffix(named.Path, "/")+"/") {
			continue
		}
		return &prm, nil
	}
	return nil, nil
}

func publishedIssuer(ctx context.Context, client *http.Client, server string, maxBytes int64) string {
	a, _ := url.Parse(server)
	if CheckEndpoints(server) != nil {
		return ""
	}
	for _, m := range []string{"/.well-known/oauth-authorization-server" + a.Path, "/.well-known/openid-configuration" + a.Path, a.Path + "/.well-known/openid-configuration"} {
		var other oauthex.AuthServerMeta
		if getJSON(ctx, client, a.Scheme+"://"+a.Host+m, maxBytes, &other) && other.Issuer != "" && CheckEndpoints(other.Issuer) == nil {
			return other.Issuer
		}
	}
	return ""
}

func isLoopback(redirect string) bool {
	u, err := url.Parse(redirect)
	return err == nil && (u.Hostname() == "localhost" || net.ParseIP(u.Hostname()).IsLoopback())
}

func getJSON(ctx context.Context, client *http.Client, u string, maxBytes int64, v any) bool {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return false
	}
	resp, err := client.Do(req)
	if err != nil {
		return false
	}
	defer resp.Body.Close()
	return resp.StatusCode == http.StatusOK && json.NewDecoder(io.LimitReader(resp.Body, maxBytes)).Decode(v) == nil
}

func (s *SignIn) Exchange(ctx context.Context, code, clientID string) (json.RawMessage, error) {
	if code == "" {
		return nil, errors.New("the sign-in callback has no authorization code")
	}
	grant, config := s.grant, *s.config
	if grant.Registration != nil && grant.ClientID == "" {
		if clientID == "" || clientID == grant.Registration.ClientID || len(clientID) > s.limits.MaxClientIDBytes || strings.ContainsAny(clientID, " \r\n\t") {
			return nil, errors.New("authorization did not return an issued client ID; start sign-in again")
		}
		grant.ClientID, config.ClientID = clientID, clientID
	} else if clientID != "" && clientID != grant.ClientID {
		return nil, errors.New("authorization returned a different client registration")
	}
	t, err := config.Exchange(context.WithValue(ctx, oauth2.HTTPClient, s.client), code, append(slices.Clone(s.opts), oauth2.VerifierOption(s.verifier))...)
	if err != nil {
		return nil, Scrub(ctx, "exchange", err)
	}
	if err := grant.acceptToken(t, false); err != nil {
		return nil, err
	}
	if grant.OIDC != nil {
		identity := *grant.OIDC
		if err := identity.verify(ctx, s.client, t, grant.ClientID, s.nonce, s.limits.MaxResponseBytes); err != nil {
			return nil, err
		}
		grant.OIDC = &identity
	}
	return encodeGrant(grant), nil
}

func (o *Grant) acceptToken(t *oauth2.Token, refresh bool) error {
	if t.AccessToken == "" || !strings.EqualFold(t.Type(), cmp.Or(o.TokenType, "Bearer")) {
		return errors.New("oauth returned an invalid bearer token")
	}
	scope, _ := t.Extra("scope").(string)
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

func (o *Grant) refresh(ctx context.Context, client *http.Client, token *oauth2.Token) (*oauth2.Token, error) {
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

type SignInResult struct {
	Code     string  `json:"code"`
	ClientID string  `json:"client_id,omitempty"`
	Error    *string `json:"error,omitempty"`
	Cancel   bool    `json:"cancel,omitempty"`
}

type pendingSignIn struct {
	finish  func(context.Context, SignInResult) error
	session string
	expires time.Time
	done    <-chan struct{}
	cancel  context.CancelFunc
}

type SignIns struct {
	pending    sync.Map
	limits     SignInLimits
	clientName string
}

type SignInLimits struct {
	Timeout, Lifetime time.Duration
	MaxDeviceExpiry   time.Duration
	MaxDeviceInterval int
	MaxResponseBytes  int64
	MaxClientIDBytes  int
}

func NewSignIns(limits SignInLimits, clientName string) *SignIns {
	return &SignIns{limits: limits, clientName: clientName}
}

func (s *SignIns) begin(ctx context.Context, client *http.Client, raw json.RawMessage, redirect string) (*SignIn, error) {
	g, err := DecodeGrant(raw)
	if err != nil {
		return nil, err
	}
	if c := g.DefaultClient; c != nil && g.ClientID == "" {
		g.ClientID, g.ClientSecret = c.ClientID, c.ClientSecret
		g.Loopback = g.Loopback || c.Loopback
	}
	if g.DeviceAuthURL != "" {
		return newDeviceSignIn(ctx, client, *g, s.limits)
	}
	if g.Loopback && !isLoopback(redirect) {
		return nil, ErrLoopback
	}
	if g.AuthURL == "" {
		if err := s.discover(ctx, client, g, redirect); errors.Is(err, errRegistration) || errors.Is(err, ErrLoopback) {
			return nil, err
		} else if err != nil {
			return nil, Scrub(ctx, "discovery", err)
		}
	}
	return newAuthCodeSignIn(client, *g, redirect, s.limits, oauth2.AccessTypeOffline)
}

func (s *SignIns) discover(ctx context.Context, client *http.Client, g *Grant, redirect string) error {
	prm, err := protectedResource(ctx, client, g.Resource, s.limits.MaxResponseBytes)
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
	if err := CheckEndpoints(server); err != nil {
		return err
	}

	asm, err := oauthauth.GetAuthServerMetadata(ctx, server, client)
	if err != nil {
		if issuer := publishedIssuer(ctx, client, server, s.limits.MaxResponseBytes); issuer != "" {
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
	if err := CheckEndpoints(asm.AuthorizationEndpoint, asm.TokenEndpoint, asm.RegistrationEndpoint); err != nil {
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
		return errRegistration
	}
	registration := &oauthex.ClientRegistrationMetadata{
		RedirectURIs: []string{redirect}, ClientName: s.clientName, GrantTypes: []string{"authorization_code"}, ResponseTypes: []string{"code"},
	}
	if slices.Contains(asm.GrantTypesSupported, "refresh_token") {
		registration.GrantTypes = append(registration.GrantTypes, "refresh_token")
	}
	if slices.Contains(asm.TokenEndpointAuthMethodsSupported, "none") {
		registration.TokenEndpointAuthMethod = "none"
	}
	reg, err := oauthex.RegisterClient(ctx, asm.RegistrationEndpoint, registration, client)
	var refused *oauthex.ClientRegistrationError
	if errors.As(err, &refused) && refused.ErrorCode == "invalid_redirect_uri" && !isLoopback(redirect) {
		return ErrLoopback
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

func (s *SignIns) Start(ctx context.Context, client *http.Client, credential json.RawMessage, redirect, session string, save func(context.Context, json.RawMessage) error) (*SignIn, error) {
	c, err := decode(credential)
	if err == nil && c.oauth == nil {
		err = errors.New("the secret is not an oauth grant")
	}
	if err != nil {
		return nil, err
	}
	ctx, cancel := context.WithTimeout(ctx, s.limits.Timeout)
	defer cancel()
	pending := &pendingSignIn{session: session, expires: time.Now().Add(s.limits.Lifetime)}
	sign, err := s.begin(ctx, client, c.oauth, redirect)
	if err != nil {
		return nil, err
	}
	exchange := sign.Exchange
	if sign.UserCode != "" {
		poll, stop := context.WithDeadline(context.Background(), sign.Expires)
		done := make(chan struct{})
		var secret json.RawMessage
		var failure error
		go func() { defer close(done); defer stop(); secret, failure = sign.WaitDevice(poll) }()
		pending.expires, pending.done, pending.cancel = sign.Expires, done, stop
		exchange = func(context.Context, string, string) (json.RawMessage, error) { return secret, failure }
	}
	pending.finish = func(ctx context.Context, result SignInResult) error {
		if result.Error != nil {
			return errors.New("sign-in was not completed; try again")
		}
		grant, err := exchange(ctx, result.Code, result.ClientID)
		if err != nil {
			return err
		}
		return save(ctx, encodeOAuth(grant))
	}
	s.pending.Store(sign.State, pending)
	time.AfterFunc(time.Until(pending.expires), func() { s.pending.CompareAndDelete(sign.State, pending) })
	return sign, nil
}

func (s *SignIns) Finish(ctx context.Context, state, session string, result SignInResult) (bool, error) {
	value, ok := s.pending.Load(state)
	if !ok {
		return false, errSignInGone
	}
	pending := value.(*pendingSignIn)
	if pending.session != session {
		return false, errors.New("sign-in belongs to a different session")
	}
	if !result.Cancel && result.Error == nil && pending.done != nil && time.Now().Before(pending.expires) {
		select {
		case <-pending.done:
		default:
			return true, nil
		}
	}
	if !s.pending.CompareAndDelete(state, pending) {
		return false, errSignInGone
	}
	if pending.cancel != nil {
		defer pending.cancel()
	}
	if !time.Now().Before(pending.expires) {
		return false, errSignInGone
	}
	if result.Cancel {
		return false, nil
	}
	ctx, cancel := context.WithTimeout(ctx, s.limits.Timeout)
	defer cancel()
	return false, pending.finish(ctx, result)
}
