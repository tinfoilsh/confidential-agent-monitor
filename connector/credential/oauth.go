package credential

import (
	"context"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
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
	AuthURL      string    `json:"auth_url"`
	TokenURL     string    `json:"token_url"`
	ClientID     string    `json:"client_id"`
	ClientSecret string    `json:"client_secret"`
	RefreshToken string    `json:"refresh_token"`
	Scope        string    `json:"scope"`
	Resource     string    `json:"resource"`
	Prompt       string    `json:"prompt,omitempty"`
	AuthStyle    string    `json:"auth_style,omitempty"`
	AccessToken  string    `json:"access_token,omitempty"`
	Expiry       time.Time `json:"expiry,omitzero"`
}

func (o *oauth) validate() error {
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
	s.config = &config
	opts := append(slices.Clone(s.opts), oauth2.S256ChallengeOption(s.verifier), oauth2.AccessTypeOffline)
	if s.grant.Prompt != "" {
		opts = append(opts, oauth2.SetAuthURLParam("prompt", s.grant.Prompt))
	}
	s.URL = s.config.AuthCodeURL(s.State, opts...)
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
func (s *SignIn) Exchange(ctx context.Context, code string) (json.RawMessage, error) {
	t, err := s.config.Exchange(context.WithValue(ctx, oauth2.HTTPClient, s.client), code, append(s.opts, oauth2.VerifierOption(s.verifier))...)
	if err != nil {
		return nil, scrub(ctx, "exchange", err)
	}
	s.grant.RefreshToken, s.grant.AccessToken, s.grant.Expiry = t.RefreshToken, "", time.Time{}
	if t.RefreshToken == "" {
		s.grant.AccessToken, s.grant.Expiry = t.AccessToken, t.Expiry
	}
	return encodeGrant(s.grant), nil
}
