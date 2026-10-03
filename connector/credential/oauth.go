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

	"github.com/modelcontextprotocol/go-sdk/auth"
	"github.com/modelcontextprotocol/go-sdk/oauthex"
	"golang.org/x/oauth2"
)

const offlineAccess = "offline_access"

// A grant without an AuthURL is signed in at the authorization server its Resource names (RFC 9728).
type oauth struct {
	AuthURL      string `json:"auth_url"`
	TokenURL     string `json:"token_url"`
	ClientID     string `json:"client_id"`
	ClientSecret string `json:"client_secret"`
	RefreshToken string `json:"refresh_token"`
	Scope        string `json:"scope"`
	Resource     string `json:"resource"`
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
			return nil, err
		}
	}
	if s.grant.Resource != "" {
		s.opts = append(s.opts, oauth2.SetAuthURLParam("resource", s.grant.Resource))
	}
	s.config = &oauth2.Config{
		ClientID: s.grant.ClientID, ClientSecret: s.grant.ClientSecret, RedirectURL: redirect, Scopes: strings.Fields(s.grant.Scope),
		Endpoint: oauth2.Endpoint{AuthURL: s.grant.AuthURL, TokenURL: s.grant.TokenURL},
	}
	s.URL = s.config.AuthCodeURL(s.State, append(s.opts, oauth2.S256ChallengeOption(s.verifier), oauth2.AccessTypeOffline)...)
	return s, nil
}

// register discovers the resource's authorization server (RFC 9728, RFC 8414) and registers with it (RFC 7591).
func (s *SignIn) register(ctx context.Context, redirect string) error {
	u, err := url.Parse(s.grant.Resource)
	if err != nil {
		return err
	}
	metadata := u.Scheme + "://" + u.Host + "/.well-known/oauth-protected-resource" + u.Path
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, s.grant.Resource, nil)
	if err != nil {
		return err
	}
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
	prm, err := oauthex.GetProtectedResourceMetadata(ctx, metadata, s.grant.Resource, s.client)
	if err != nil {
		return err
	}
	if len(prm.AuthorizationServers) == 0 {
		return fmt.Errorf("%s names no authorization server", s.grant.Resource)
	}
	asm, err := auth.GetAuthServerMetadata(ctx, prm.AuthorizationServers[0], s.client)
	if err != nil {
		return err
	}
	if asm == nil || asm.RegistrationEndpoint == "" {
		return fmt.Errorf("%s does not register clients", prm.AuthorizationServers[0])
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
		return nil, err
	}
	if t.RefreshToken == "" {
		return json.Marshal(t.AccessToken)
	}
	s.grant.RefreshToken = t.RefreshToken
	return encodeGrant(s.grant), nil
}
