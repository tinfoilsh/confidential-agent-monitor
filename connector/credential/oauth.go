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
	"sync"
	"time"

	"github.com/modelcontextprotocol/go-sdk/auth"
	"github.com/modelcontextprotocol/go-sdk/oauthex"
	"golang.org/x/oauth2"
)

const (
	clientName    = "Monitor"
	offlineAccess = "offline_access"
)

// A grant without an AuthURL is signed in at the authorization server its Resource names (RFC 9728).
type oauth struct {
	AuthURL      string `json:"auth_url,omitempty"`
	TokenURL     string `json:"token_url"`
	ClientID     string `json:"client_id"`
	ClientSecret string `json:"client_secret,omitempty"`
	RefreshToken string `json:"refresh_token"`
	Scope        string `json:"scope,omitempty"`
	Resource     string `json:"resource,omitempty"`
}

// OAuth caches access tokens and persists refresh-token rotations.
// Set Rotated before sharing the source with callers.
type OAuth struct {
	config    *oauth2.Config
	token     *oauth2.Token
	refresh   chan struct{}
	mu        sync.Mutex
	persisted string
	saving    bool
	Rotated   func(old, new string) error
}

func newOAuth(grant oauth) *OAuth {
	return &OAuth{
		config: &oauth2.Config{ClientID: grant.ClientID, ClientSecret: grant.ClientSecret,
			Endpoint: oauth2.Endpoint{TokenURL: grant.TokenURL}},
		token:     &oauth2.Token{RefreshToken: grant.RefreshToken},
		refresh:   make(chan struct{}, 1),
		persisted: grant.RefreshToken,
	}
}

func (c *OAuth) Value(ctx context.Context) (string, error) {
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	select {
	case c.refresh <- struct{}{}:
		defer func() { <-c.refresh }()
	case <-ctx.Done():
		return "", ctx.Err()
	}
	t := c.token
	if !t.Valid() {
		var err error
		if t, err = c.config.TokenSource(ctx, t).Token(); err != nil {
			return "", err
		}
		c.token = t
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.Rotated != nil && c.persisted != t.RefreshToken && !c.saving {
		old, next := c.persisted, t.RefreshToken
		c.saving = true
		go func() {
			err := c.Rotated(old, next)
			c.mu.Lock()
			defer c.mu.Unlock()
			if err == nil {
				c.persisted = next
			}
			c.saving = false
		}()
	}
	return t.AccessToken, nil
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
func NewSignIn(ctx context.Context, client *http.Client, secret any, redirect string) (*SignIn, error) {
	raw, err := json.Marshal(secret)
	if err != nil {
		return nil, err
	}
	var v struct {
		OAuth *oauth `json:"oauth"`
	}
	if err := json.Unmarshal(raw, &v); err != nil || v.OAuth == nil {
		return nil, errors.New("the secret is not an oauth grant")
	}
	s := &SignIn{State: rand.Text(), grant: *v.OAuth, client: client, verifier: oauth2.GenerateVerifier()}
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
		RedirectURIs: []string{redirect}, ClientName: clientName, GrantTypes: []string{"authorization_code", "refresh_token"},
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

// Exchange trades the provider's code for the secret a Credential refreshes from.
func (s *SignIn) Exchange(ctx context.Context, code string) (any, error) {
	t, err := s.config.Exchange(context.WithValue(ctx, oauth2.HTTPClient, s.client), code, append(s.opts, oauth2.VerifierOption(s.verifier))...)
	if err != nil {
		return nil, err
	}
	if t.RefreshToken == "" {
		return t.AccessToken, nil
	}
	s.grant.RefreshToken = t.RefreshToken
	return map[string]oauth{"oauth": s.grant}, nil
}
