package credential

import (
	"context"
	"errors"
	"io"
	"net/http"

	"github.com/lestrrat-go/jwx/v3/jwk"
	"github.com/lestrrat-go/jwx/v3/jwt"
	"golang.org/x/oauth2"
)

// OIDC identity stays with its OAuth client registration in encrypted storage.
type oidc struct {
	Issuer  string `json:"issuer"`
	JWKSURL string `json:"jwks_url"`
	Subject string `json:"subject,omitempty"`
	Email   string `json:"email,omitempty"`
	IDToken string `json:"id_token,omitempty"`
}

func (o *oidc) verify(ctx context.Context, client *http.Client, token *oauth2.Token, audience, nonce string) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, o.JWKSURL, nil)
	if err != nil {
		return scrub(ctx, "identity verification", err)
	}
	resp, err := client.Do(req)
	if err != nil {
		return scrub(ctx, "identity verification", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return errors.New("OIDC signing keys are unavailable")
	}
	keys, err := jwk.ParseReader(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return errors.New("OIDC signing keys are invalid")
	}
	idToken, _ := token.Extra("id_token").(string)
	identity, err := jwt.ParseString(idToken, jwt.WithKeySet(keys), jwt.WithIssuer(o.Issuer),
		jwt.WithAudience(audience), jwt.WithRequiredClaim("exp"), jwt.WithRequiredClaim("sub"), jwt.WithClaimValue("nonce", nonce))
	if err != nil {
		return errors.New("sign-in identity could not be verified")
	}
	subject, _ := identity.Subject()
	if subject == "" || o.Subject != "" && subject != o.Subject {
		return errors.New("sign-in belongs to a different account; add a new account instead")
	}
	o.Subject, o.IDToken, o.Email = subject, idToken, ""
	_ = identity.Get("email", &o.Email)
	return nil
}
