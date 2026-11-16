package credential_test

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"slices"
	"testing"
	"time"

	"github.com/tinfoilsh/confidential-agent-monitor/connector/credential"
	"golang.org/x/oauth2"
)

var testLimits = credential.SignInLimits{Timeout: 10 * time.Second, Lifetime: time.Minute, MaxDeviceExpiry: time.Hour, MaxDeviceInterval: 5, MaxResponseBytes: 1 << 10, MaxClientIDBytes: 512}

func TestExplicitAuthCodeSignInKeepsStateAndPKCE(t *testing.T) {
	var calls []string
	var challenge string
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls = append(calls, r.URL.Path)
		sum := sha256.Sum256([]byte(r.FormValue("code_verifier")))
		if r.URL.Path != "/token" || r.FormValue("code") != "code" || r.FormValue("resource") == "" || base64.RawURLEncoding.EncodeToString(sum[:]) != challenge {
			http.Error(w, "unexpected request", http.StatusBadRequest)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"access_token":"access","token_type":"Bearer","refresh_token":"refresh","scope":"read"}`))
	}))
	defer server.Close()
	raw, _ := json.Marshal(map[string]any{"auth_url": server.URL + "/authorize", "device_auth_url": server.URL + "/device", "token_url": server.URL + "/token",
		"client_id": "client", "scope": "read", "resource": server.URL + "/mcp", "authorize_params": map[string]string{"audience": "api"}})
	grant, err := credential.DecodeGrant(raw)
	if err != nil {
		t.Fatal(err)
	}
	var saved struct {
		AccessToken     string            `json:"access_token"`
		AuthorizeParams map[string]string `json:"authorize_params"`
	}
	signIns := credential.NewSignIns(testLimits)
	sign, err := signIns.Start(context.Background(), func(context.Context) (*credential.SignIn, error) {
		return credential.NewAuthCodeSignIn(server.Client(), *grant, "https://app.example/callback", testLimits,
			oauth2.SetAuthURLParam("state", "host"), oauth2.SetAuthURLParam("code_challenge", "host"))
	}, "session", func(_ context.Context, g json.RawMessage) error { return json.Unmarshal(g, &saved) })
	if err != nil {
		t.Fatal(err)
	}
	grant.AuthorizeParams["audience"] = "edited"
	u, _ := url.Parse(sign.URL)
	q := u.Query()
	if len(calls) != 0 || u.Path != "/authorize" || q.Get("state") != sign.State || q.Get("code_challenge_method") != "S256" || q.Has("access_type") ||
		q.Get("scope") != "read" || q.Get("resource") != server.URL+"/mcp" || q.Get("audience") != "api" {
		t.Fatalf("requests %v before authorization %s", calls, sign.URL)
	}
	challenge = q.Get("code_challenge")
	if _, err := signIns.Finish(context.Background(), sign.State, "other", credential.SignInResult{Code: "code"}); err == nil {
		t.Fatal("another session finished the sign-in")
	}
	if _, err := signIns.Finish(context.Background(), sign.State, "session", credential.SignInResult{Code: "code"}); err != nil || saved.AccessToken != "access" || saved.AuthorizeParams["audience"] != "api" {
		t.Fatalf("saved %+v: %v", saved, err)
	}
	if _, err := signIns.Finish(context.Background(), sign.State, "session", credential.SignInResult{Code: "code"}); err == nil || !slices.Equal(calls, []string{"/token"}) {
		t.Fatalf("requests %v, second finish: %v", calls, err)
	}
}

func TestSignInConstructorsValidateDirectGrants(t *testing.T) {
	requests := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests++
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"device_code":"device","user_code":"USER","verification_uri":"https://example.com/device","expires_in":600,"interval":5}`))
	}))
	defer server.Close()
	valid := credential.Grant{AuthURL: "https://as.example/authorize", TokenURL: "https://as.example/token", ClientID: "client"}
	reserved, insecure, unnamed, device := valid, valid, valid, valid
	reserved.AuthorizeParams = map[string]string{"state": "fixed"}
	insecure.TokenURL = server.URL + "/token"
	unnamed.AuthURL = ""
	device.DeviceAuthURL = server.URL + "/device"
	for name, grant := range map[string]credential.Grant{"reserved parameter": reserved, "insecure endpoint": insecure, "no authorization URL": unnamed} {
		if _, err := credential.NewAuthCodeSignIn(server.Client(), grant, "https://app.example/callback", testLimits); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	if _, err := credential.NewDeviceSignIn(context.Background(), server.Client(), device, testLimits); err == nil || requests != 0 {
		t.Errorf("insecure device endpoint reached after %d requests: %v", requests, err)
	}
	if _, err := credential.NewAuthCodeSignIn(server.Client(), valid, "https://app.example/callback", testLimits); err != nil {
		t.Fatal(err)
	}
}

func TestDiscoveryLeavesServerChoiceToCaller(t *testing.T) {
	var calls []string
	var server *httptest.Server
	server = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls = append(calls, r.URL.Path)
		switch r.URL.Path {
		case "/mcp/tools":
			w.Header().Set("WWW-Authenticate", `Bearer resource_metadata="`+server.URL+`/metadata"`)
			w.WriteHeader(http.StatusUnauthorized)
		case "/metadata", "/.well-known/oauth-protected-resource":
			fmt.Fprintf(w, `{"resource":%q,"authorization_servers":[%q,%q],"scopes_supported":["read"]}`, server.URL+"/mcp", server.URL+"/b/", server.URL+"/a")
		case "/.well-known/oauth-authorization-server/tenant":
			fmt.Fprintf(w, `{"issuer":%q}`, server.URL+"/other")
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()
	ctx, client := context.Background(), server.Client()
	prm, err := credential.ProtectedResource(ctx, client, server.URL+"/mcp/tools", testLimits.MaxResponseBytes)
	if err != nil || prm == nil || prm.Resource != server.URL+"/mcp" || !slices.Equal(prm.AuthorizationServers, []string{server.URL + "/b/", server.URL + "/a"}) || !slices.Equal(prm.ScopesSupported, []string{"read"}) {
		t.Fatalf("%+v: %v", prm, err)
	}
	if prm, err := credential.ProtectedResource(ctx, client, server.URL+"/elsewhere", testLimits.MaxResponseBytes); prm != nil || err != nil {
		t.Fatalf("metadata for another resource was returned: %+v %v", prm, err)
	}
	if issuer := credential.PublishedIssuer(ctx, client, server.URL+"/tenant", testLimits.MaxResponseBytes); issuer != server.URL+"/other" {
		t.Fatal(issuer)
	}
	if !slices.Equal(calls, []string{"/mcp/tools", "/metadata", "/elsewhere", "/.well-known/oauth-protected-resource/elsewhere", "/.well-known/oauth-protected-resource",
		"/.well-known/oauth-authorization-server/tenant"}) {
		t.Fatalf("discovery contacted a server it should only report: %v", calls)
	}
}

func TestRotatedGrantIsSavedBeforeItsTokenIsUsed(t *testing.T) {
	refreshes := 0
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		refreshes++
		if r.FormValue("refresh_token") != "old-refresh" {
			http.Error(w, "unknown grant", http.StatusBadRequest)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"access_token":"new-access","token_type":"Bearer","expires_in":3600,"refresh_token":"new-refresh"}`))
	}))
	defer server.Close()
	grant, _ := json.Marshal(map[string]any{"token_url": server.URL + "/token", "auth_url": "", "client_id": "client", "client_secret": "",
		"refresh_token": "old-refresh", "scope": "", "resource": "", "access_token": "expired", "expiry": time.Now().Add(-time.Hour)})
	var saved map[string]any
	fail := true
	v, err := credential.OAuth(grant, credential.OAuthOptions{Client: server.Client(), Timeout: 10 * time.Second,
		Save: func(_ context.Context, rotated json.RawMessage) error {
			if fail {
				return errors.New("storage failed")
			}
			return json.Unmarshal(rotated, &saved)
		}})
	if err != nil {
		t.Fatal(err)
	}
	if token, err := v.Value(context.Background()); err == nil || token != "" {
		t.Fatalf("a token was used before its grant was saved: %q", token)
	}
	fail = false
	token, err := v.Value(context.Background())
	if err != nil || token != "new-access" || saved["refresh_token"] != "new-refresh" || saved["access_token"] != "new-access" || refreshes != 1 {
		t.Fatalf("token %q saved %v refreshes %d: %v", token, saved, refreshes, err)
	}
	if ready, _, err := credential.DescribeOAuth(grant); err != nil || !ready {
		t.Fatalf("refreshable grant described as not ready: %v", err)
	}
}

func TestDeviceSignInHonorsSuppliedLimits(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if r.URL.Path == "/token" {
			w.WriteHeader(http.StatusBadRequest)
			w.Write([]byte(`{"error":"authorization_pending"}`))
			return
		}
		w.Write([]byte(`{"device_code":"device","user_code":"USER","verification_uri":"https://example.com/device","expires_in":600,"interval":5}`))
	}))
	defer server.Close()
	grant, _ := json.Marshal(map[string]any{"device_auth_url": server.URL + "/device", "token_url": server.URL + "/token", "auth_url": "",
		"client_id": "client", "client_secret": "", "refresh_token": "", "scope": "", "resource": ""})
	g, err := credential.DecodeGrant(grant)
	if err != nil {
		t.Fatal(err)
	}
	save := func(context.Context, json.RawMessage) error { return nil }
	for _, tc := range []struct {
		name   string
		change func(*credential.SignInLimits)
		ok     bool
	}{
		{name: "within limits", change: func(*credential.SignInLimits) {}, ok: true},
		{name: "interval too long", change: func(l *credential.SignInLimits) { l.MaxDeviceInterval = 4 }},
		{name: "expiry too long", change: func(l *credential.SignInLimits) { l.MaxDeviceExpiry = time.Minute }},
		{name: "response too large", change: func(l *credential.SignInLimits) { l.MaxResponseBytes = 16 }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			l := testLimits
			tc.change(&l)
			signIns := credential.NewSignIns(l)
			sign, err := signIns.Start(context.Background(), func(ctx context.Context) (*credential.SignIn, error) {
				return credential.NewDeviceSignIn(ctx, server.Client(), *g, l)
			}, "session", save)
			if (err == nil) != tc.ok {
				t.Fatalf("accepted %v: %v", err == nil, err)
			}
			if err == nil {
				if sign.UserCode != "USER" {
					t.Fatal(sign)
				}
				signIns.Finish(context.Background(), sign.State, "session", credential.SignInResult{Cancel: true})
			}
		})
	}
}
