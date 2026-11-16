package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"reflect"
	"sync/atomic"
	"testing"

	"github.com/modelcontextprotocol/go-sdk/oauthex"
)

func TestOAuthConfiguredFlowAndDefaultClient(t *testing.T) {
	var devices atomic.Int32
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/device" {
			t.Errorf("configured sign-in unexpectedly fetched %s", r.URL.Path)
			http.NotFound(w, r)
			return
		}
		devices.Add(1)
		if r.FormValue("client_id") != "explicit" || r.FormValue("scope") != "read" {
			t.Error("device request lost the selected client or scope")
		}
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"device_code":"device","user_code":"USER","verification_uri":"https://provider.example/device","expires_in":600,"interval":5}`))
	}))
	defer server.Close()
	for _, tc := range []struct {
		name, client, want string
		device, loopback   bool
		refused            bool
	}{
		{name: "default client", want: "default"},
		{name: "explicit client", client: "explicit", want: "explicit", loopback: true},
		{name: "default requires loopback", loopback: true, refused: true},
		{name: "device takes precedence", client: "explicit", device: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			grant := map[string]any{"auth_url": server.URL + "/authorize", "token_url": server.URL + "/token", "client_id": tc.client, "scope": "read",
				"default_client": map[string]any{"client_id": "default", "loopback": tc.loopback}}
			if tc.device {
				grant["device_auth_url"] = server.URL + "/device"
			}
			raw, _ := json.Marshal(grant)
			sign, err := beginOAuth(t.Context(), server.Client(), raw, "https://owner.example/callback")
			if tc.refused {
				if err == nil {
					t.Fatal("non-loopback redirect accepted for the selected default client")
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if tc.device {
				if sign.UserCode != "USER" || sign.URL != "https://provider.example/device" {
					t.Fatal("main did not select the configured device flow")
				}
				return
			}
			u, err := url.Parse(sign.URL)
			if err != nil {
				t.Fatal(err)
			}
			q := u.Query()
			if q.Get("client_id") != tc.want || q.Get("scope") != "read" || q.Get("access_type") != "offline" || q.Get("state") != sign.State ||
				q.Get("code_challenge") == "" || q.Get("code_challenge_method") != "S256" {
				t.Fatal("main's client, scope, offline access or PKCE selection changed")
			}
		})
	}
	if devices.Load() != 1 {
		t.Fatalf("device exchanges: %d", devices.Load())
	}
}

func TestOAuthDiscoveryAndRegistrationPreserveProductChoices(t *testing.T) {
	for _, tc := range []struct {
		name, client, scope, wantScope string
		register                       bool
	}{
		{name: "discovered defaults", wantScope: "read write offline_access", register: true},
		{name: "explicit client and scope", client: "existing", scope: "custom", wantScope: "custom"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var registrations, exchanges atomic.Int32
			var server *httptest.Server
			server = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				switch r.URL.Path {
				case "/resource":
					w.WriteHeader(http.StatusUnauthorized)
				case "/.well-known/oauth-protected-resource/resource":
					json.NewEncoder(w).Encode(oauthex.ProtectedResourceMetadata{Resource: server.URL + "/resource",
						AuthorizationServers: []string{server.URL + "/first", server.URL + "/second"}, ScopesSupported: []string{"read", "write"}})
				case "/.well-known/oauth-authorization-server/first":
					json.NewEncoder(w).Encode(oauthex.AuthServerMeta{Issuer: server.URL + "/first", AuthorizationEndpoint: server.URL + "/authorize",
						TokenEndpoint: server.URL + "/token", RegistrationEndpoint: server.URL + "/register", ResponseTypesSupported: []string{"code"},
						CodeChallengeMethodsSupported: []string{"S256"},
						ScopesSupported:               []string{"read", "write", "offline_access"}, GrantTypesSupported: []string{"authorization_code", "refresh_token"},
						TokenEndpointAuthMethodsSupported: []string{"none"}})
				case "/register":
					registrations.Add(1)
					var meta oauthex.ClientRegistrationMetadata
					if err := json.NewDecoder(r.Body).Decode(&meta); err != nil {
						t.Error(err)
					}
					if meta.ClientName != signInClient || !reflect.DeepEqual(meta.RedirectURIs, []string{"https://owner.example/callback"}) ||
						!reflect.DeepEqual(meta.GrantTypes, []string{"authorization_code", "refresh_token"}) || meta.TokenEndpointAuthMethod != "none" {
						t.Error("main's registration choices changed")
					}
					w.WriteHeader(http.StatusCreated)
					w.Write([]byte(`{"client_id":"registered","token_endpoint_auth_method":"none"}`))
				case "/token":
					exchanges.Add(1)
					wantClient := tc.client
					if wantClient == "" {
						wantClient = "registered"
					}
					if r.Header.Get("Authorization") != "" || r.FormValue("client_id") != wantClient || r.FormValue("code_verifier") == "" ||
						r.FormValue("resource") != server.URL+"/resource" {
						t.Error("token exchange changed client authentication, PKCE or resource binding")
					}
					w.Write([]byte(`{"access_token":"access","refresh_token":"refresh","token_type":"Bearer","expires_in":3600}`))
				default:
					t.Errorf("unexpected discovery or exchange: %s", r.URL.Path)
					http.NotFound(w, r)
				}
			}))
			defer server.Close()
			raw, _ := json.Marshal(map[string]any{"resource": server.URL + "/resource", "client_id": tc.client, "scope": tc.scope})
			sign, err := beginOAuth(t.Context(), server.Client(), raw, "https://owner.example/callback")
			if err != nil {
				t.Fatal(err)
			}
			u, _ := url.Parse(sign.URL)
			if u.Query().Get("scope") != tc.wantScope || u.Query().Get("access_type") != "offline" {
				t.Fatal("main's scope choices changed")
			}
			if (registrations.Load() == 1) != tc.register {
				t.Fatalf("registration exchanges: %d", registrations.Load())
			}
			updated, err := sign.Exchange(t.Context(), "code", "")
			if err != nil {
				t.Fatal(err)
			}
			var grant map[string]any
			if err := json.Unmarshal(updated, &grant); err != nil {
				t.Fatal(err)
			}
			if exchanges.Load() != 1 || grant["auth_style"] != "params" || grant["scope"] != tc.wantScope || grant["refresh_token"] != "refresh" {
				t.Fatal("exchange lost the chosen authentication, scope or replacement grant")
			}
		})
	}
}

func TestOAuthLegacyIssuerFallbackOnlyAfterDiscoveryError(t *testing.T) {
	for _, mode := range []string{"different issuer", "no metadata", "missing endpoint", "insecure endpoint"} {
		t.Run(mode, func(t *testing.T) {
			var first, oidc, issuer atomic.Int32
			var server *httptest.Server
			server = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				meta := oauthex.AuthServerMeta{Issuer: server.URL, AuthorizationEndpoint: server.URL + "/authorize",
					TokenEndpoint: server.URL + "/token", CodeChallengeMethodsSupported: []string{"S256"}}
				switch r.URL.Path {
				case "/.well-known/oauth-authorization-server":
					first.Add(1)
					switch mode {
					case "different issuer":
						meta.Issuer += "/issuer"
					case "no metadata":
						http.NotFound(w, r)
						return
					case "missing endpoint":
						meta.AuthorizationEndpoint = ""
					case "insecure endpoint":
						// The SDK permits loopback HTTP; this application requires HTTPS.
						meta.AuthorizationEndpoint = "http://127.0.0.1/authorize"
					}
				case "/.well-known/openid-configuration":
					oidc.Add(1)
					http.NotFound(w, r)
					return
				case "/.well-known/oauth-authorization-server/issuer":
					issuer.Add(1)
					meta.Issuer += "/issuer"
				default:
					http.NotFound(w, r)
					return
				}
				w.Header().Set("Content-Type", "application/json")
				json.NewEncoder(w).Encode(meta)
			}))
			defer server.Close()
			raw, _ := json.Marshal(map[string]string{"resource": server.URL + "/service", "client_id": "existing"})
			sign, err := beginOAuth(t.Context(), server.Client(), raw, "https://owner.example/callback")
			wantFirst, wantOIDC, wantIssuer := int32(1), int32(0), int32(0)
			if mode == "different issuer" {
				wantFirst, wantIssuer = 2, 1
				if err != nil || sign == nil {
					t.Fatalf("legacy issuer discovery failed: %v", err)
				}
			} else if err == nil || err.Error() != "oauth discovery failed" {
				t.Fatalf("invalid discovery was not refused with a scrubbed error: %v", err)
			}
			if mode == "no metadata" {
				wantOIDC = 1
			}
			if first.Load() != wantFirst || oidc.Load() != wantOIDC || issuer.Load() != wantIssuer {
				t.Fatalf("discovery requests = (%d, %d, %d), want (%d, %d, %d)", first.Load(), oidc.Load(), issuer.Load(), wantFirst, wantOIDC, wantIssuer)
			}
		})
	}
}
