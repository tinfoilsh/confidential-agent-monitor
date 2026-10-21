package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"gocloud.dev/blob/memblob"
)

var githubCredentialPaths = [][]string{
	{"connections", "", "http", "secrets", "GITHUB_TOKEN"},
	{"connections", "mcp", "mcp", "secrets", "token"},
}

func stopSignInMonitor(m *monitor) {
	m.signIns.Range(func(_, value any) bool {
		p := value.(*pendingSignIn)
		if p.cancel != nil {
			p.cancel()
		}
		if p.done != nil {
			<-p.done
		}
		return true
	})
	for _, c := range m.running {
		c.cancel()
	}
	for _, c := range m.running {
		<-c.done
	}
}

func signInMonitor(t *testing.T, upstream string) *monitor {
	t.Helper()
	bucket := memblob.OpenBucket(nil)
	t.Cleanup(func() { bucket.Close() })
	m := &monitor{store: stateStore{bucket: bucket}, ownerPublicKey: ed25519.NewKeyFromSeed(bytes.Repeat([]byte{1}, 32)).Public().(ed25519.PublicKey)}
	if err := m.unlock(t.Context(), bytes.Repeat([]byte{42}, 32), 0, true); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { stopSignInMonitor(m) })
	// Keep both real GitHub connector types, but never connect to a real account.
	editEnrollmentPolicy(t, m,
		sourceChange{Path: []string{"allow_networks"}, Value: []any{"127.0.0.0/8"}},
		sourceChange{Path: []string{"accounts", "github"}, Value: map[string]any{"preset": "github", "contents": "team", "sends": "me"}},
		sourceChange{Path: []string{"accounts", "github", "connections", "mcp", "mcp", "url"}, Value: upstream + "/mcp"},
	)
	return m
}

func ownerSignInRequest(t *testing.T, m *monitor, session, path string, body any, status int) []byte {
	t.Helper()
	raw, err := json.Marshal(body)
	if err != nil {
		t.Fatal(err)
	}
	r := httptest.NewRequest("POST", path, bytes.NewReader(raw))
	if session != "" {
		r = r.WithContext(context.WithValue(r.Context(), ownerSSHContextKey{}, ownerSSHContext{session: session, acknowledge: func() error { return nil }}))
	}
	w := httptest.NewRecorder()
	m.ownerHandler(true, nil).ServeHTTP(w, r)
	if w.Code != status {
		t.Fatalf("%s: status=%d, want=%d: %s", path, w.Code, status, w.Body.String())
	}
	return w.Body.Bytes()
}

func TestOwnerDeviceSignIn(t *testing.T) {
	for _, outcome := range []string{"success", "cancel", "expired", "denied", "changed"} {
		t.Run(outcome, func(t *testing.T) {
			upstream := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				switch r.URL.Path {
				case "/device":
					json.NewEncoder(w).Encode(map[string]any{"device_code": "private-device-code", "user_code": "ABCD-EFGH", "verification_uri": "https://github.com/login/device", "expires_in": 60, "interval": 1})
				case "/token":
					if outcome == "denied" {
						w.Write([]byte(`{"error":"access_denied","error_description":"private-provider-response"}`))
					} else {
						w.Write([]byte(`{"access_token":"private-access-token","token_type":"bearer","scope":"repo,read:org,gist"}`))
					}
				default:
					http.NotFound(w, r)
				}
			}))
			t.Cleanup(upstream.Close)
			transport := http.DefaultTransport
			http.DefaultTransport = upstream.Client().Transport
			t.Cleanup(func() { http.DefaultTransport = transport })
			m := signInMonitor(t, upstream.URL)
			grant := json.RawMessage(`{"oauth":{"device_auth_url":"` + upstream.URL + `/device","token_url":"` + upstream.URL + `/token","client_id":"test-client","auth_style":"params","scope":"repo read:org gist"}}`)
			input := signInInput{Path: githubCredentialPaths[0], Credential: grant}
			ownerSignInRequest(t, m, "", "/accounts/github/sign-in", input, http.StatusUnauthorized)
			raw := ownerSignInRequest(t, m, "owner", "/accounts/github/sign-in", input, http.StatusOK)
			var prompt struct{ State, UserCode string }
			var response map[string]any
			if err := json.Unmarshal(raw, &response); err != nil {
				t.Fatal(err)
			}
			prompt.State, _ = response["state"].(string)
			prompt.UserCode, _ = response["user_code"].(string)
			if prompt.State == "" || prompt.UserCode != "ABCD-EFGH" || strings.Contains(string(raw), "private-") {
				t.Fatalf("invalid public prompt: %s", raw)
			}
			path := "/sign-in/" + prompt.State
			value, _ := m.signIns.Load(prompt.State)
			pending := value.(*pendingSignIn)
			ownerSignInRequest(t, m, "other-owner", path, finishSignInInput{}, http.StatusBadRequest)
			ownerSignInRequest(t, m, "other-owner", path, finishSignInInput{Cancel: true}, http.StatusBadRequest)
			if raw := ownerSignInRequest(t, m, "owner", path, finishSignInInput{}, http.StatusOK); !strings.Contains(string(raw), `"pending":true`) {
				t.Fatalf("expected pending result: %s", raw)
			}
			if outcome == "cancel" || outcome == "expired" {
				if outcome == "expired" {
					pending.expires = time.Now().Add(-time.Second)
					ownerSignInRequest(t, m, "owner", path, finishSignInInput{}, http.StatusBadRequest)
				} else {
					ownerSignInRequest(t, m, "owner", path, finishSignInInput{Cancel: true}, http.StatusOK)
				}
				select {
				case <-pending.done:
				case <-time.After(time.Second):
					t.Fatal("cancellation did not stop provider polling")
				}
			} else {
				if outcome == "changed" {
					editEnrollmentPolicy(t, m, sourceChange{Path: append([]string{"accounts", "github"}, githubCredentialPaths[1]...), Value: "newer-owner-token"})
				}
				select {
				case <-pending.done:
				case <-time.After(5 * time.Second):
					t.Fatal("device polling did not complete")
				}
				status := http.StatusOK
				if outcome != "success" {
					status = http.StatusBadRequest
				}
				raw = ownerSignInRequest(t, m, "owner", path, finishSignInInput{}, status)
				if strings.Contains(string(raw), "private-access-token") || strings.Contains(string(raw), "private-device-code") || strings.Contains(string(raw), "private-provider-response") {
					t.Fatal("sign-in result disclosed provider data")
				}
			}
			ownerSignInRequest(t, m, "owner", path, finishSignInInput{}, http.StatusBadRequest)
			for _, p := range githubCredentialPaths {
				c := m.live.Load().connections[connectionName("github", p[1])]
				token, err := c.Secrets[p[4]].Value(t.Context())
				want := ""
				if outcome == "success" {
					want = "private-access-token"
				} else if outcome == "changed" && p[1] == "mcp" {
					want = "newer-owner-token"
				}
				if token != want || err != nil {
					t.Fatalf("%v credential=%q, want=%q, error=%v", p, token, want, err)
				}
			}
			if outcome == "success" {
				encrypted, err := m.store.bucket.ReadAll(t.Context(), stateObject)
				if err != nil || bytes.Contains(encrypted, []byte("private-access-token")) {
					t.Fatal("credential was not encrypted at rest")
				}
				restored := &monitor{store: stateStore{bucket: m.store.bucket}}
				if err := restored.unlock(t.Context(), bytes.Repeat([]byte{42}, 32), m.store.doc.Generation, false); err != nil {
					t.Fatal(err)
				}
				t.Cleanup(func() { stopSignInMonitor(restored) })
				for _, p := range githubCredentialPaths {
					value := restored.live.Load().connections[connectionName("github", p[1])].Secrets[p[4]]
					if token, err := value.Value(t.Context()); err != nil || token != "private-access-token" {
						t.Fatalf("credential did not survive restart: %v", err)
					}
				}
			}
		})
	}
}

func TestSignInWithDisabledCompanionConnection(t *testing.T) {
	m := signInMonitor(t, "https://127.0.0.1:1")
	editEnrollmentPolicy(t, m, sourceChange{Path: []string{"accounts", "github", "connections", "mcp"}, Value: nil})
	_, save, err := m.signInCredential("github", githubCredentialPaths[0])
	if err != nil {
		t.Fatal(err)
	}
	if err := save(t.Context(), json.RawMessage(`"test-token"`)); err != nil {
		t.Fatal(err)
	}
	if token, err := m.live.Load().connections["github"].Secrets["GITHUB_TOKEN"].Value(t.Context()); err != nil || token != "test-token" {
		t.Fatal("HTTP-only account could not sign in")
	}
	if m.live.Load().connections["github-mcp"] != nil {
		t.Fatal("sign-in restored a disabled connection")
	}
}
