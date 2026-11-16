package credential_test

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/tinfoilsh/confidential-agent-monitor/credential"
)

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
	limits := credential.SignInLimits{Timeout: 10 * time.Second, Lifetime: time.Minute, MaxDeviceExpiry: time.Hour, MaxDeviceInterval: 5, MaxResponseBytes: 1 << 10, MaxClientIDBytes: 512}
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
			l := limits
			tc.change(&l)
			signIns := credential.NewSignIns("client", l)
			sign, err := signIns.Start(context.Background(), server.Client(), grant, "", "session", save)
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
