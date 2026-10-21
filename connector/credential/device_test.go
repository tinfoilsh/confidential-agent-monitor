package credential

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"testing/synctest"
	"time"
)

type deviceTransport func(*http.Request) (*http.Response, error)

func (f deviceTransport) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

const deviceGrant = `{"oauth":{"device_auth_url":"https://provider.example/device","token_url":"https://provider.example/token","client_id":"public-client","auth_style":"params","scope":"repo read:org gist","required_scopes":["repo","read:org","gist"]}}`
const deviceResponse = `{"device_code":"private-device-code","user_code":"ABCD-EFGH","verification_uri":"https://provider.example/activate","expires_in":900,"interval":5}`

func deviceJSON(body string) *http.Response {
	return &http.Response{StatusCode: http.StatusOK, Header: http.Header{"Content-Type": {"application/json"}}, Body: io.NopCloser(strings.NewReader(body))}
}

func TestDeviceSignInPollingAndStoredGrant(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		start := time.Now()
		var polls []time.Duration
		client := &http.Client{Transport: deviceTransport(func(r *http.Request) (*http.Response, error) {
			if err := r.ParseForm(); err != nil {
				t.Fatal(err)
			}
			if r.Method != "POST" || r.Form.Get("client_id") != "public-client" || r.Form.Has("client_secret") {
				t.Fatalf("unexpected OAuth request: %s %v", r.Method, r.Form)
			}
			if r.URL.Path == "/device" {
				if r.Form.Get("scope") != "repo read:org gist" || r.Header.Get("Accept") != "application/json" {
					t.Fatal("device authorization omitted scopes or JSON negotiation")
				}
				return deviceJSON(deviceResponse), nil
			}
			if r.Form.Get("device_code") != "private-device-code" || r.Form.Get("grant_type") != "urn:ietf:params:oauth:grant-type:device_code" {
				t.Fatal("incorrect device token exchange")
			}
			polls = append(polls, time.Since(start))
			switch len(polls) {
			case 1:
				return deviceJSON(`{"error":"authorization_pending"}`), nil
			case 2:
				return deviceJSON(`{"error":"slow_down"}`), nil
			default:
				return deviceJSON(`{"access_token":"test-access-token","token_type":"bearer","scope":"repo,read:org,gist"}`), nil
			}
		})}
		sign, err := NewSignIn(t.Context(), client, json.RawMessage(deviceGrant), "")
		if err != nil {
			t.Fatal(err)
		}
		if sign.UserCode != "ABCD-EFGH" || sign.URL != "https://provider.example/activate" || sign.State == "" || sign.Expires.Sub(start) != 15*time.Minute {
			t.Fatal("incorrect device prompt")
		}
		raw, err := sign.WaitDevice(t.Context())
		if err != nil {
			t.Fatal(err)
		}
		if fmt.Sprint(polls) != "[5s 10s 20s]" {
			t.Fatalf("polling did not respect slowdown: %v", polls)
		}
		var value Value
		if err := json.Unmarshal(raw, &value); err != nil {
			t.Fatal(err)
		}
		if token, err := value.Value(t.Context()); err != nil || token != "test-access-token" || Describe(raw) != "oauth" {
			t.Fatalf("stored grant cannot supply the token: %v", err)
		}
		if value.grant.Scope != "repo read:org gist" || strings.Contains(string(raw), "private-device-code") {
			t.Fatal("scope normalization or device code isolation failed")
		}
	})
}

func TestDeviceSignInFailures(t *testing.T) {
	for _, tc := range []struct{ name, response, want string }{
		{"denied", `{"error":"access_denied","error_description":"private-device-code"}`, "declined"},
		{"expired", `{"error":"expired_token"}`, "expired"},
		{"scope", `{"access_token":"private-token","token_type":"bearer","scope":"read:org"}`, "permissions"},
		{"token", `{"access_token":"private-token","token_type":"mac"}`, "bearer"},
		{"provider", `{"error":"unknown","error_description":"private-device-code"}`, "failed"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				client := &http.Client{Transport: deviceTransport(func(r *http.Request) (*http.Response, error) {
					if r.URL.Path == "/device" {
						return deviceJSON(deviceResponse), nil
					}
					return deviceJSON(tc.response), nil
				})}
				sign, err := NewSignIn(t.Context(), client, json.RawMessage(deviceGrant), "")
				if err != nil {
					t.Fatal(err)
				}
				raw, err := sign.WaitDevice(t.Context())
				if err == nil || !strings.Contains(err.Error(), tc.want) || strings.Contains(err.Error(), "private-") || raw != nil {
					t.Fatalf("unexpected result: %s, %v", raw, err)
				}
			})
		})
	}
}

func TestDeviceSignInCancellationAndDeadline(t *testing.T) {
	for _, cancelEarly := range []bool{false, true} {
		t.Run(fmt.Sprint(cancelEarly), func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				polls := 0
				client := &http.Client{Transport: deviceTransport(func(r *http.Request) (*http.Response, error) {
					if r.URL.Path == "/device" {
						return deviceJSON(strings.Replace(deviceResponse, "900", "12", 1)), nil
					}
					polls++
					return deviceJSON(`{"error":"authorization_pending"}`), nil
				})}
				sign, err := NewSignIn(t.Context(), client, json.RawMessage(deviceGrant), "")
				if err != nil {
					t.Fatal(err)
				}
				ctx, cancel := context.WithCancel(t.Context())
				defer cancel()
				if cancelEarly {
					time.AfterFunc(time.Second, cancel)
				}
				_, err = sign.WaitDevice(ctx)
				if err == nil || cancelEarly && (err != context.Canceled || polls != 0) || !cancelEarly && (!strings.Contains(err.Error(), "expired") || polls != 2) {
					t.Fatalf("polls=%d, error=%v", polls, err)
				}
			})
		})
	}
}

func TestDeviceSignInRejectsInvalidPrompt(t *testing.T) {
	for _, response := range []string{
		`{"error":"device_flow_disabled"}`,
		strings.Replace(deviceResponse, "https://provider.example/activate", "javascript:alert(1)", 1),
		strings.Replace(deviceResponse, "900", "-1", 1),
		strings.Replace(deviceResponse, `"interval":5`, `"interval":-1`, 1),
	} {
		client := &http.Client{Transport: deviceTransport(func(*http.Request) (*http.Response, error) { return deviceJSON(response), nil })}
		if _, err := NewSignIn(t.Context(), client, json.RawMessage(deviceGrant), ""); err == nil {
			t.Fatalf("accepted invalid device response: %s", response)
		}
	}
}

func TestAuthorizationCallbackStillUsesPKCE(t *testing.T) {
	client := &http.Client{Transport: deviceTransport(func(r *http.Request) (*http.Response, error) {
		if err := r.ParseForm(); err != nil {
			t.Fatal(err)
		}
		if r.Form.Get("grant_type") != "authorization_code" || r.Form.Get("code") != "auth-code" || r.Form.Get("code_verifier") == "" {
			t.Fatal("callback exchange lost its code or PKCE verifier")
		}
		return deviceJSON(`{"access_token":"callback-token","refresh_token":"callback-refresh","expires_in":3600,"token_type":"bearer"}`), nil
	})}
	sign, err := NewSignIn(t.Context(), client, json.RawMessage(`{"oauth":{"auth_url":"https://provider.example/authorize","token_url":"https://provider.example/token","client_id":"callback-client","auth_style":"params"}}`), "https://monitor.example/app/")
	if err != nil {
		t.Fatal(err)
	}
	location, _ := url.Parse(sign.URL)
	if location.Query().Get("state") != sign.State || location.Query().Get("code_challenge_method") != "S256" || sign.UserCode != "" {
		t.Fatal("callback authorization changed")
	}
	raw, err := sign.Exchange(t.Context(), "auth-code", "")
	if err != nil {
		t.Fatal(err)
	}
	var value Value
	if err := json.Unmarshal(raw, &value); err != nil || value.grant.RefreshToken != "callback-refresh" || value.grant.Expiry.IsZero() {
		t.Fatal("callback grant lost its refresh token or expiry")
	}
}
