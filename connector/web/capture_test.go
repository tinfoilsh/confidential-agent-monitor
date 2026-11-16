package web_test

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/tinfoilsh/confidential-agent-monitor/connector/web"
	"github.com/tinfoilsh/confidential-agent-monitor/core/facts"
)

type roundTrip func(*http.Request) (*http.Response, error)

func (f roundTrip) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func TestCapturedPreparedInputGovernsExecution(t *testing.T) {
	for _, allow := range []bool{false, true} {
		t.Run(map[bool]string{false: "refuse", true: "allow"}[allow], func(t *testing.T) {
			const body = `{"value":9007199254740993}`
			var captured facts.Event
			forwarded, resolved := 0, 0
			setup, err := web.New(nil, nil, []string{"example.test"}, web.Slots{
				Claim:  func(string, uint32) int { return -1 },
				Covers: func(string, string) bool { return false },
				Bind: func(r *http.Request, _ string, _ func(string) string) ([]string, func(*http.Request, func(context.Context, string) (string, error)) (*http.Request, error), error) {
					return []string{"token"}, func(r *http.Request, secret func(context.Context, string) (string, error)) (*http.Request, error) {
						value, err := secret(r.Context(), "token")
						clone := r.Clone(r.Context())
						clone.Header.Set("Authorization", value)
						return clone, err
					}, nil
				},
			})
			if err != nil {
				t.Fatal(err)
			}
			req := httptest.NewRequest("POST", "/original", strings.NewReader(`{"value":1}`))
			req.Host = "example.test"
			req.Header.Set("Content-Type", "application/json")
			req.Header.Set("Authorization", "placeholder")
			response := httptest.NewRecorder()
			handler := web.Handler{Setup: setup, MaxBody: 8 << 20,
				ServeHTTP: func(_ context.Context, _ net.Conn, server *http.Server) error {
					server.Handler.ServeHTTP(response, req)
					return nil
				},
				Prepare: func(r *http.Request, _ *web.HTTPFacts) (http.RoundTripper, error) {
					r.URL.Path = "/prepared"
					r.Body = io.NopCloser(strings.NewReader(body))
					r.ContentLength = int64(len(body))
					return nil, nil
				},
				Secret: func(context.Context, string) (string, error) {
					resolved++
					if captured == "" {
						t.Error("secret resolved before authorization")
					}
					return "private credential", nil
				},
				Transport: roundTrip(func(r *http.Request) (*http.Response, error) {
					forwarded++
					actual, err := io.ReadAll(r.Body)
					if err != nil || string(actual) != body || r.URL.Path != "/prepared" || r.Header.Get("Authorization") != "private credential" {
						t.Error("execution differs from captured input and declared credential placement")
					}
					return &http.Response{StatusCode: http.StatusOK, Header: make(http.Header), Body: io.NopCloser(strings.NewReader("ok"))}, nil
				}),
			}
			handler.Serve(t.Context(), nil, "service", "example.test", 80, func(_ context.Context, event facts.Event) error {
				captured = event
				o, err := event.Decode()
				if err != nil {
					t.Fatal(err)
				}
				details, err := facts.JSON[web.Details](o.Details)
				if err != nil || details.HTTP.Path != "/prepared" || details.HTTP.Headers.Get("Authorization") != "placeholder" || details.HTTP.Body.(map[string]any)["value"] != json.Number("9007199254740993") {
					t.Fatalf("gate did not receive exact prepared input: %+v (%v)", details, err)
				}
				if !allow {
					return errors.New("refused by application")
				}
				return nil
			})
			if allow && (response.Code != http.StatusOK || forwarded != 1 || resolved != 1) {
				t.Fatalf("allowed execution: status=%d forwarded=%d resolved=%d", response.Code, forwarded, resolved)
			}
			if !allow && (response.Code != http.StatusForbidden || forwarded != 0 || resolved != 0) {
				t.Fatalf("refused execution: status=%d forwarded=%d resolved=%d", response.Code, forwarded, resolved)
			}
		})
	}
}
