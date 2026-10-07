package main

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"gocloud.dev/blob/memblob"
)

func TestDevAppUpdatesWithoutRestart(t *testing.T) {
	t.Chdir(t.TempDir())
	if err := os.MkdirAll("app/icons", 0o755); err != nil {
		t.Fatal(err)
	}
	modified := time.Unix(1700000000, 0)
	write := func(name, content string) {
		t.Helper()
		if err := os.WriteFile(name, []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
		if err := os.Chtimes(name, modified, modified); err != nil {
			t.Fatal(err)
		}
	}
	write("app/index.html", "before")
	handler := (&monitor{dev: true}).handler()
	get := func(path string) *httptest.ResponseRecorder {
		t.Helper()
		r := httptest.NewRequest(http.MethodGet, path, nil)
		r.Header.Set("If-Modified-Since", modified.UTC().Format(http.TimeFormat))
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, r)
		return w
	}
	for _, content := range []string{"before", "after!"} {
		write("app/index.html", content)
		w := get("/app/")
		if w.Code != http.StatusOK || w.Body.String() != content {
			t.Fatalf("after writing %q: status %d, body %q", content, w.Code, w.Body.String())
		}
		if got := w.Header().Get("Cache-Control"); got != "no-store" {
			t.Fatalf("Cache-Control = %q, want no-store", got)
		}
	}
	// Assets created after startup are also served from the app directory.
	write("app/icons/new.svg", "<svg/>")
	if w := get("/app/icons/new.svg"); w.Code != http.StatusOK || w.Body.String() != "<svg/>" {
		t.Fatalf("new icon: status %d, body %q", w.Code, w.Body.String())
	}
	write("private.txt", "outside the app")
	if w := get("/app/private.txt"); w.Code != http.StatusNotFound {
		t.Fatalf("file outside app: status %d, want 404", w.Code)
	}
	if w := get("/app/index.html"); w.Code != http.StatusMovedPermanently || w.Header().Get("Location") != "./" {
		t.Fatalf("index redirect: status %d, location %q", w.Code, w.Header().Get("Location"))
	}
}

func TestEmbeddedApp(t *testing.T) {
	embedded, err := app.ReadFile("app/index.html")
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name  string
		dev   bool
		local bool
	}{
		{name: "production ignores local files", local: true},
		{name: "dev without local files", dev: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Chdir(t.TempDir())
			if tc.local {
				if err := os.Mkdir("app", 0o755); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile("app/index.html", []byte("local copy"), 0o600); err != nil {
					t.Fatal(err)
				}
			}
			w := httptest.NewRecorder()
			(&monitor{dev: tc.dev}).handler().ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/app/", nil))
			if w.Code != http.StatusOK || w.Body.String() != string(embedded) {
				t.Fatalf("embedded app: status %d, got %d bytes", w.Code, w.Body.Len())
			}
		})
	}
}

// Browser controls answer only the owner, and only for a browser connection.
func TestBrowserControlNeedsOwner(t *testing.T) {
	m := &monitor{store: memblob.OpenBucket(nil), object: "monitor.enc", listen: "127.0.0.1:0"}
	handler := m.handler()
	key, wrong := make([]byte, ownerKeyBytes), make([]byte, ownerKeyBytes)
	rand.Read(key)
	rand.Read(wrong)
	get := func(secret []byte) int {
		r := httptest.NewRequest(http.MethodPost, "/connections/web/browser", strings.NewReader(`{"action":"pause"}`))
		if secret != nil {
			r.Header.Set("Authorization", "Bearer "+base64.StdEncoding.EncodeToString(secret))
		}
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, r)
		return w.Code
	}
	if status := get(key); status != http.StatusLocked {
		t.Fatalf("while locked: %d", status)
	}
	if _, err := m.unlock(context.Background(), key, 0); err != nil {
		t.Fatal(err)
	}
	if _, err := m.patch(context.Background(), []byte(`{"accounts": {"web": {"preset": "web", "contents": "anyone", "sends": "anyone"}}}`)); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		secret []byte
		want   int
	}{{nil, http.StatusUnauthorized}, {wrong, http.StatusUnauthorized}, {key, http.StatusNotFound}} {
		if status := get(tc.secret); status != tc.want {
			t.Fatalf("status %d, want %d", status, tc.want)
		}
	}
}
