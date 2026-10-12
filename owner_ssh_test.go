package main

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"net/http/httptest"
	"testing"

	"gocloud.dev/blob/memblob"
	"golang.org/x/crypto/ssh"
)

func TestOwnerSSHBindingAndBrowserIsolation(t *testing.T) {
	private := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{1}, 32))
	store := memblob.OpenBucket(nil)
	defer store.Close()
	m := &monitor{ownerPublicKey: private.Public().(ed25519.PublicKey), store: store}
	if err := m.unlock(t.Context(), bytes.Repeat([]byte{2}, 32), 0); err != nil {
		t.Fatal(err)
	}
	owner, _ := ssh.NewPublicKey(private.Public())
	permissions, err := m.authorized(nil, owner)
	if err != nil || permissions.Extensions[ownerSSHExtension] != "true" {
		t.Fatal("bound owner not recognized")
	}
	stranger, _ := ssh.NewPublicKey(ed25519.NewKeyFromSeed(bytes.Repeat([]byte{3}, 32)).Public())
	permissions, err = m.authorized(nil, stranger)
	if err != nil || permissions.Extensions[ownerSSHExtension] != "" {
		t.Fatal("stranger gained owner authority")
	}
	// Even a trusted HTTP handler must receive the server-only context marker.
	r := httptest.NewRequest("GET", "/", nil)
	r.Header.Set("X-Tinfoil-Owner", "true")
	w := httptest.NewRecorder()
	m.ownerHandler(true).ServeHTTP(w, r)
	if w.Code != 401 {
		t.Fatal("header forged owner authority", w.Code)
	}
	token := base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{4}, 32))
	options := ownerChannelOptions{Host: "127.0.0.1:12345", Token: token}
	acks := 0
	panel := m.ownerPanel(options, func() error { acks++; return nil })
	for _, test := range []struct {
		name, path, site, mode, dest, token, origin, host string
		code                                              int
	}{
		{"API", "/api/", "same-origin", "cors", "empty", token, "", options.Host, 200},
		{"no session", "/api/", "same-origin", "cors", "empty", "", "", options.Host, 401},
		{"foreign origin", "/api/", "same-origin", "cors", "empty", token, "https://evil.invalid", options.Host, 403},
		{"foreign host", "/api/", "same-origin", "cors", "empty", token, "", "evil.invalid", 403},
		{"cross-site", "/api/", "cross-site", "cors", "empty", token, "", options.Host, 403},
		{"OAuth return", "/app/?state=test&code=test", "cross-site", "navigate", "document", "", "", options.Host, 200},
		{"fun UI OAuth return", "/app/fun_ui.html?state=test&code=test", "cross-site", "navigate", "document", "", "", options.Host, 200},
		{"dashboard module", "/app/dashboard.js", "same-origin", "cors", "script", "", "", options.Host, 200},
		{"shared UI runtime", "/app/monitor.js", "same-origin", "cors", "script", "", "", options.Host, 200},
		{"dashboard styles", "/app/dashboard.css", "same-origin", "no-cors", "style", "", "", options.Host, 200},
		{"dashboard font", "/app/fonts/aeonik-fono-regular.woff2", "same-origin", "cors", "font", "", "", options.Host, 200},
		{"API navigation", "/api/", "cross-site", "navigate", "document", token, "", options.Host, 403},
		{"cross-site asset", "/app/owner.js", "cross-site", "no-cors", "script", "", "", options.Host, 403},
		{"unlock", "/api/unlock", "same-origin", "cors", "empty", token, "", options.Host, 404},
		{"encoded unlock", "/api/%75nlock", "same-origin", "cors", "empty", token, "", options.Host, 404},
		{"challenge", "/api/owner/challenge", "same-origin", "cors", "empty", token, "", options.Host, 404},
		{"path escape", "/api/../unlock", "same-origin", "cors", "empty", token, "", options.Host, 404},
	} {
		t.Run(test.name, func(t *testing.T) {
			r := httptest.NewRequest("GET", "http://"+options.Host+test.path, nil)
			r.Host = test.host
			for k, v := range map[string]string{"X-Tinfoil-Session": test.token, "Origin": test.origin, "Sec-Fetch-Site": test.site, "Sec-Fetch-Mode": test.mode, "Sec-Fetch-Dest": test.dest} {
				r.Header.Set(k, v)
			}
			w := httptest.NewRecorder()
			panel.ServeHTTP(w, r)
			if w.Code != test.code {
				t.Fatalf("got %d: %s", w.Code, w.Body.String())
			}
		})
	}
	if acks != 1 {
		t.Fatalf("unexpected generation acknowledgments: %d", acks)
	}
}
