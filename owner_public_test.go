package main

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"reflect"
	"testing"

	"gocloud.dev/blob/memblob"
)

func TestOwnerSSHUnlockAndRecovery(t *testing.T) {
	seed := bytes.Repeat([]byte{1}, 32)
	public := ed25519.NewKeyFromSeed(seed).Public().(ed25519.PublicKey)
	key := bytes.Repeat([]byte{2}, 32)
	store := memblob.OpenBucket(nil)
	defer store.Close()
	makeMonitor := func() *monitor { return &monitor{store: store, ownerPublicKey: public} }
	m := makeMonitor()
	body, _ := json.Marshal(unlockInput{StorageKey: key})
	for _, path := range []string{"/unlock", "/owner/challenge", "/policy", "/app/"} {
		r := httptest.NewRequest("POST", path, bytes.NewReader(body))
		r.Header.Set("Authorization", "Bearer "+base64.StdEncoding.EncodeToString(key))
		w := httptest.NewRecorder()
		m.handler().ServeHTTP(w, r)
		if w.Code != http.StatusNotFound {
			t.Fatalf("public %s: %d", path, w.Code)
		}
	}
	// Neither possession of the storage key nor HTTP headers confer SSH authority.
	r := httptest.NewRequest("POST", "/unlock", bytes.NewReader(body))
	r.Header.Set("X-Tinfoil-Owner", "true")
	w := httptest.NewRecorder()
	m.ownerHandler(true).ServeHTTP(w, r)
	if w.Code != http.StatusUnauthorized || m.live.Load() != nil {
		t.Fatal("HTTP claimed Monitor")
	}

	call := func(m *monitor, key []byte, floor uint64) *httptest.ResponseRecorder {
		// Deliberately omit generation from the body; the channel floor must govern unlock.
		data, _ := json.Marshal(unlockInput{StorageKey: key})
		options := ownerChannelOptions{Host: "owner.monitor", Token: base64.RawURLEncoding.EncodeToString(seed), Generation: floor}
		r := httptest.NewRequest("POST", "http://owner.monitor/api/unlock", bytes.NewReader(data))
		r.Header.Set("X-Tinfoil-Session", options.Token)
		w := httptest.NewRecorder()
		m.ownerPanel(options, func() error { return nil }).ServeHTTP(w, r)
		return w
	}
	if w := call(m, key[:31], 0); w.Code == http.StatusOK || m.live.Load() != nil {
		t.Fatal("invalid storage key accepted")
	}
	if w := call(m, key, 0); w.Code != http.StatusOK {
		t.Fatal(w.Code, w.Body.String())
	}
	if call(m, seed, 0).Code == http.StatusOK {
		t.Fatal("wrong storage key accepted")
	}
	raw, err := store.ReadAll(t.Context(), stateObject)
	if err != nil {
		t.Fatal(err)
	}
	for _, candidate := range [][]byte{public, seed} {
		aead, _ := newAEAD(candidate)
		if _, err := aead.Open(nil, nil, raw, nil); err == nil {
			t.Fatal("SSH material decrypted storage")
		}
	}
	after := makeMonitor()
	if w := call(after, key, m.doc.Generation+1); w.Code == http.StatusOK || after.live.Load() != nil {
		t.Fatal("accepted rolled-back state")
	}
	if w := call(after, key, m.doc.Generation); w.Code != http.StatusOK {
		t.Fatal(w.Code, w.Body.String())
	}
	if !reflect.DeepEqual(after.doc.Keys, m.doc.Keys) || after.doc.Generation != m.doc.Generation+1 {
		t.Fatal("restart lost encrypted identities")
	}
}

func TestMeasuredOwnerPublicKey(t *testing.T) {
	key := bytes.Repeat([]byte{1}, ed25519.PublicKeySize)
	encoded := "ed25519:" + base64.StdEncoding.EncodeToString(key)
	got, err := parseOwnerPublicKey(encoded)
	if err != nil || !bytes.Equal(got, key) {
		t.Fatal("valid owner key refused")
	}
	for _, invalid := range []string{"", "ssh-" + encoded, encoded + "\n", "ed25519:" + base64.StdEncoding.EncodeToString(key[:31])} {
		if _, err := parseOwnerPublicKey(invalid); err == nil {
			t.Fatal("invalid owner key accepted")
		}
	}
}

func TestAppAuthenticationMode(t *testing.T) {
	for _, tc := range []struct {
		name   string
		public bool
		ssh    bool
		mode   string
	}{
		{name: "direct browser", mode: "bearer"},
		{name: "owner SSH panel", public: true, ssh: true, mode: "ssh"},
		{name: "public HTTP for SSH owner", public: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			m := &monitor{}
			if tc.public {
				m.ownerPublicKey = make(ed25519.PublicKey, ed25519.PublicKeySize)
			}
			handler := m.handler()
			if tc.ssh {
				handler = m.ownerPanel(ownerChannelOptions{Host: "127.0.0.1:12345"}, func() error {
					t.Fatal("loading sign-in options must not acknowledge an owner operation")
					return nil
				})
			}
			w := httptest.NewRecorder()
			handler.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "http://127.0.0.1:12345/app/auth.json", nil))
			if tc.mode == "" {
				if w.Code != http.StatusNotFound {
					t.Fatalf("public HTTP exposed app config: %d", w.Code)
				}
				return
			}
			var config map[string]string
			if w.Code != http.StatusOK || json.Unmarshal(w.Body.Bytes(), &config) != nil || config["mode"] != tc.mode {
				t.Fatalf("sign-in options: %d %s", w.Code, w.Body.String())
			}
			if w.Header().Get("Cache-Control") != "no-store" {
				t.Fatal("sign-in options must not be cached")
			}
		})
	}
}

func TestOwnerAppAssetSource(t *testing.T) {
	embedded, err := app.ReadFile("app/index.html")
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name string
		dev  bool
		ssh  bool
	}{
		{name: "local development reloads files", dev: true},
		{name: "owner SSH keeps embedded assets", dev: true, ssh: true},
		{name: "production keeps embedded assets"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Chdir(t.TempDir())
			if err := os.Mkdir("app", 0o700); err != nil {
				t.Fatal(err)
			}
			handler := (&monitor{dev: tc.dev}).ownerHandler(tc.ssh)
			for _, content := range []string{"before", "after"} {
				if err := os.WriteFile("app/index.html", []byte(content), 0o600); err != nil {
					t.Fatal(err)
				}
				r := httptest.NewRequest(http.MethodGet, "/app/", nil)
				want := string(embedded)
				if tc.dev && !tc.ssh {
					want = content
					r.Header.Set("If-Modified-Since", "Fri, 31 Dec 9999 23:59:59 GMT")
				}
				w := httptest.NewRecorder()
				handler.ServeHTTP(w, r)
				if w.Code != http.StatusOK || w.Body.String() != want || w.Header().Get("Cache-Control") != "no-store" {
					t.Fatalf("unexpected asset response: status %d, %d bytes", w.Code, w.Body.Len())
				}
			}
		})
	}
}
