package main

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
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
