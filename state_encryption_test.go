package main

import (
	"bytes"
	"encoding/base64"
	"errors"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"

	"gocloud.dev/blob/memblob"
)

func TestDevelopmentPassphraseStateRecovery(t *testing.T) {
	secret := []byte("  Café workspace 🔐\n")
	store := memblob.OpenBucket(nil)
	defer store.Close()
	open := func() *monitor { return &monitor{store: store, dev: true} }
	m := open()
	r := httptest.NewRequest("POST", "/unlock", strings.NewReader(`{"generation":0}`))
	r.Header.Set("Authorization", "Bearer "+base64.StdEncoding.EncodeToString(secret))
	w := httptest.NewRecorder()
	m.handler().ServeHTTP(w, r)
	if w.Code != http.StatusOK {
		t.Fatalf("HTTP unlock failed: %d", w.Code)
	}
	raw, err := store.ReadAll(t.Context(), stateObject)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.HasPrefix(raw, stateMagic) || bytes.Contains(raw, []byte("PRIVATE KEY")) {
		t.Fatal("state was not encrypted with the versioned format")
	}
	wrong := open()
	if err := wrong.unlock(t.Context(), bytes.TrimSpace(secret), 0); !errors.Is(err, errOwner) {
		t.Fatalf("normalized passphrase accepted: %v", err)
	}
	after, _ := store.ReadAll(t.Context(), stateObject)
	if !bytes.Equal(after, raw) {
		t.Fatal("failed authentication changed state")
	}
	restarted := open()
	if err := restarted.unlock(t.Context(), secret, m.doc.Generation); err != nil {
		t.Fatal(err)
	}
	if restarted.doc.Generation != m.doc.Generation+1 || !reflect.DeepEqual(restarted.doc.Keys, m.doc.Keys) {
		t.Fatal("restart lost state")
	}
	if err := restarted.unlock(t.Context(), secret, restarted.doc.Generation+1); err == nil {
		t.Fatal("accepted rollback")
	}
	raw, _ = store.ReadAll(t.Context(), stateObject)
	raw[len(stateMagic)] ^= 1
	if err := store.WriteAll(t.Context(), stateObject, raw, nil); err != nil {
		t.Fatal(err)
	}
	if err := open().unlock(t.Context(), secret, 0); !errors.Is(err, errOwner) {
		t.Fatalf("tampered salt accepted: %v", err)
	}
}

func TestDevelopmentOwnerTransportValidation(t *testing.T) {
	for _, size := range []int{0, 15, 16, 32, 64, 4096, 4097} {
		r := httptest.NewRequest("POST", "/unlock", nil)
		r.Header.Set("Authorization", "Bearer "+base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{'x'}, size)))
		key, err := ownerKey(r)
		valid := size >= 16 && size <= 4096
		if (err == nil) != valid || valid && len(key) != size {
			t.Fatalf("length %d: %v", size, err)
		}
	}
}
