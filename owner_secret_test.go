package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"

	"gocloud.dev/blob/memblob"
)

const unicodeOwnerPHC = "$argon2id$v=19$m=262144,t=3,p=4$AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8$a0FZaNclCYyaPhjUatURHT9w5vA+/5MPWZZCRzopI1k"

func TestOwnerPassphraseStateRecovery(t *testing.T) {
	secret := []byte("  Café workspace 🔐\n")
	commitment, err := parseOwnerCommitment("", unicodeOwnerPHC)
	if err != nil {
		t.Fatal(err)
	}
	store := memblob.OpenBucket(nil)
	defer store.Close()
	open := func() *monitor { return &monitor{store: store, ownerCommitment: commitment} }
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
	header := raw[:len(stateMagic)+32]
	if bytes.Equal(header[len(stateMagic):], commitment.salt) {
		t.Fatal("storage reused the public commitment salt")
	}
	public, _ := newAEAD(commitment.hash)
	if _, err := public.Open(nil, nil, raw[len(header):], header); err == nil {
		t.Fatal("public verifier decrypted state")
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

func TestLegacyOwnerStateRemainsReadable(t *testing.T) {
	secret := bytes.Repeat([]byte{7}, ownerKeyBytes)
	digest := sha256.Sum256(secret)
	commitment, err := parseOwnerCommitment(hex.EncodeToString(digest[:]), "")
	if err != nil {
		t.Fatal(err)
	}
	store := memblob.OpenBucket(nil)
	defer store.Close()
	m := &monitor{store: store, ownerCommitment: commitment}
	if err := m.unlock(t.Context(), secret, 0); err != nil {
		t.Fatal(err)
	}
	restarted := &monitor{store: store, ownerCommitment: commitment}
	if err := restarted.unlock(t.Context(), secret, 1); err != nil {
		t.Fatal(err)
	}
	raw, _ := store.ReadAll(t.Context(), stateObject)
	aead, _ := newAEAD(secret)
	if _, err := aead.Open(nil, nil, raw, nil); err != nil {
		t.Fatal("legacy state format changed", err)
	}
}

func TestOwnerBindingAndTransportValidation(t *testing.T) {
	for _, phc := range []string{"", strings.Replace(unicodeOwnerPHC, "m=262144", "m=1", 1), unicodeOwnerPHC + "$extra", unicodeOwnerPHC + "=", strings.Replace(unicodeOwnerPHC, "v=19", "v=16", 1)} {
		if _, err := parseOwnerCommitment("", phc); err == nil {
			t.Fatal("accepted invalid commitment")
		}
	}
	if _, err := parseOwnerCommitment(strings.Repeat("a", 64), unicodeOwnerPHC); err == nil {
		t.Fatal("accepted two bindings")
	}
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
