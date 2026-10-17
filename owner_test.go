package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"gocloud.dev/blob/memblob"
	"golang.org/x/crypto/ssh"
)

func TestOwnerUnlockRestoresDevice(t *testing.T) {
	bucket := memblob.OpenBucket(nil)
	t.Cleanup(func() { bucket.Close() })
	secret := bytes.Repeat([]byte{42}, 32)
	owner := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{1}, 32)).Public().(ed25519.PublicKey)
	m := &monitor{store: bucket, ownerPublicKey: owner}
	public, err := ssh.NewPublicKey(ed25519.NewKeyFromSeed(bytes.Repeat([]byte{2}, 32)).Public())
	if err != nil {
		t.Fatal(err)
	}
	key := strings.TrimSpace(string(ssh.MarshalAuthorizedKey(public)))
	digest := sha256.Sum256([]byte(key))
	name := fmt.Sprintf("device-%x", digest[:8])
	request := func(input unlockInput, authenticated bool, wantStatus int) {
		t.Helper()
		raw, err := json.Marshal(input)
		if err != nil {
			t.Fatal(err)
		}
		r := httptest.NewRequest(http.MethodPost, "/unlock", bytes.NewReader(raw))
		if authenticated {
			r = r.WithContext(context.WithValue(r.Context(), ownerSSHContextKey{}, ownerSSHContext{acknowledge: func() error { return nil }}))
		}
		w := httptest.NewRecorder()
		m.ownerHandler(true).ServeHTTP(w, r)
		if w.Code != wantStatus {
			t.Fatalf("unlock status %d, want %d: %s", w.Code, wantStatus, w.Body.String())
		}
	}
	unlock := unlockInput{StorageKey: secret, Initialize: true, DeviceKey: key}
	request(unlock, false, http.StatusUnauthorized)
	if m.live.Load() != nil {
		t.Fatal("unauthenticated unlock initialized state")
	}
	request(unlock, true, http.StatusOK)
	if id := m.live.Load().cfg.Identities[name]; id.Key != key || !id.Routes {
		t.Fatalf("device not enrolled during unlock: %+v", id)
	}

	// An unchanged unlock must preserve both the live policy and encrypted object.
	before, err := bucket.ReadAll(t.Context(), stateObject)
	if err != nil {
		t.Fatal(err)
	}
	live, generation := m.live.Load(), m.doc.Generation
	request(unlock, true, http.StatusOK)
	after, err := bucket.ReadAll(t.Context(), stateObject)
	if err != nil || !bytes.Equal(before, after) || m.live.Load() != live || m.doc.Generation != generation {
		t.Fatalf("unchanged unlock rewrote state: %v", err)
	}

	// Restore by fingerprint so a renamed device keeps its settings and name.
	effectEdit(t, m,
		sourceChange{Path: []string{"identities", name}, Delete: true},
		sourceChange{Path: []string{"identities", "laptop"}, Value: map[string]any{
			"key": key, "routes": false, "effects": map[string]string{"pay": "off"}}})
	request(unlock, true, http.StatusOK)
	if ids := m.live.Load().cfg.Identities; len(ids) != 1 || !ids["laptop"].Routes || ids["laptop"].Effects["pay"] != "off" {
		t.Fatalf("restoration changed identity settings: %+v", ids)
	}

	effectEdit(t, m, sourceChange{Path: []string{"identities", "laptop"}, Delete: true})
	wrong := unlock
	wrong.StorageKey = bytes.Repeat([]byte{43}, 32)
	request(wrong, true, http.StatusUnauthorized)
	legacy := unlock
	legacy.DeviceKey = ""
	request(legacy, true, http.StatusOK)
	if len(m.live.Load().cfg.Identities) != 0 {
		t.Fatal("failed or legacy unlock restored a revoked identity")
	}
	request(unlock, true, http.StatusOK)
	if !m.live.Load().cfg.Identities[name].Routes {
		t.Fatal("unlock did not restore the removed device")
	}

	// A restarted Monitor must load the restored identity from encrypted storage.
	m = &monitor{store: bucket, ownerPublicKey: owner}
	legacy.Initialize = false
	request(legacy, true, http.StatusOK)
	if !m.live.Load().cfg.Identities[name].Routes {
		t.Fatal("restoration was not persisted")
	}

	other, err := ssh.NewPublicKey(owner)
	if err != nil {
		t.Fatal(err)
	}
	otherKey := strings.TrimSpace(string(ssh.MarshalAuthorizedKey(other)))
	effectEdit(t, m, sourceChange{Path: []string{"identities", name, "key"}, Value: otherKey})
	request(unlock, true, http.StatusBadRequest)
	if m.live.Load().cfg.Identities[name].Key != otherKey {
		t.Fatal("restoration replaced an unrelated key")
	}
	malformed := unlock
	malformed.DeviceKey = "invalid key"
	request(malformed, true, http.StatusBadRequest)
}
