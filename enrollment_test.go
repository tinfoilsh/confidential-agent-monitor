package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"gocloud.dev/blob/memblob"
	"golang.org/x/crypto/ssh"
)

func editEnrollmentPolicy(t *testing.T, m *monitor, changes ...sourceChange) {
	t.Helper()
	m.mu.Lock()
	defer m.mu.Unlock()
	if err := m.editPolicy(t.Context(), changes); err != nil {
		t.Fatal(err)
	}
}

func TestOwnerEnrollmentRestoresRemovedSandboxAndDeviceAccess(t *testing.T) {
	bucket := memblob.OpenBucket(nil)
	t.Cleanup(func() { bucket.Close() })
	secret := bytes.Repeat([]byte{42}, 32)
	owner := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{1}, 32)).Public().(ed25519.PublicKey)
	m := &monitor{store: stateStore{bucket: bucket}, ownerPublicKey: owner}
	if err := m.unlock(t.Context(), secret, 0, true); err != nil {
		t.Fatal(err)
	}
	public := func(seed byte) string {
		t.Helper()
		key, err := ssh.NewPublicKey(ed25519.NewKeyFromSeed(bytes.Repeat([]byte{seed}, 32)).Public())
		if err != nil {
			t.Fatal(err)
		}
		return strings.TrimSpace(string(ssh.MarshalAuthorizedKey(key)))
	}
	device, sandbox, other := public(2), public(3), public(4)
	request := func(restore, authenticated bool, wantStatus int) {
		t.Helper()
		raw, err := json.Marshal(map[string]any{
			"device":       map[string]any{"key": device, "routes": true, "restore": restore},
			"sandbox-work": map[string]any{"key": sandbox, "restore": restore},
		})
		if err != nil {
			t.Fatal(err)
		}
		r := httptest.NewRequest(http.MethodPost, "/enroll", bytes.NewReader(raw))
		if authenticated {
			r = r.WithContext(context.WithValue(r.Context(), ownerSSHContextKey{}, ownerSSHContext{acknowledge: func() error { return nil }}))
		}
		w := httptest.NewRecorder()
		m.ownerHandler(true, nil).ServeHTTP(w, r)
		if w.Code != wantStatus {
			t.Fatalf("enroll status %d, want %d: %s", w.Code, wantStatus, w.Body.String())
		}
	}
	request(false, true, http.StatusOK)
	editEnrollmentPolicy(t, m,
		sourceChange{Path: []string{"identities", "sandbox-work"}, Delete: true},
		sourceChange{Path: []string{"identities", "device"}, Delete: true},
		sourceChange{Path: []string{"identities", "laptop"}, Value: map[string]any{
			"key": device, "routes": false, "effects": map[string]string{"pay": "off"}}})
	request(false, true, http.StatusBadRequest)
	request(true, false, http.StatusUnauthorized)
	if ids := m.live.Load().cfg.Identities; len(ids) != 1 || ids["laptop"].Routes {
		t.Fatal("ordinary or unauthenticated enrollment restored access")
	}
	request(true, true, http.StatusOK)
	checkRestored := func() {
		t.Helper()
		ids := m.live.Load().cfg.Identities
		if len(ids) != 2 || ids["sandbox-work"].Key != sandbox || ids["sandbox-work"].Routes ||
			!ids["laptop"].Routes || ids["laptop"].Effects["pay"] != "off" {
			t.Fatalf("restoration changed identity settings: %+v", ids)
		}
	}
	checkRestored()
	generation := m.store.doc.Generation
	request(true, true, http.StatusOK)
	if m.store.doc.Generation != generation {
		t.Fatal("repeated restoration rewrote policy")
	}
	m = &monitor{store: stateStore{bucket: bucket}, ownerPublicKey: owner}
	if err := m.unlock(t.Context(), secret, generation, false); err != nil {
		t.Fatal(err)
	}
	checkRestored()

	editEnrollmentPolicy(t, m,
		sourceChange{Path: []string{"identities", "sandbox-work", "key"}, Value: other},
		sourceChange{Path: []string{"identities", "laptop", "routes"}, Value: false})
	request(true, true, http.StatusBadRequest)
	if ids := m.live.Load().cfg.Identities; ids["sandbox-work"].Key != other || ids["laptop"].Routes {
		t.Fatal("conflicting restoration replaced another key or partially applied")
	}
}
