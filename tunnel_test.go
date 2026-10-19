package main

import (
	"bytes"
	"crypto/ed25519"
	"testing"

	"gocloud.dev/blob/memblob"
	"golang.org/x/crypto/ssh"
)

type enrollmentMetadata struct {
	ssh.ConnMetadata
	user string
}

func (m enrollmentMetadata) User() string { return m.user }

func TestSSHSetupRequiresEnrolledSandboxWithoutChangingPolicy(t *testing.T) {
	bucket := memblob.OpenBucket(nil)
	t.Cleanup(func() { bucket.Close() })
	m := &monitor{store: stateStore{bucket: bucket}}
	if err := m.unlock(t.Context(), bytes.Repeat([]byte{42}, 32), 0, true); err != nil {
		t.Fatal(err)
	}
	agent, err := ssh.NewPublicKey(ed25519.NewKeyFromSeed(bytes.Repeat([]byte{1}, 32)).Public())
	if err != nil {
		t.Fatal(err)
	}
	device, err := ssh.NewPublicKey(ed25519.NewKeyFromSeed(bytes.Repeat([]byte{2}, 32)).Public())
	if err != nil {
		t.Fatal(err)
	}
	fingerprint := ssh.FingerprintSHA256(agent)
	check := func(user string, allowed bool) {
		t.Helper()
		before, err := bucket.ReadAll(t.Context(), stateObject)
		if err != nil {
			t.Fatal(err)
		}
		live, generation := m.live.Load(), m.store.doc.Generation
		permissions, err := m.authorized(enrollmentMetadata{user: user}, device)
		if (err == nil) != allowed {
			t.Fatalf("authorization for %q: %v, want allowed=%v", user, err, allowed)
		}
		if allowed && permissions.Extensions[fingerprintExtension] != ssh.FingerprintSHA256(device) {
			t.Fatal("setup replaced the authenticated device identity")
		}
		after, err := bucket.ReadAll(t.Context(), stateObject)
		if err != nil || !bytes.Equal(before, after) || m.live.Load() != live || m.store.doc.Generation != generation {
			t.Fatalf("authentication changed policy or encrypted storage: %v", err)
		}
	}
	check("sandbox-v2:instance", true)
	check("device", true)
	check(sandboxUserPrefix, false)
	check(sandboxUserPrefix+fingerprint, false)

	editPolicyForTest(t, m, sourceChange{Path: []string{"identities", "sandbox-work"}, Value: map[string]any{"key": string(ssh.MarshalAuthorizedKey(agent))}})
	check(sandboxUserPrefix+fingerprint, true)
	editPolicyForTest(t, m, sourceChange{Path: []string{"identities", "sandbox-work"}, Delete: true})
	if !m.store.doc.Enrolled[fingerprint] {
		t.Fatal("revoked key was not remembered")
	}
	check(sandboxUserPrefix+fingerprint, false)
}
