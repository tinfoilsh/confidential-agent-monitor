package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"testing"

	"github.com/tinfoilsh/monitor/connector"
	"gocloud.dev/blob/memblob"
)

func TestUnlockPatchRestart(t *testing.T) {
	ctx := context.Background()
	store := memblob.OpenBucket(nil)
	open := func() *monitor {
		return &monitor{store: store, object: "monitor.enc", listen: "127.0.0.1:0", gateway: connector.NewListener()}
	}
	key, wrong := make([]byte, ownerKeyBytes), make([]byte, ownerKeyBytes)
	rand.Read(key)
	rand.Read(wrong)

	m := open()
	first, err := m.unlock(ctx, key, 0)
	if err != nil || first.Generation != 1 {
		t.Fatalf("first unlock: generation %d, %v", first.Generation, err)
	}
	if _, err := m.patch(ctx, []byte(`{"policies": {"bad.rego": "package sentinel\ndeny contains"}}`)); err == nil {
		t.Fatal("patch with an invalid policy was accepted")
	}
	patched, err := m.patch(ctx, []byte(`{"data": {"n": 1}}`))
	if err != nil || patched.Generation != 2 {
		t.Fatalf("patch: generation %d, %v", patched.Generation, err)
	}

	m = open()
	if _, err := m.unlock(ctx, wrong, 0); err != errOwner {
		t.Fatalf("unlock with another secret: %v", err)
	}
	if _, err := m.unlock(ctx, key, 3); err == nil {
		t.Fatal("unlock accepted state older than the requested generation")
	}
	restored, err := m.unlock(ctx, key, 2)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(restored.HostKey.PublicKey().Marshal(), first.HostKey.PublicKey().Marshal()) || !bytes.Equal(restored.Config, patched.Config) {
		t.Fatal("restart did not restore the host key and config")
	}
}
