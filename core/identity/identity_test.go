package identity_test

import (
	"context"
	"testing"
	"time"

	"github.com/tinfoilsh/confidential-agent-monitor/core/facts"
	"github.com/tinfoilsh/confidential-agent-monitor/core/identity"
)

func TestRegistryConflictsExpiryAndRemoval(t *testing.T) {
	var r identity.Registry
	alice, bob := facts.Principal{Name: "alice"}, facts.Principal{Name: "bob", Groups: []string{"ops"}}
	if _, err := r.Register("declared", alice, true); err != nil {
		t.Fatal(err)
	}
	if _, err := r.Register("cert", alice, false); err == nil {
		t.Fatal("a certificate took a declared identity's name")
	}
	expire, err := r.Register("cert", bob, false)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := r.Register("cert", facts.Principal{Name: "carol"}, false); err == nil {
		t.Fatal("one key was certified as two identities")
	}
	held, release, ok := r.Hold(context.Background(), "cert")
	if !ok {
		t.Fatal("registered key cannot hold")
	}
	defer release()
	renewed, err := r.Register("cert", bob, false)
	if err != nil {
		t.Fatal(err)
	}
	expire()
	if p, ok := r.Lookup("cert"); !ok || p.Key != "cert" || held.Err() != nil {
		t.Fatal("an expiry the renewal replaced removed the key")
	}
	renewed()
	if _, ok := r.Lookup("cert"); ok || !ended(held) {
		t.Fatal("expired key still registered or held")
	}

	if _, err := r.Register("shared", bob, false); err != nil {
		t.Fatal(err)
	}
	shared, release, _ := r.Hold(context.Background(), "shared")
	defer release()
	if _, err := r.Register("owned", bob, true); err != nil {
		t.Fatal(err)
	}
	if _, ok := r.Lookup("shared"); ok || !ended(shared) {
		t.Fatal("declaring a name left another key certified as it")
	}

	declared, release, _ := r.Hold(context.Background(), "declared")
	defer release()
	r.Unregister("declared")
	if _, _, ok := r.Hold(context.Background(), "declared"); ok || !ended(declared) {
		t.Fatal("removed identity still holds")
	}
}

// ended waits for the asynchronous end of a hold.
func ended(ctx context.Context) bool {
	select {
	case <-ctx.Done():
		return true
	case <-time.After(time.Second):
		return false
	}
}
