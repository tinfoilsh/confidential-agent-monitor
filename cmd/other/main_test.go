package main

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"io"
	"net"
	"sync/atomic"
	"testing"
	"time"

	cedar "github.com/cedar-policy/cedar-go"
	"github.com/tinfoilsh/confidential-agent-monitor/core/facts"
	"golang.org/x/crypto/ssh"
)

func TestNativeCedarDecisions(t *testing.T) {
	policy := `permit(principal == User::"alice", action == Action::"connect", resource == Service::"database");`
	for _, test := range []struct {
		name, principal, resource, extra string
		allow                            bool
	}{
		{"allow", "alice", "database", "", true},
		{"deny principal", "bob", "database", "", false},
		{"deny resource", "alice", "other", "", false},
		{"forbid wins", "alice", "database", `forbid(principal, action, resource);`, false},
		{"diagnostic fails closed", "alice", "database", `permit(principal, action, resource) when { context.missing };`, false},
	} {
		t.Run(test.name, func(t *testing.T) {
			policies, err := cedar.NewPolicySetFromBytes("test.cedar", []byte(policy+test.extra))
			if err != nil {
				t.Fatal(err)
			}
			err = evaluateCedar(context.Background(), policies, facts.Principal{Name: test.principal}, test.resource)
			if (err == nil) != test.allow {
				t.Fatalf("allow=%v, error=%v", test.allow, err)
			}
		})
	}
	policies, err := cedar.NewPolicySetFromBytes("test.cedar", []byte(policy))
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := evaluateCedar(ctx, policies, facts.Principal{Name: "alice"}, "database"); !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled evaluation: %v", err)
	}
}

func TestStaticSSHAndCedarGateTCP(t *testing.T) {
	signer := func() ssh.Signer {
		_, key, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		value, err := ssh.NewSignerFromKey(key)
		if err != nil {
			t.Fatal(err)
		}
		return value
	}
	host, alice, bob := signer(), signer(), signer()
	upstream, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer upstream.Close()
	var accepted atomic.Int32
	go func() {
		for {
			conn, err := upstream.Accept()
			if err != nil {
				return
			}
			accepted.Add(1)
			go func() { defer conn.Close(); io.Copy(conn, conn) }()
		}
	}()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- serveStatic(ctx, listener, host, alice.PublicKey(), upstream.Addr().String()) }()
	connect := func(key ssh.Signer) (*ssh.Client, error) {
		return ssh.Dial("tcp", listener.Addr().String(), &ssh.ClientConfig{User: "ignored-by-static-list", Auth: []ssh.AuthMethod{ssh.PublicKeys(key)}, HostKeyCallback: ssh.FixedHostKey(host.PublicKey()), Timeout: time.Second})
	}
	if client, err := connect(bob); err == nil {
		client.Close()
		t.Fatal("unregistered key authenticated")
	}
	client, err := connect(alice)
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	conn, err := client.Dial("tcp", upstream.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	exchange := make(chan error, 1)
	go func() {
		if _, err := conn.Write([]byte("captured-input")); err != nil {
			exchange <- err
			return
		}
		buf := make([]byte, len("captured-input"))
		_, err := io.ReadFull(conn, buf)
		if err == nil && string(buf) != "captured-input" {
			err = errors.New("forwarded input changed")
		}
		exchange <- err
	}()
	select {
	case err := <-exchange:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("admitted TCP request did not complete")
	}
	if other, err := client.Dial("tcp", "unauthorized.invalid:5432"); err == nil {
		other.Close()
		t.Fatal("unselected destination was forwarded")
	}
	if accepted.Load() != 1 {
		t.Fatalf("upstream connections=%d", accepted.Load())
	}
	conn.Close()
	client.Close()
	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("composition did not retire its streams")
	}
}
