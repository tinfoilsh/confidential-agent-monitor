package sshtransport_test

import (
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"io"
	"net"
	"sync/atomic"
	"testing"
	"time"

	"github.com/tinfoilsh/confidential-agent-monitor/core/transport/sshtransport"
	"golang.org/x/crypto/ssh"
)

type publicOnlySigner struct{ ssh.Signer }

func (s publicOnlySigner) Sign(io.Reader, []byte) (*ssh.Signature, error) {
	return nil, errors.New("no private key possession")
}
func newSigner(t *testing.T) ssh.Signer {
	t.Helper()
	_, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	signer, err := ssh.NewSignerFromKey(key)
	if err != nil {
		t.Fatal(err)
	}
	return signer
}

func TestAuthenticationSideEffectsRequireProof(t *testing.T) {
	host, key := newSigner(t), newSigner(t)
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	var probed, proved, served atomic.Int32
	done := make(chan struct{})
	go func() {
		defer close(done)
		sshtransport.Serve(listener, func() ssh.Signer { return host }, sshtransport.Limits{MaxAuthTries: 3, MaxHandshakes: 8, HandshakeTimeout: time.Second},
			func(_ ssh.ConnMetadata, offered ssh.PublicKey) (sshtransport.Session, func() error, error) {
				if ssh.FingerprintSHA256(offered) != ssh.FingerprintSHA256(key.PublicKey()) {
					return nil, nil, errors.New("unknown key")
				}
				probed.Add(1)
				return func(conn *ssh.ServerConn, _ <-chan ssh.NewChannel, _ <-chan *ssh.Request) {
						served.Add(1)
						conn.Close()
					},
					func() error { proved.Add(1); return nil }, nil
			}, func(error) {})
	}()
	connect := func(signer ssh.Signer) error {
		client, err := ssh.Dial("tcp", listener.Addr().String(), &ssh.ClientConfig{User: "fixture", Auth: []ssh.AuthMethod{ssh.PublicKeys(signer)}, HostKeyCallback: ssh.FixedHostKey(host.PublicKey()), Timeout: time.Second})
		if err == nil {
			client.Close()
		}
		return err
	}
	if err := connect(publicOnlySigner{key}); err == nil {
		t.Fatal("public-key probe authenticated without possession")
	}
	if probed.Load() == 0 {
		t.Fatal("test did not send a public-key probe")
	}
	if proved.Load() != 0 || served.Load() != 0 {
		t.Fatal("public-key probe caused an authority side effect")
	}
	if err := connect(key); err != nil {
		t.Fatal(err)
	}
	if proved.Load() != 1 {
		t.Fatalf("proved callback ran %d times", proved.Load())
	}
	listener.Close()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("transport listener did not stop")
	}
}

func TestProvedCallbackCanRefuseRegistration(t *testing.T) {
	host, key := newSigner(t), newSigner(t)
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	var served atomic.Bool
	go sshtransport.Serve(listener, func() ssh.Signer { return host }, sshtransport.Limits{MaxAuthTries: 1, MaxHandshakes: 1, HandshakeTimeout: time.Second},
		func(ssh.ConnMetadata, ssh.PublicKey) (sshtransport.Session, func() error, error) {
			return func(*ssh.ServerConn, <-chan ssh.NewChannel, <-chan *ssh.Request) { served.Store(true) }, func() error { return errors.New("registration conflict") }, nil
		}, func(error) {})
	client, err := ssh.Dial("tcp", listener.Addr().String(), &ssh.ClientConfig{User: "fixture", Auth: []ssh.AuthMethod{ssh.PublicKeys(key)}, HostKeyCallback: ssh.FixedHostKey(host.PublicKey()), Timeout: time.Second})
	if err == nil {
		client.Close()
		t.Error("failed registration authenticated")
	}
	if served.Load() {
		t.Error("failed registration entered session")
	}
}
