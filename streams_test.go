package main

import (
	"errors"
	"fmt"
	"io"
	"net"
	"testing"
	"time"

	"gocloud.dev/blob/memblob"
	"golang.org/x/crypto/ssh"
)

func TestAccountPermissionChangesRetireStreams(t *testing.T) {
	for _, tc := range []struct {
		name, patch string
		retire      bool
	}{
		{"revoke", `{"identities":{"bob":{"accounts":{"web":{"level":"off"}}}}}`, true},
		{"reduce", `{"identities":{"bob":{"accounts":{"web":{"level":"read"}}}}}`, true},
		{"action override", `{"identities":{"bob":{"accounts":{"web":{"actions":{"browse":"off"}}}}}}`, true},
		{"remove account access", `{"identities":{"bob":{"accounts":{"web":null}}}}`, true},
		{"unchanged permissions", `{"identities":{"bob":{"accounts":{"web":{"level":"allow","actions":{}}}}}}`, false},
		{"unrelated edit", `{"data":{"note":"updated"}}`, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newMessageFixture(t, messageLimit{Audience: "me", Trust: "untrusted"})
			stream := trackedTestStream(t, f, "bob")
			other := trackedTestStream(t, f, "alice")
			if err := f.patch(t, tc.patch); err != nil {
				t.Fatal(err)
			}
			if closed := stream.Context.Err() != nil; closed != tc.retire {
				t.Fatalf("stream closed = %v, want %v", closed, tc.retire)
			}
			if other.Context.Err() != nil {
				t.Fatal("permission edit closed another agent's stream")
			}
		})
	}
}

func TestFailedPermissionPatchPreservesStreams(t *testing.T) {
	f := newMessageFixture(t, messageLimit{Audience: "me", Trust: "untrusted"})
	stream := trackedTestStream(t, f, "bob")
	working := f.m.store
	failed := memblob.OpenBucket(nil)
	failed.Close()
	f.m.store = failed
	defer func() { f.m.store = working }()
	patch := `{"identities":{"bob":{"accounts":{"web":{"level":"off"}}}}}`
	if err := f.patch(t, patch); err == nil {
		t.Fatal("permission patch succeeded despite failed persistence")
	}
	if stream.Context.Err() != nil || f.m.live.Load().cfg.Identities["bob"].Accounts["web"].Level != "allow" {
		t.Fatal("failed patch changed live access or closed the stream")
	}
	f.m.store = working
	if err := f.patch(t, patch); err != nil {
		t.Fatal(err)
	}
	if stream.Context.Err() == nil {
		t.Fatal("persisted revocation left the stream open")
	}
}

func TestSSHAccessRevocationClosesShell(t *testing.T) {
	f := newMessageFixture(t, messageLimit{Audience: "me", Trust: "untrusted"})
	hostKey := f.m.live.Load().HostKey
	upstream := sshEchoServer(t, hostKey)
	patch := fmt.Sprintf(`{
		"allow_networks": ["127.0.0.0/8"],
		"accounts": {"shell": {
			"preset": "ssh", "contents": "anyone", "strangers": false, "sends": "anyone",
			"connections": {"": {"ssh": {"host": "127.0.0.1", "port": %d, "user": "test", "host_key": %q, "key": %q}}}
		}},
		"identities": {"bob": {"accounts": {"shell": {"level": "allow"}}}}
	}`, upstream.Port, ssh.MarshalAuthorizedKey(hostKey.PublicKey()), f.m.doc.Keys.HostKey)
	if err := f.patch(t, patch); err != nil {
		t.Fatal(err)
	}
	c := f.m.live.Load().connections["shell"]
	t.Cleanup(func() {
		c.cancel()
		select {
		case <-c.done:
		case <-time.After(3 * time.Second):
			t.Error("SSH connector did not stop")
		}
	})
	select {
	case <-c.ready:
	case <-time.After(3 * time.Second):
		t.Fatal("SSH connector did not start")
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	go f.m.serveSSH(ln)
	outer, err := ssh.Dial("tcp", ln.Addr().String(), &ssh.ClientConfig{
		User: "monitor", Auth: []ssh.AuthMethod{ssh.PublicKeys(f.keys["bob"])},
		HostKeyCallback: ssh.FixedHostKey(hostKey.PublicKey()), Timeout: 3 * time.Second,
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { outer.Close() })
	tunnel, err := outer.Dial("tcp", "shell.monitor:22")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { tunnel.Close() })
	conn, channels, requests, err := ssh.NewClientConn(tunnel, "shell.monitor:22", &ssh.ClientConfig{
		User: "test", HostKeyCallback: ssh.FixedHostKey(hostKey.PublicKey()),
	})
	if err != nil {
		t.Fatal(err)
	}
	inner := ssh.NewClient(conn, channels, requests)
	t.Cleanup(func() { inner.Close() })
	shell, err := inner.NewSession()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { shell.Close() })
	stdin, err := shell.StdinPipe()
	if err != nil {
		t.Fatal(err)
	}
	stdout, err := shell.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	if err := shell.Shell(); err != nil {
		t.Fatal(err)
	}
	echoed := make(chan error, 1)
	go func() {
		_, err := io.WriteString(stdin, "before revocation\n")
		if err == nil {
			buf := make([]byte, len("before revocation\n"))
			_, err = io.ReadFull(stdout, buf)
			if err == nil && string(buf) != "before revocation\n" {
				err = fmt.Errorf("unexpected shell output: %q", buf)
			}
		}
		echoed <- err
	}()
	select {
	case err := <-echoed:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("SSH shell did not echo input")
	}
	closed := make(chan struct{})
	go func() { shell.Wait(); close(closed) }()
	if err := f.patch(t, `{"identities":{"bob":{"accounts":{"shell":{"level":"off"}}}}}`); err != nil {
		t.Fatal(err)
	}
	select {
	case <-closed:
	case <-time.After(3 * time.Second):
		t.Fatal("revoked SSH shell remained open")
	}
	reopened, err := outer.Dial("tcp", "shell.monitor:22")
	if err == nil {
		reopened.Close()
		t.Fatal("revoked account accepted a new SSH stream")
	}
	var denied *ssh.OpenChannelError
	if !errors.As(err, &denied) || denied.Reason != ssh.Prohibited {
		t.Fatalf("reconnection failed for a reason other than revoked access: %v", err)
	}
}

// The upstream speaks SSH and echoes shell input without launching a process.
func sshEchoServer(t *testing.T, hostKey ssh.Signer) *net.TCPAddr {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		cfg := &ssh.ServerConfig{NoClientAuth: true}
		cfg.AddHostKey(hostKey)
		server, channels, requests, err := ssh.NewServerConn(conn, cfg)
		if err != nil {
			return
		}
		defer server.Close()
		go ssh.DiscardRequests(requests)
		for nc := range channels {
			ch, requests, err := nc.Accept()
			if err != nil {
				return
			}
			go func() {
				defer ch.Close()
				for req := range requests {
					req.Reply(req.Type == "shell", nil)
					if req.Type == "shell" {
						go ssh.DiscardRequests(requests)
						io.Copy(ch, ch)
						return
					}
				}
			}()
		}
	}()
	return ln.Addr().(*net.TCPAddr)
}
