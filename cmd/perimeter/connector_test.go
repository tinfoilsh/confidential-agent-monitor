package main

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net"
	"net/textproto"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/tinfoilsh/confidential-agent-monitor/connector/worker"
	"github.com/tinfoilsh/confidential-agent-monitor/core"
	"github.com/tinfoilsh/confidential-agent-monitor/core/facts"
	"golang.org/x/crypto/ssh"
)

func connectorStream(t *testing.T, protocol, config string, host worker.Host, gate core.Gate) net.Conn {
	t.Helper()
	p, err := parseConnection(ConnectionSpec{Protocol: protocol, Config: json.RawMessage(config)})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(t.Context())
	instance, err := p.open(ctx, host)
	if err != nil {
		cancel()
		t.Fatal(err)
	}
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		cancel()
		t.Fatal(err)
	}
	done := make(chan struct{})
	go func() {
		defer close(done)
		conn, err := listener.Accept()
		if err == nil {
			defer conn.Close()
			stop := context.AfterFunc(ctx, func() { conn.Close() })
			defer stop()
			instance.Serve(ctx, conn, "fixture", "fixture.example", 0, gate)
		}
	}()
	t.Cleanup(func() {
		cancel()
		listener.Close()
		select {
		case <-done:
		case <-time.After(5 * time.Second):
			t.Error("connector did not release its stream")
		}
		if instance.Close != nil {
			instance.Close()
		}
	})
	conn, err := net.Dial("tcp", listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { conn.Close() })
	conn.SetDeadline(time.Now().Add(5 * time.Second))
	return conn
}

func TestSMTPUsesAdmittedStreamAuthenticationAndStillGatesMail(t *testing.T) {
	var effects, gates atomic.Int32
	host := worker.Host{
		TLS: func(context.Context, string) *tls.Config { return nil },
		Dial: func(context.Context, string, string) (net.Conn, error) {
			effects.Add(1)
			return nil, errors.New("unexpected upstream dial")
		},
		Secret: func(context.Context, string) (string, error) { effects.Add(1); return "", nil },
	}
	conn := connectorStream(t, "smtp", `{"url":"smtp://mail.example","user":"sender"}`, host, func(_ context.Context, event facts.Event) error {
		if _, err := event.Decode(); err != nil {
			t.Error(err)
		}
		gates.Add(1)
		return errors.New("fixture refused")
	})
	client := textproto.NewConn(conn)
	_, greeting, err := client.ReadResponse(220)
	if err != nil || !strings.Contains(greeting, protocolIdentity) {
		t.Fatalf("greeting %q: %v", greeting, err)
	}
	for _, cmd := range []struct {
		line string
		code int
	}{
		{"EHLO agent.example", 250},
		{"AUTH PLAIN " + base64.StdEncoding.EncodeToString([]byte("\x00agent\x00unused")), 235},
		{"MAIL FROM:<sender@example.com>", 250},
		{"RCPT TO:<target@example.com>", 250},
		{"DATA", 354},
	} {
		if err := client.PrintfLine("%s", cmd.line); err != nil {
			t.Fatal(err)
		}
		if _, _, err := client.ReadResponse(cmd.code); err != nil {
			t.Fatal(err)
		}
	}
	if err := client.PrintfLine("Subject: captured\r\n\r\nbody\r\n."); err != nil {
		t.Fatal(err)
	}
	code, _, err := client.ReadResponse(0)
	if err != nil || code < 400 || gates.Load() != 1 || effects.Load() != 0 {
		t.Fatalf("code %d gates %d upstream uses %d: %v", code, gates.Load(), effects.Load(), err)
	}
}

func TestCLIAcceptsAdmittedSSHAndGatesExecution(t *testing.T) {
	_, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	signer, err := ssh.NewSignerFromKey(key)
	if err != nil {
		t.Fatal(err)
	}
	var gates, secrets atomic.Int32
	conn := connectorStream(t, "cli", `{"path":"unexpected-executable","credentials":["token"]}`, worker.Host{
		HostKey: signer, Secret: func(context.Context, string) (string, error) { secrets.Add(1); return "", nil },
	}, func(context.Context, facts.Event) error { gates.Add(1); return errors.New("fixture refused") })
	clientConn, channels, requests, err := ssh.NewClientConn(conn, "fixture.example", &ssh.ClientConfig{User: "agent", HostKeyCallback: ssh.FixedHostKey(signer.PublicKey())})
	if err != nil {
		t.Fatal(err)
	}
	client := ssh.NewClient(clientConn, channels, requests)
	defer client.Close()
	session, err := client.NewSession()
	if err != nil {
		t.Fatal(err)
	}
	defer session.Close()
	output, err := session.CombinedOutput("fixture argument")
	var refused *ssh.ExitError
	if !errors.As(err, &refused) || refused.ExitStatus() != 126 || string(output) != protocolIdentity+": fixture refused\n" || gates.Load() != 1 || secrets.Load() != 0 {
		t.Fatalf("output %q gates %d secrets %d: %v", output, gates.Load(), secrets.Load(), err)
	}
}
