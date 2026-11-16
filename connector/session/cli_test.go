package session_test

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"net"
	"os/exec"
	"sync/atomic"
	"testing"
	"time"

	"github.com/tinfoilsh/confidential-agent-monitor/connector/session"
	"github.com/tinfoilsh/confidential-agent-monitor/core/facts"
	"golang.org/x/crypto/ssh"
)

func TestCLIUsesSuppliedServerConfigAndName(t *testing.T) {
	echo, err := exec.LookPath("echo")
	if err != nil {
		t.Skip(err)
	}
	path, _ := json.Marshal(echo)
	cli, err := session.ParseCLI(json.RawMessage(`{"path":` + string(path) + `}`))
	if err != nil {
		t.Fatal(err)
	}
	_, private, _ := ed25519.GenerateKey(nil)
	host, _ := ssh.NewSignerFromKey(private)
	config := &ssh.ServerConfig{PasswordCallback: func(_ ssh.ConnMetadata, password []byte) (*ssh.Permissions, error) {
		if string(password) != "right" {
			return nil, errors.New("wrong password")
		}
		return nil, nil
	}}
	config.AddHostKey(host)
	var deny atomic.Bool
	serve := cli.Handler(config, func(context.Context, string) (string, error) { return "", nil }, session.Limits{}, "custom-cli")
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	go func() {
		for {
			stream, err := listener.Accept()
			if err != nil {
				return
			}
			stream.SetDeadline(time.Now().Add(10 * time.Second))
			go serve(t.Context(), stream, "", "cli.test", 22, func(context.Context, facts.Event) error {
				if deny.Load() {
					return errors.New("denied for test")
				}
				return nil
			})
		}
	}()
	connect := func(password string) (*ssh.Client, error) {
		agent, err := net.Dial("tcp", listener.Addr().String())
		if err != nil {
			t.Fatal(err)
		}
		agent.SetDeadline(time.Now().Add(10 * time.Second))
		c, chans, reqs, err := ssh.NewClientConn(agent, "cli.test:22", &ssh.ClientConfig{
			User: "agent", Auth: []ssh.AuthMethod{ssh.Password(password)}, HostKeyCallback: ssh.FixedHostKey(host.PublicKey()),
		})
		if err != nil {
			agent.Close()
			return nil, err
		}
		return ssh.NewClient(c, chans, reqs), nil
	}
	run := func(client *ssh.Client) (stdout, stderr string, err error) {
		s, err := client.NewSession()
		if err != nil {
			t.Fatal(err)
		}
		defer s.Close()
		var out, errOut bytes.Buffer
		s.Stdout, s.Stderr = &out, &errOut
		err = s.Run("echo hi")
		return out.String(), errOut.String(), err
	}

	if _, err := connect("wrong"); err == nil {
		t.Fatal("the inner handshake ignored the supplied config's authentication")
	}
	client, err := connect("right")
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	deny.Store(true)
	var exit *ssh.ExitError
	if stdout, stderr, err := run(client); stdout != "" || stderr != "custom-cli: denied for test\n" || !errors.As(err, &exit) || exit.ExitStatus() != 126 {
		t.Fatalf("denied command: stdout %q stderr %q err %v", stdout, stderr, err)
	}
	deny.Store(false)
	if stdout, _, err := run(client); stdout != "hi\n" || err != nil {
		t.Fatalf("admitted command: stdout %q err %v", stdout, err)
	}
}
