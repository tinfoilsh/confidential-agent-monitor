package session

import (
	"cmp"
	"fmt"
	"io"
	"log"
	"net"
	"slices"
	"strconv"
	"strings"
	"sync"

	"golang.org/x/crypto/ssh"
	"mvdan.cc/sh/v3/expand"
	"mvdan.cc/sh/v3/syntax"

	"github.com/tinfoilsh/monitor/connector"
)

const (
	channelSession   = "session"
	sshPort          = 22
	requestExec      = "exec"
	requestSubsystem = "subsystem"
	requestEnv       = "env"
	requestPty       = "pty-req"
)

var refusedRequests = []string{"auth-agent-req@openssh.com", "x11-req"}

type SSH struct {
	Host    string `json:"host"`
	Port    int    `json:"port"`
	User    string `json:"user"`
	Key     string `json:"key"`
	HostKey string `json:"host_key"`
}

func (t *SSH) dial(d *net.Dialer) (*ssh.Client, error) {
	hostKey, _, _, _, err := ssh.ParseAuthorizedKey([]byte(t.HostKey))
	if err != nil {
		return nil, fmt.Errorf("host_key: %w", err)
	}
	signer, err := ssh.ParsePrivateKey([]byte(t.Key))
	if err != nil {
		return nil, err
	}
	hostKeyAlgorithms := []string{hostKey.Type()}
	if hostKey.Type() == ssh.KeyAlgoRSA {
		// An RSA key can sign with SHA-2 even though its key format is ssh-rsa.
		hostKeyAlgorithms = []string{ssh.KeyAlgoRSASHA512, ssh.KeyAlgoRSASHA256, ssh.KeyAlgoRSA}
	}
	addr := net.JoinHostPort(t.Host, strconv.Itoa(cmp.Or(t.Port, sshPort)))
	conn, err := d.Dial("tcp", addr)
	if err != nil {
		return nil, err
	}
	c, chans, reqs, err := ssh.NewClientConn(conn, addr, &ssh.ClientConfig{
		User:              t.User,
		Auth:              []ssh.AuthMethod{ssh.PublicKeys(signer)},
		HostKeyCallback:   ssh.FixedHostKey(hostKey),
		HostKeyAlgorithms: hostKeyAlgorithms,
	})
	if err != nil {
		conn.Close()
		return nil, err
	}
	return ssh.NewClient(c, chans, reqs), nil
}

func (t *SSH) Serve(s *connector.Stream) {
	defer s.Close()
	inner, chans, reqs, err := innerSSH(s)
	if err != nil {
		return
	}
	defer inner.Close()
	go ssh.DiscardRequests(reqs)
	up, err := t.dial(s.Dialer)
	if err != nil {
		log.Printf("%s: %v", t.Host, err)
		return
	}
	defer up.Close()
	go func() {
		up.Wait()
		inner.Close()
	}()
	check := func(r *ssh.Request) error { return s.Gate(eventForSSH(r)) }
	for nc := range chans {
		go relayChannel(up, nc, check)
	}
}

func relayChannel(up *ssh.Client, nc ssh.NewChannel, check func(*ssh.Request) error) {
	if nc.ChannelType() != channelSession {
		nc.Reject(ssh.Prohibited, "only session channels are relayed")
		return
	}
	upCh, upReqs, err := up.OpenChannel(channelSession, nc.ExtraData())
	if err != nil {
		nc.Reject(ssh.ConnectionFailed, err.Error())
		return
	}
	defer upCh.Close()
	ch, reqs, err := nc.Accept()
	if err != nil {
		return
	}
	defer ch.Close()
	go func() {
		if _, err := io.Copy(upCh, ch); err == nil {
			upCh.CloseWrite()
		}
	}()
	go func() {
		forwardRequests(upCh, reqs, check)
		upCh.Close()
	}()
	var replies, output sync.WaitGroup
	replies.Go(func() { forwardRequests(ch, upReqs, nil) })
	output.Go(func() { io.Copy(ch, upCh) })
	output.Go(func() { io.Copy(ch.Stderr(), upCh.Stderr()) })
	// EOF ends extended data too, so it waits for stderr as well as stdout.
	output.Wait()
	ch.CloseWrite()
	replies.Wait()
}

func forwardRequests(dst ssh.Channel, reqs <-chan *ssh.Request, check func(*ssh.Request) error) {
	for r := range reqs {
		ok := false
		if !slices.Contains(refusedRequests, r.Type) && (check == nil || check(r) == nil) {
			ok, _ = dst.SendRequest(r.Type, r.WantReply, r.Payload)
		}
		if r.WantReply {
			r.Reply(ok, nil)
		}
	}
}

func eventForSSH(r *ssh.Request) connector.Event {
	layer := &connector.SSHLayer{Request: r.Type}
	e := connector.Event{SSH: layer}
	switch r.Type {
	case requestExec:
		var p struct{ Command string }
		if ssh.Unmarshal(r.Payload, &p) == nil {
			layer.Command = p.Command
			if args := argv(p.Command); args != nil {
				e.Command = &connector.ArgvLayer{Argv: args}
			}
		}
	case requestSubsystem:
		var p struct{ Name string }
		if ssh.Unmarshal(r.Payload, &p) == nil {
			layer.Subsystem = p.Name
		}
	case requestEnv:
		var p connector.SSHEnv
		if ssh.Unmarshal(r.Payload, &p) == nil {
			layer.Env = &p
		}
	case requestPty:
		var p struct {
			Term string
			Rest []byte `ssh:"rest"`
		}
		if ssh.Unmarshal(r.Payload, &p) == nil {
			layer.Term = p.Term
		}
	}
	return e
}

// argv is nil for anything but one plain command.
func argv(command string) []string {
	file, err := syntax.NewParser().Parse(strings.NewReader(command), "")
	if err != nil || len(file.Stmts) != 1 {
		return nil
	}
	stmt := file.Stmts[0]
	call, ok := stmt.Cmd.(*syntax.CallExpr)
	if !ok || stmt.Negated || stmt.Background || len(stmt.Redirs) > 0 || len(call.Assigns) > 0 {
		return nil
	}
	for _, word := range call.Args {
		if !literal(word.Parts) {
			return nil
		}
	}
	args, err := expand.Fields(nil, call.Args...)
	if err != nil {
		return nil
	}
	return args
}

func literal(parts []syntax.WordPart) bool {
	for _, part := range parts {
		switch p := part.(type) {
		case *syntax.Lit, *syntax.SglQuoted:
		case *syntax.DblQuoted:
			if !literal(p.Parts) {
				return false
			}
		default:
			return false
		}
	}
	return true
}

// NoClientAuth is safe because the tunnel already checked the client's key.
func innerSSH(s *connector.Stream) (*ssh.ServerConn, <-chan ssh.NewChannel, <-chan *ssh.Request, error) {
	cfg := &ssh.ServerConfig{NoClientAuth: true}
	cfg.AddHostKey(s.HostKey)
	return ssh.NewServerConn(s, cfg)
}
