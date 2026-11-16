package session

import (
	"cmp"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"slices"
	"strconv"
	"strings"
	"sync"

	"github.com/tinfoilsh/confidential-agent-monitor/core/facts"
	"golang.org/x/crypto/ssh"
	"mvdan.cc/sh/v3/expand"
	"mvdan.cc/sh/v3/syntax"
)

const (
	channelSession = "session"
	sshPort        = 22
	requestExec    = "exec"
)

var refusedRequests = []string{"auth-agent-req@openssh.com", "x11-req"}

// SSH relays an agent's sessions to one server, authenticated with the "key" credential and
// pinned to its host key.
type SSH struct {
	Host    string `json:"host"`
	Port    int    `json:"port"`
	User    string `json:"user"`
	HostKey string `json:"host_key"`
}

func ParseSSH(config json.RawMessage) (*SSH, error) {
	t := new(SSH)
	return t, facts.DecodeNumbers(config, t)
}

func (t *SSH) Hosts() []string { return []string{t.Host} }

// stream is one agent connection, which the host key terminates.
type stream struct {
	ctx    context.Context
	cancel context.CancelFunc
	conn   net.Conn
	gate   func(context.Context, facts.Event) error
}

func newStream(ctx context.Context, conn net.Conn, gate func(context.Context, facts.Event) error) *stream {
	ctx, cancel := context.WithCancel(ctx)
	return &stream{ctx, cancel, conn, gate}
}

func (s *stream) close() { s.cancel(); s.conn.Close() }

// upstream dials the server with key through dial.
type upstream struct {
	dial func(context.Context, string, string) (net.Conn, error)
	key  func(context.Context) (string, error)
}

func (t *SSH) dial(s *stream, u upstream) (*ssh.Client, error) {
	hostKey, _, _, _, err := ssh.ParseAuthorizedKey([]byte(t.HostKey))
	if err != nil {
		return nil, fmt.Errorf("host_key: %w", err)
	}
	secret, err := u.key(s.ctx)
	if err != nil {
		return nil, err
	}
	signer, err := ssh.ParsePrivateKey([]byte(secret))
	if err != nil {
		return nil, err
	}
	hostKeyAlgorithms := []string{hostKey.Type()}
	if hostKey.Type() == ssh.KeyAlgoRSA {
		// An RSA key can sign with SHA-2 even though its key format is ssh-rsa.
		hostKeyAlgorithms = []string{ssh.KeyAlgoRSASHA512, ssh.KeyAlgoRSASHA256, ssh.KeyAlgoRSA}
	}
	addr := net.JoinHostPort(t.Host, strconv.Itoa(cmp.Or(t.Port, sshPort)))
	conn, err := u.dial(s.ctx, "tcp", addr)
	if err != nil {
		return nil, err
	}
	context.AfterFunc(s.ctx, func() { conn.Close() })
	c, chans, reqs, err := ssh.NewClientConn(conn, addr, &ssh.ClientConfig{
		User:              t.User,
		Auth:              []ssh.AuthMethod{ssh.PublicKeys(signer)},
		HostKeyCallback:   ssh.FixedHostKey(hostKey),
		HostKeyAlgorithms: hostKeyAlgorithms,
	})
	if err != nil {
		return nil, err
	}
	return ssh.NewClient(c, chans, reqs), nil
}

// Handler serves agent sessions under host, the SSH host identity they reach, and relays
// each admitted request to the server it dials with key.
func (t *SSH) Handler(dial func(ctx context.Context, network, address string) (net.Conn, error), host ssh.Signer, key func(context.Context) (string, error)) func(context.Context, net.Conn, string, string, uint32, func(context.Context, facts.Event) error) {
	return func(ctx context.Context, conn net.Conn, _, _ string, _ uint32, gate func(context.Context, facts.Event) error) {
		s := newStream(ctx, conn, gate)
		t.serve(s, host, upstream{dial, key}, func(up *ssh.Client, nc ssh.NewChannel) {
			relayChannel(up, nc, func(r *ssh.Request) error { return s.gate(s.ctx, facts.Capture(eventForSSH(r).Describe(t.Host), nil)) })
		})
	}
}

func (t *SSH) serve(s *stream, host ssh.Signer, u upstream, pump func(*ssh.Client, ssh.NewChannel)) {
	serveSessions(s, host, func(workers *sync.WaitGroup) func(ssh.NewChannel) {
		up, err := t.dial(s, u)
		if err != nil {
			log.Printf("%s: %v", t.Host, err)
			return nil
		}
		workers.Go(func() {
			up.Wait()
			s.close()
		})
		return func(nc ssh.NewChannel) { pump(up, nc) }
	})
}

func serveSessions(s *stream, hostKey ssh.Signer, start func(*sync.WaitGroup) func(ssh.NewChannel)) {
	defer s.cancel()
	chans, err := innerSSH(s.conn, hostKey)
	if err != nil {
		return
	}
	var workers sync.WaitGroup
	defer func() { s.close(); workers.Wait() }()
	serve := start(&workers)
	if serve == nil {
		return
	}
	for nc := range chans {
		if nc.ChannelType() != channelSession {
			nc.Reject(ssh.Prohibited, "only session channels are supported")
			continue
		}
		workers.Go(func() { serve(nc) })
	}
}

func relayChannel(up *ssh.Client, nc ssh.NewChannel, check func(*ssh.Request) error) {
	upCh, upReqs, err := up.OpenChannel(channelSession, nc.ExtraData())
	if err != nil {
		nc.Reject(ssh.ConnectionFailed, err.Error())
		return
	}

	ch, reqs, err := nc.Accept()
	if err != nil {
		upCh.Close()
		return
	}
	var workers sync.WaitGroup
	defer workers.Wait()
	defer upCh.Close()
	defer ch.Close()
	workers.Go(func() {
		if _, err := io.Copy(upCh, ch); err == nil {
			upCh.CloseWrite()
		}
	})
	workers.Go(func() {
		forwardRequests(upCh, reqs, check)
		upCh.Close()
	})
	var replies, output sync.WaitGroup
	replies.Go(func() { forwardRequests(ch, upReqs, nil) })
	output.Go(func() { io.Copy(ch, upCh) })
	io.Copy(ch.Stderr(), upCh.Stderr())
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

func eventForSSH(r *ssh.Request) *SSHRequest {
	layer := &SSHFacts{Request: r.Type}
	e := &SSHRequest{SSH: layer}
	switch r.Type {
	case requestExec:
		var p struct{ Command string }
		if ssh.Unmarshal(r.Payload, &p) == nil {
			layer.Command = p.Command
			if args := argv(p.Command); args != nil {
				e.Command = &CommandFacts{Argv: args}
			}
		}
	case "subsystem":
		var p struct{ Name string }
		if ssh.Unmarshal(r.Payload, &p) == nil {
			layer.Subsystem = p.Name
		}
	case "env":
		var p SSHEnvFacts
		if ssh.Unmarshal(r.Payload, &p) == nil {
			layer.Env = &p
		}
	case "pty-req":
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
func innerSSH(s net.Conn, hostKey ssh.Signer) (<-chan ssh.NewChannel, error) {
	if hostKey == nil {
		return nil, errors.New("SSH host identity is unavailable")
	}
	cfg := &ssh.ServerConfig{NoClientAuth: true}
	cfg.AddHostKey(hostKey)
	_, chans, reqs, err := ssh.NewServerConn(s, cfg)
	if err != nil {
		return nil, err
	}
	go ssh.DiscardRequests(reqs)
	return chans, nil
}

type SSHRequest Details

func (r *SSHRequest) Describe(host string) facts.Observation {
	v := r.SSH
	action := map[string]string{"pty-req": "session", "env": "session", "window-change": "session", "signal": "session", "break": "session", "exec": "run", "shell": "shell"}[v.Request]
	if v.Request == "subsystem" && v.Subsystem == "sftp" {
		action = "files"
	}
	scope := map[string]any{}
	if v.Command != "" {
		scope["command"] = v.Command
	}
	title := map[string]string{"run": "Run " + v.Command + " on " + host, "shell": "Open a shell on " + host, "files": "Transfer files on " + host}[action]
	if title == "" {
		title = "SSH " + v.Request
	}
	op := &facts.Operation{Action: action}
	return facts.Observation{Operation: op, Title: title, Parameters: scope, Details: Details(*r)}
}
