package session

import (
	"cmp"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"slices"
	"strconv"
	"strings"
	"sync"

	"github.com/tinfoilsh/monitor/connector"
	"github.com/tinfoilsh/monitor/facts"
	"golang.org/x/crypto/ssh"
	"mvdan.cc/sh/v3/expand"
	"mvdan.cc/sh/v3/syntax"
)

var SSHDefinition = connector.Definition{HostKey: true, NewConfig: func() connector.Server { return new(SSH) }, Requests: []connector.Request{new(SSHRequest)}}

const (
	channelSession = "session"
	sshPort        = 22
	requestExec    = "exec"
)

var refusedRequests = []string{"auth-agent-req@openssh.com", "x11-req"}

type SSH struct {
	connector.SecretConfig
	Host    string `json:"host"`
	Port    int    `json:"port"`
	User    string `json:"user"`
	HostKey string `json:"host_key"`
}

func (t *SSH) dial(s *connector.Stream, e *connector.Env) (*ssh.Client, error) {
	hostKey, _, _, _, err := ssh.ParseAuthorizedKey([]byte(t.HostKey))
	if err != nil {
		return nil, fmt.Errorf("host_key: %w", err)
	}
	secret, err := t.Secret(s.Context, "key")
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
	conn, err := e.Dialer.DialContext(s.Context, "tcp", addr)
	if err != nil {
		return nil, err
	}
	s.Interrupt(conn)
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

func (t *SSH) Serve(s *connector.Stream, e *connector.Env) {
	t.serve(s, e, func(up *ssh.Client, nc ssh.NewChannel) {
		relayChannel(up, nc, func(r *ssh.Request) error { return s.Gate(eventForSSH(r)) })
	})
}

func (t *SSH) serve(s *connector.Stream, e *connector.Env, pump func(*ssh.Client, ssh.NewChannel)) {
	_, chans, reqs, err := innerSSH(s, e.HostKey)
	if err != nil {
		return
	}
	var workers sync.WaitGroup
	defer func() { s.Close(); workers.Wait() }()
	go ssh.DiscardRequests(reqs)
	up, err := t.dial(s, e)
	if err != nil {
		log.Printf("%s: %v", t.Host, err)
		return
	}
	defer s.Interrupt(up)()
	workers.Go(func() {
		up.Wait()
		s.Close()
	})
	for nc := range chans {
		workers.Go(func() { pump(up, nc) })
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

func eventForSSH(r *ssh.Request) *SSHRequest {
	layer := &facts.SSH{Request: r.Type}
	e := &SSHRequest{SSH: layer}
	switch r.Type {
	case requestExec:
		var p struct{ Command string }
		if ssh.Unmarshal(r.Payload, &p) == nil {
			layer.Command = p.Command
			if args := argv(p.Command); args != nil {
				e.Command = &facts.Command{Argv: args}
			}
		}
	case "subsystem":
		var p struct{ Name string }
		if ssh.Unmarshal(r.Payload, &p) == nil {
			layer.Subsystem = p.Name
		}
	case "env":
		var p facts.SSHEnv
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
func innerSSH(s *connector.Stream, hostKey ssh.Signer) (*ssh.ServerConn, <-chan ssh.NewChannel, <-chan *ssh.Request, error) {
	if hostKey == nil {
		return nil, nil, nil, errors.New("SSH host identity is unavailable")
	}
	cfg := &ssh.ServerConfig{NoClientAuth: true}
	cfg.AddHostKey(hostKey)
	return ssh.NewServerConn(s, cfg)
}

type SSHRequest facts.Details

func (r *SSHRequest) Describe(c connector.Context) (facts.Facts, error) {
	details := facts.Details(*r)
	v := r.SSH
	if v == nil {
		return facts.Facts{Details: details}, nil
	}
	action := map[string]string{"pty-req": "session", "env": "session", "window-change": "session", "signal": "session", "break": "session", "exec": "run", "shell": "shell"}[v.Request]
	if v.Request == "subsystem" && v.Subsystem == "sftp" {
		action = "files"
	}
	scope := map[string]any{}
	if v.Command != "" {
		scope["command"] = v.Command
	}
	host := ""
	if config, ok := c.Config.(*SSH); ok {
		host = config.Host
	}
	title := map[string]string{"run": "Run " + v.Command + " on " + host, "shell": "Open a shell on " + host, "files": "Transfer files on " + host}[action]
	if title == "" {
		title = "SSH " + v.Request
	}
	op := &facts.Operation{Action: action}
	return facts.Facts{Operation: op, Title: title, Parameters: scope, Details: details}, nil
}
