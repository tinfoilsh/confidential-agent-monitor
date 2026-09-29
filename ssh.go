package main

import (
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"slices"
	"strconv"
	"strings"
	"sync"

	"golang.org/x/crypto/ssh"
	"mvdan.cc/sh/v3/expand"
	"mvdan.cc/sh/v3/syntax"
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

type sshRelay struct {
	Host    string `yaml:"host"`
	Port    int    `yaml:"port"`
	User    string `yaml:"user"`
	Key     string `yaml:"key"`
	HostKey string `yaml:"host_key"`
}

func (t *sshRelay) dial() (*ssh.Client, error) {
	hostKey, _, _, _, err := ssh.ParseAuthorizedKey([]byte(t.HostKey))
	if err != nil {
		return nil, fmt.Errorf("host_key: %w", err)
	}
	encoded, err := os.ReadFile(t.Key)
	if err != nil {
		return nil, err
	}
	signer, err := ssh.ParsePrivateKey(encoded)
	if err != nil {
		return nil, err
	}
	port := t.Port
	if port == 0 {
		port = sshPort
	}
	return ssh.Dial("tcp", net.JoinHostPort(t.Host, strconv.Itoa(port)), &ssh.ClientConfig{
		User:            t.User,
		Auth:            []ssh.AuthMethod{ssh.PublicKeys(signer)},
		HostKeyCallback: ssh.FixedHostKey(hostKey),
		Timeout:         dialTimeout,
	})
}

// serve answers as an SSH server that asks for no credential and relays each session upstream.
func (t *sshRelay) serve(cc *channelConn) {
	defer cc.Close()
	inner, chans, reqs, err := ssh.NewServerConn(cc, cc.m.inner)
	if err != nil {
		return
	}
	defer inner.Close()
	go ssh.DiscardRequests(reqs)
	up, err := t.dial()
	if err != nil {
		log.Printf("%s: %v", t.Host, err)
		return
	}
	defer up.Close()
	go func() {
		up.Wait()
		inner.Close()
	}()
	check := func(r *ssh.Request) error { return cc.gate(sshEvent(r)) }
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

// sshEvent is the ssh layer for a channel request, plus the command layer when its exec string is one plain command.
func sshEvent(r *ssh.Request) event {
	layer := &sshLayer{Request: r.Type}
	e := event{SSH: layer}
	switch r.Type {
	case requestExec:
		var p struct{ Command string }
		if ssh.Unmarshal(r.Payload, &p) == nil {
			layer.Command = p.Command
			if args := argv(p.Command); args != nil {
				e.Command = &argvLayer{Argv: args}
			}
		}
	case requestSubsystem:
		var p struct{ Name string }
		if ssh.Unmarshal(r.Payload, &p) == nil {
			layer.Subsystem = p.Name
		}
	case requestEnv:
		var p sshEnv
		if ssh.Unmarshal(r.Payload, &p) == nil {
			layer.Env = &p
		}
	case requestPty:
		var p struct {
			Term                         string
			Columns, Rows, Width, Height uint32
			Modes                        string
		}
		if ssh.Unmarshal(r.Payload, &p) == nil {
			layer.Term = p.Term
		}
	}
	return e
}

// argv is the words of exactly one plain command: no pipes, redirects, assignments, or expansions.
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
