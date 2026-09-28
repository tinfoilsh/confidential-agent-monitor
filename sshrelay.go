package main

import (
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"slices"
	"strconv"
	"sync"

	"golang.org/x/crypto/ssh"
)

const (
	channelSession = "session"
	sshPort        = 22
)

var refusedRequests = []string{"auth-agent-req@openssh.com", "x11-req"}

type sshTarget struct {
	Host    string `yaml:"host"`
	Port    int    `yaml:"port"`
	User    string `yaml:"user"`
	Key     string `yaml:"key"`
	HostKey string `yaml:"host_key"`
}

func (t *sshTarget) dial() (*ssh.Client, error) {
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

// relaySSH serves the channel as an SSH server that asks for no credential and relays each session upstream.
func (m *monitor) relaySSH(conn net.Conn, t *sshTarget) {
	defer conn.Close()
	inner, chans, reqs, err := ssh.NewServerConn(conn, m.inner)
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
	for nc := range chans {
		go relayChannel(up, nc)
	}
}

func relayChannel(up *ssh.Client, nc ssh.NewChannel) {
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
		forwardRequests(upCh, reqs)
		upCh.Close()
	}()
	var replies, output sync.WaitGroup
	replies.Go(func() { forwardRequests(ch, upReqs) })
	output.Go(func() { io.Copy(ch, upCh) })
	output.Go(func() { io.Copy(ch.Stderr(), upCh.Stderr()) })
	// EOF ends extended data too, so it waits for stderr as well as stdout.
	output.Wait()
	ch.CloseWrite()
	replies.Wait()
}

func forwardRequests(dst ssh.Channel, reqs <-chan *ssh.Request) {
	for r := range reqs {
		ok := false
		if !slices.Contains(refusedRequests, r.Type) {
			ok, _ = dst.SendRequest(r.Type, r.WantReply, r.Payload)
		}
		if r.WantReply {
			r.Reply(ok, nil)
		}
	}
}
