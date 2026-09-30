package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"log"
	"net"
	"os"
	"path"
	"slices"
	"strings"
	"time"

	"github.com/open-policy-agent/opa/v1/util"
	"github.com/tinfoilsh/monitor/connector"
	"golang.org/x/crypto/ssh"
)

type tcpLayer struct {
	Host string `json:"host"`
	Port uint32 `json:"port"`
}

// input carries either the tunnel's tcp layer or a connector's layers, never both.
type input struct {
	Principal  principal `json:"principal"`
	Connection string    `json:"connection"`
	Protocol   string    `json:"protocol"`
	TCP        *tcpLayer `json:"tcp,omitempty"`
	*connector.Event
}

type principal struct {
	Key         string   `json:"key"`
	Name        string   `json:"name"`
	Connections []string `json:"connections"`
}

func (p principal) reaches(name string) bool {
	return slices.ContainsFunc(p.Connections, func(pattern string) bool {
		ok, _ := path.Match(pattern, name)
		return ok
	})
}

type principalKey struct{}

const (
	optionConnections = "connections="
	channelDirect     = "direct-tcpip"
	monitorSuffix     = ".monitor"
)

func (m *monitor) serveSSH(listen, authorizedKeys string) error {
	front := &ssh.ServerConfig{PublicKeyCallback: authorized(authorizedKeys)}
	front.AddHostKey(m.HostKey)
	ln, err := net.Listen("tcp", listen)
	if err != nil {
		return err
	}
	defer ln.Close()
	log.Printf("monitor listening on %s", ln.Addr())
	for {
		nc, err := ln.Accept()
		if err != nil {
			return err
		}
		go func() {
			conn, chans, reqs, err := ssh.NewServerConn(nc, front)
			if err != nil {
				nc.Close()
				return
			}
			defer conn.Close()
			go ssh.DiscardRequests(reqs)
			p := conn.Permissions.ExtraData[principalKey{}].(principal)
			for nc := range chans {
				go m.forward(p, nc)
			}
		}()
	}
}

func (m *monitor) forward(p principal, nc ssh.NewChannel) {
	if nc.ChannelType() != channelDirect {
		nc.Reject(ssh.Prohibited, "only direct-tcpip channels are forwarded")
		return
	}
	var target struct {
		Host string
		Port uint32
		Rest []byte `ssh:"rest"`
	}
	if err := ssh.Unmarshal(nc.ExtraData(), &target); err != nil {
		nc.Reject(ssh.ConnectionFailed, "malformed direct-tcpip request")
		return
	}
	c := m.route(p, target.Host, target.Port)
	if c == nil {
		log.Printf("%s: dropped %s:%d", p.Name, target.Host, target.Port)
		nc.Reject(ssh.Prohibited, "the monitor does not forward this target")
		return
	}
	s := &connector.Stream{Env: &m.Env, Name: c.name, Host: target.Host, Port: target.Port}
	s.Gate = func(e connector.Event) error { return m.gate(input{p, c.name, c.protocol, nil, &e}) }
	if err := m.gate(input{p, c.name, c.protocol, &tcpLayer{Host: target.Host, Port: target.Port}, nil}); err != nil {
		nc.Reject(ssh.Prohibited, err.Error())
		return
	}
	ch, reqs, err := nc.Accept()
	if err != nil {
		return
	}
	go ssh.DiscardRequests(reqs)
	s.Conn = channelConn{ch, p}
	log.Printf("%s: forwarding %s:%d", p.Name, target.Host, target.Port)
	c.connector.Serve(s)
}

// Only connections the principal reaches are routed, so their claims never tie with another principal's.
func (m *monitor) route(p principal, host string, port uint32) *connection {
	if name, ok := strings.CutSuffix(host, monitorSuffix); ok {
		c := m.connections[name]
		if c == nil || !p.reaches(name) {
			return nil
		}
		if _, ok := c.connector.(connector.Claimer); ok {
			return nil
		}
		return c
	}
	best, tied := -1, false
	var selected *connection
	for _, c := range m.connections {
		r, ok := c.connector.(connector.Claimer)
		if !ok || !p.reaches(c.name) {
			continue
		}
		score := r.Claim(host, port)
		if score < 0 {
			continue
		}
		if score > best {
			best, tied, selected = score, false, c
		} else if score == best {
			tied = true
		}
	}
	if tied {
		log.Printf("ambiguous route for %s:%d at claim %d", host, port, best)
		return nil
	}
	return selected
}

func (m *monitor) gate(in input) error {
	encoded, err := json.Marshal(in)
	if err != nil {
		return err
	}
	var doc map[string]any
	// Keep util.UnmarshalJSON so numbers retain their precision for policy evaluation.
	if err := util.UnmarshalJSON(encoded, &doc); err != nil {
		return err
	}
	denied, err := m.policy.Deny(context.Background(), doc)
	if err != nil {
		log.Printf("policy: %v", err)
		return err
	}
	if len(denied) == 0 {
		return nil
	}
	reason := strings.Join(denied, "; ")
	log.Printf("denied %s: %s", encoded, reason)
	return errors.New(reason)
}

type channelConn struct {
	ssh.Channel
	principal principal
}

func (channelConn) LocalAddr() net.Addr              { return &net.TCPAddr{} }
func (channelConn) RemoteAddr() net.Addr             { return &net.TCPAddr{} }
func (channelConn) SetDeadline(time.Time) error      { return nil }
func (channelConn) SetReadDeadline(time.Time) error  { return nil }
func (channelConn) SetWriteDeadline(time.Time) error { return nil }

// authorized rereads the key file on every attempt, so keys change without a restart.
// A key reaches only the connections its connections="a,b" option names.
func authorized(path string) func(ssh.ConnMetadata, ssh.PublicKey) (*ssh.Permissions, error) {
	return func(_ ssh.ConnMetadata, key ssh.PublicKey) (*ssh.Permissions, error) {
		rest, err := os.ReadFile(path)
		if err != nil {
			return nil, err
		}
		for len(rest) > 0 {
			listed, comment, options, next, err := ssh.ParseAuthorizedKey(rest)
			if err != nil {
				break
			}
			if bytes.Equal(listed.Marshal(), key.Marshal()) {
				p := principal{Key: ssh.FingerprintSHA256(key), Name: comment, Connections: []string{}}
				for _, option := range options {
					if names, ok := strings.CutPrefix(option, optionConnections); ok {
						p.Connections = strings.Split(strings.Trim(names, `"`), ",")
					}
				}
				return &ssh.Permissions{ExtraData: map[any]any{principalKey{}: p}}, nil
			}
			rest = next
		}
		return nil, errors.New("key is not authorized")
	}
}
