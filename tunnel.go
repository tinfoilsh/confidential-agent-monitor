package main

import (
	"context"
	"encoding/json"
	"errors"
	"log"
	"net"
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
	channelDirect = "direct-tcpip"
	monitorSuffix = ".monitor"
)

func (m *monitor) serveSSH(ln net.Listener) {
	front := &ssh.ServerConfig{PublicKeyCallback: m.authorized}
	front.AddHostKey(m.live.Load().HostKey)
	log.Printf("monitor listening on %s", ln.Addr())
	for {
		nc, err := ln.Accept()
		if err != nil {
			log.Fatal(err)
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
	st := m.live.Load()
	c := st.route(p, target.Host, target.Port)
	if c == nil {
		log.Printf("%s: dropped %s:%d", p.Name, target.Host, target.Port)
		nc.Reject(ssh.Prohibited, "the monitor does not forward this target")
		return
	}
	s := &connector.Stream{Env: &st.Env, Name: c.name, Host: target.Host, Port: target.Port}
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
func (st *state) route(p principal, host string, port uint32) *connection {
	if name, ok := strings.CutSuffix(host, monitorSuffix); ok {
		c := st.connections[name]
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
	for _, c := range st.connections {
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
	denied, err := m.live.Load().policy.Deny(context.Background(), doc)
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

// authorized reads the identities on every attempt, so keys change without a restart.
func (m *monitor) authorized(_ ssh.ConnMetadata, key ssh.PublicKey) (*ssh.Permissions, error) {
	if p, ok := m.live.Load().principals[ssh.FingerprintSHA256(key)]; ok {
		return &ssh.Permissions{ExtraData: map[any]any{principalKey{}: p}}, nil
	}
	return nil, errors.New("key is not authorized")
}
