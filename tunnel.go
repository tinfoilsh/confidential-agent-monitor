package main

import (
	"context"
	"errors"
	"log"
	"net"
	"strings"
	"time"

	"github.com/tinfoilsh/monitor/connector"
	"golang.org/x/crypto/ssh"
)

type tcpLayer struct {
	Host string `json:"host"`
	Port uint32 `json:"port"`
}

type namedAccount struct {
	Name string `json:"name"`
	account
}

// input carries either the tunnel's tcp layer or a connector's layers, never both.
type input struct {
	Principal  principal     `json:"principal"`
	Connection string        `json:"connection"`
	Protocol   string        `json:"protocol"`
	TCP        *tcpLayer     `json:"tcp,omitempty"`
	Account    *namedAccount `json:"account"`
	Access     access        `json:"access"`
	Rules      []rule        `json:"rules"`
	Label      label         `json:"label"`
	*connector.Event
}

type principal struct {
	Key      string            `json:"key"`
	Name     string            `json:"name"`
	Accounts map[string]access `json:"-"`
	Rules    []rule            `json:"-"`
}

func (p principal) reaches(account string) bool {
	level := p.Accounts[account].Level
	return level != "" && level != "off"
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
	s.Gate = func(e connector.Event) error {
		return m.gate(context.Background(), input{Principal: p, Connection: c.name, Protocol: c.protocol, Event: &e}, c.account)
	}
	if err := m.gate(context.Background(), input{Principal: p, Connection: c.name, Protocol: c.protocol, TCP: &tcpLayer{Host: target.Host, Port: target.Port}}, c.account); err != nil {
		nc.Reject(ssh.Prohibited, err.Error())
		return
	}
	ch, reqs, err := nc.Accept()
	if err != nil {
		return
	}
	go ssh.DiscardRequests(reqs)
	s.Conn = channelConn{ch}
	log.Printf("%s: forwarding %s:%d", p.Name, target.Host, target.Port)
	c.connector.Serve(s)
}

// Only connections the principal reaches are routed, so their claims never tie with another principal's.
func (st *state) route(p principal, host string, port uint32) *connection {
	if name, ok := strings.CutSuffix(host, monitorSuffix); ok {
		c := st.connections[name]
		if c == nil || !p.reaches(c.account) {
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
		if !ok || !p.reaches(c.account) {
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

type channelConn struct{ ssh.Channel }

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
