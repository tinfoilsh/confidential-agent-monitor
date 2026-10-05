package main

import (
	"errors"
	"log"
	"net"
	"strings"
	"time"

	"github.com/tinfoilsh/monitor/connector"
	"golang.org/x/crypto/ssh"
)

type principalKey struct{}

const (
	channelDirect = "direct-tcpip"
)

func (m *monitor) serveSSH(ln net.Listener) {
	front := &ssh.ServerConfig{PublicKeyCallback: m.authorized}
	front.AddHostKey(m.live.Load().HostKey)
	log.Printf("monitor listening on %s", ln.Addr())
	for {
		nc, err := ln.Accept()
		if err != nil {
			if !errors.Is(err, net.ErrClosed) {
				log.Printf("SSH listener: %v", err)
			}
			return
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
	if target.Host == messageHost {
		m.forwardMessages(p, nc, target.Port)
		return
	}
	st := m.live.Load()
	p = st.principals[p.Key]
	c, selected := st.route(p, target.Host, target.Port)
	if c == nil {
		log.Printf("%s: dropped %s:%d", p.Name, target.Host, target.Port)
		nc.Reject(ssh.Prohibited, "the monitor does not forward this target")
		return
	}
	select {
	case <-c.ready:
	default:
		nc.Reject(ssh.ConnectionFailed, "the connector is starting")
		return
	}
	if c.ctx.Err() != nil {
		nc.Reject(ssh.ConnectionFailed, "the connector is stopped")
		return
	}
	s := connector.NewStream(c.ctx)
	s.Name, s.Host, s.Port = c.name, target.Host, target.Port
	if selected {
		s.Host = ""
	}
	s.Gate = func(e connector.Event) error {
		return m.gate(s.Context, input{stream: s, Principal: p, Connection: c.name, Protocol: c.protocol, Event: &e}, c.account)
	}
	if err := m.gate(s.Context, input{Principal: p, Connection: c.name, Protocol: c.protocol, TCP: &tcpLayer{Host: target.Host, Port: target.Port}}, c.account); err != nil {
		s.Close()
		nc.Reject(ssh.Prohibited, err.Error())
		return
	}
	ch, reqs, err := nc.Accept()
	if err != nil {
		s.Close()
		return
	}
	go ssh.DiscardRequests(reqs)
	s.Conn = channelConn{ch}
	if err := m.trackStream(p.Key, s); err != nil {
		s.Close()
		return
	}
	log.Printf("%s: forwarding %s:%d", p.Name, target.Host, target.Port)
	c.incoming.Hand(s)
}

// Only connections the principal reaches are routed, so their claims never tie with another principal's.
// A name.monitor target selects that connection; a claimer then checks each request's origin itself.
func (st *state) route(p principal, host string, port uint32) (*connection, bool) {
	if name, ok := strings.CutSuffix(host, ".monitor"); ok {
		c := st.connections[name]
		if c == nil || !p.reaches(c.account) {
			return nil, false
		}
		return c, true
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
		return nil, false
	}
	return selected, false
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
