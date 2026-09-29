package main

import (
	"log"
	"net"
	"strings"
	"time"

	"golang.org/x/crypto/ssh"
)

const (
	channelDirect = "direct-tcpip"
	monitorSuffix = ".monitor"
	protocolHTTP  = "http"
	httpsPort     = 443
	httpPort      = 80
)

func (m *monitor) serve(nc net.Conn) {
	conn, chans, reqs, err := ssh.NewServerConn(nc, m.front)
	if err != nil {
		nc.Close()
		return
	}
	defer conn.Close()
	go ssh.DiscardRequests(reqs)
	p := principal{Key: conn.Permissions.Extensions[extensionKey], Name: conn.Permissions.Extensions[extensionName]}
	for ch := range chans {
		go m.dispatch(p, ch)
	}
}

func (m *monitor) dispatch(p principal, nc ssh.NewChannel) {
	if nc.ChannelType() != channelDirect {
		nc.Reject(ssh.Prohibited, "only direct-tcpip channels are forwarded")
		return
	}
	var target struct {
		Host       string
		Port       uint32
		OriginHost string
		OriginPort uint32
	}
	if err := ssh.Unmarshal(nc.ExtraData(), &target); err != nil {
		nc.Reject(ssh.ConnectionFailed, "malformed direct-tcpip request")
		return
	}
	cc := &channelConn{m: m, principal: p, host: target.Host}
	serve := m.route(cc, target.Port)
	if serve == nil {
		log.Printf("%s: dropped %s:%d", p.Name, target.Host, target.Port)
		nc.Reject(ssh.Prohibited, "the monitor does not forward this target")
		return
	}
	if err := cc.gate(event{TCP: &tcpLayer{Host: target.Host, Port: target.Port}}); err != nil {
		nc.Reject(ssh.Prohibited, err.Error())
		return
	}
	ch, reqs, err := nc.Accept()
	if err != nil {
		return
	}
	go ssh.DiscardRequests(reqs)
	log.Printf("%s: forwarding %s:%d", p.Name, target.Host, target.Port)
	cc.Channel = ch
	serve(cc)
}

// route names the channel's connection and protocol. A .monitor name picks its relay whatever the port;
// any other host is http, bound to the connection whose hosts list it.
func (m *monitor) route(cc *channelConn, port uint32) func(*channelConn) {
	if name, ok := strings.CutSuffix(cc.host, monitorSuffix); ok {
		c := m.Connections[name]
		if c == nil || c.relay == nil {
			return nil
		}
		cc.name, cc.protocol = name, c.protocol
		return c.relay.serve
	}
	cc.protocol = protocolHTTP
	for name, c := range m.Connections {
		if c.allows(cc.host) {
			cc.name = name
			break
		}
	}
	switch port {
	case httpsPort:
		return m.https.push
	case httpPort:
		return m.http.push
	}
	return nil
}

// channelConn lets an accepted channel stand in for a TCP connection to its target.
type channelConn struct {
	ssh.Channel
	m         *monitor
	principal principal
	name      string
	protocol  string
	host      string
}

func (*channelConn) LocalAddr() net.Addr              { return &net.TCPAddr{} }
func (*channelConn) RemoteAddr() net.Addr             { return &net.TCPAddr{} }
func (*channelConn) SetDeadline(time.Time) error      { return nil }
func (*channelConn) SetReadDeadline(time.Time) error  { return nil }
func (*channelConn) SetWriteDeadline(time.Time) error { return nil }

// chanListener hands dispatched channels to a server that wants a net.Listener.
type chanListener chan net.Conn

func (l chanListener) push(c *channelConn) { l <- c }

func (l chanListener) Accept() (net.Conn, error) { return <-l, nil }
func (chanListener) Close() error                { return nil }
func (chanListener) Addr() net.Addr              { return &net.TCPAddr{} }
