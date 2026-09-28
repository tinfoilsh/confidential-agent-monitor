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
	for ch := range chans {
		go m.dispatch(ch)
	}
}

func (m *monitor) dispatch(nc ssh.NewChannel) {
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
	handle := m.handler(target.Host, target.Port)
	if handle == nil {
		log.Printf("dropped %s:%d", target.Host, target.Port)
		nc.Reject(ssh.Prohibited, "the monitor does not forward this target")
		return
	}
	ch, reqs, err := nc.Accept()
	if err != nil {
		return
	}
	go ssh.DiscardRequests(reqs)
	log.Printf("forwarding %s:%d", target.Host, target.Port)
	handle(&channelConn{Channel: ch, host: target.Host})
}

// For a .monitor name the connection's kind picks the handler and the port is ignored.
func (m *monitor) handler(host string, port uint32) func(net.Conn) {
	if name, ok := strings.CutSuffix(host, monitorSuffix); ok {
		c := m.Connections[name]
		switch {
		case c == nil:
		case c.SSH != nil:
			return func(conn net.Conn) { m.relaySSH(conn, c.SSH) }
		case c.Postgres != "":
			return func(conn net.Conn) { m.relayPostgres(conn, c.Postgres) }
		case c.Redis != "":
			return func(conn net.Conn) { relayRedis(conn, c.Redis) }
		}
		return nil
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
	host string
}

func (*channelConn) LocalAddr() net.Addr              { return &net.TCPAddr{} }
func (*channelConn) RemoteAddr() net.Addr             { return &net.TCPAddr{} }
func (*channelConn) SetDeadline(time.Time) error      { return nil }
func (*channelConn) SetReadDeadline(time.Time) error  { return nil }
func (*channelConn) SetWriteDeadline(time.Time) error { return nil }

// chanListener hands dispatched channels to an http.Server.
type chanListener chan net.Conn

func (l chanListener) push(c net.Conn) { l <- c }

func (l chanListener) Accept() (net.Conn, error) { return <-l, nil }
func (chanListener) Close() error                { return nil }
func (chanListener) Addr() net.Addr              { return &net.TCPAddr{} }
