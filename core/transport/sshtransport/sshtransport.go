package sshtransport

import (
	"context"
	"errors"
	"io"
	"math"
	"net"
	"sync"
	"time"

	"github.com/tinfoilsh/confidential-agent-monitor/core/transport/netx"
	"golang.org/x/crypto/ssh"
)

const (
	keepalive        = "keepalive@openssh.com"
	forwardRequest   = "tcpip-forward"
	cancelRequest    = "cancel-tcpip-forward"
	directChannel    = "direct-tcpip"
	forwardedChannel = "forwarded-tcpip"
)

var ErrUnavailable = errors.New("unavailable")

type Session = func(*ssh.ServerConn, <-chan ssh.NewChannel, <-chan *ssh.Request)

type Authenticate = func(conn ssh.ConnMetadata, key ssh.PublicKey) (session Session, proved func() error, err error)

type Limits struct {
	MaxAuthTries, MaxHandshakes int
	HandshakeTimeout            time.Duration
}

type authenticatedKey struct{}

type authenticated struct {
	session Session
	proved  func() error
}

func Serve(ln net.Listener, hostKey func() ssh.Signer, limits Limits, authenticate Authenticate, failed func(error)) {
	handshakes := make(chan struct{}, limits.MaxHandshakes)
	for {
		nc, err := ln.Accept()
		if err != nil {
			if !errors.Is(err, net.ErrClosed) {
				failed(err)
			}
			return
		}
		host := hostKey()
		if host == nil {
			nc.Close()
			continue
		}
		select {
		case handshakes <- struct{}{}:
		default:
			nc.Close()
			continue
		}
		config := &ssh.ServerConfig{
			MaxAuthTries: limits.MaxAuthTries,
			PublicKeyCallback: func(conn ssh.ConnMetadata, key ssh.PublicKey) (*ssh.Permissions, error) {
				session, proved, err := authenticate(conn, key)
				if err != nil {
					return nil, err
				}
				if session == nil {
					return nil, errors.New("key refused")
				}
				return &ssh.Permissions{ExtraData: map[any]any{authenticatedKey{}: authenticated{session, proved}}}, nil
			},
			VerifiedPublicKeyCallback: func(_ ssh.ConnMetadata, _ ssh.PublicKey, p *ssh.Permissions, _ string) (*ssh.Permissions, error) {
				if a := p.ExtraData[authenticatedKey{}].(authenticated); a.proved != nil {
					return p, a.proved()
				}
				return p, nil
			},
		}
		config.AddHostKey(host)
		go func() {
			nc.SetDeadline(time.Now().Add(limits.HandshakeTimeout))
			conn, chans, reqs, err := ssh.NewServerConn(nc, config)
			<-handshakes
			if err != nil {
				nc.Close()
				return
			}
			nc.SetDeadline(time.Time{})
			defer conn.Close()
			conn.Permissions.ExtraData[authenticatedKey{}].(authenticated).session(conn, chans, reqs)
		}()
	}
}

func ServeDirect(chans <-chan ssh.NewChannel, reqs <-chan *ssh.Request, open netx.Open) {
	go AnswerKeepalives(reqs)
	for nc := range chans {
		var t TCPIP
		if nc.ChannelType() != directChannel {
			nc.Reject(ssh.Prohibited, "only direct-tcpip channels are forwarded")
			continue
		}
		if err := ssh.Unmarshal(nc.ExtraData(), &t); err != nil {
			nc.Reject(ssh.Prohibited, "malformed direct-tcpip request")
			continue
		}
		go func() {
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			accepted := false
			err := open(ctx, "tcp", t.Host, t.Port, func() (net.Conn, error) {
				accepted = true
				ch, reqs, err := nc.Accept()
				if err != nil {
					return nil, err
				}
				conn := NewConn(ch, reqs)
				go func() {
					<-conn.Closed()
					cancel()
				}()
				return conn, nil
			})
			if err == nil || accepted {
				return
			}
			reason := ssh.Prohibited
			if errors.Is(err, ErrUnavailable) {
				reason = ssh.ConnectionFailed
			}
			nc.Reject(reason, err.Error())
		}()
	}
}

func AnswerKeepalives(requests <-chan *ssh.Request) {
	for req := range requests {
		req.Reply(req.Type == keepalive, nil)
	}
}

type TCPIP struct {
	Host       string
	Port       uint32
	Origin     string
	OriginPort uint32
}

type Conn struct {
	ssh.Channel
	reader net.Conn
	closed <-chan struct{}
}

func NewConn(ch ssh.Channel, requests <-chan *ssh.Request) Conn {
	r, w := net.Pipe()
	go func() { defer w.Close(); io.Copy(w, ch) }()
	closed := make(chan struct{})
	go func() { ssh.DiscardRequests(requests); close(closed) }()
	return Conn{Channel: ch, reader: r, closed: closed}
}

func (c Conn) Closed() <-chan struct{} { return c.closed }

func (c Conn) Read(p []byte) (int, error) {
	if c.reader != nil {
		return c.reader.Read(p)
	}
	return c.Channel.Read(p)
}

func (c Conn) Close() error {
	if c.reader != nil {
		c.reader.Close()
	}
	return c.Channel.Close()
}

func (Conn) LocalAddr() net.Addr             { return &net.TCPAddr{} }
func (Conn) RemoteAddr() net.Addr            { return &net.TCPAddr{} }
func (c Conn) SetDeadline(t time.Time) error { return c.SetReadDeadline(t) }
func (c Conn) SetReadDeadline(t time.Time) error {
	if c.reader != nil {
		return c.reader.SetReadDeadline(t)
	}
	return nil
}
func (Conn) SetWriteDeadline(time.Time) error { return nil }

type Forwards struct {
	conn        *ssh.ServerConn
	limit       int
	openTimeout time.Duration
	mu          sync.Mutex
	addresses   map[address]bool
}

type address struct {
	Host string
	Port uint32
}

func NewForwards(conn *ssh.ServerConn, limit int, openTimeout time.Duration) *Forwards {
	return &Forwards{conn: conn, limit: limit, openTimeout: openTimeout, addresses: map[address]bool{}}
}

func (f *Forwards) Serve(requests <-chan *ssh.Request) {
	for req := range requests {
		ok := req.Type == keepalive
		var a address
		if (req.Type == forwardRequest || req.Type == cancelRequest) && ssh.Unmarshal(req.Payload, &a) == nil && a.Port > 0 && a.Port <= math.MaxUint16 {
			f.mu.Lock()
			if req.Type == cancelRequest {
				ok = f.addresses[a]
				delete(f.addresses, a)
			} else if !f.addresses[a] && len(f.addresses) < f.limit {
				f.addresses[a], ok = true, true
			}
			f.mu.Unlock()
		}
		req.Reply(ok, nil)
	}
}

func (f *Forwards) Has(host string, port uint32) bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.addresses[address{host, port}]
}

func (f *Forwards) Dial(host string, port uint32) (net.Conn, error) {
	if !f.Has(host, port) {
		return nil, errors.New("address is not forwarded")
	}
	stalled := time.AfterFunc(f.openTimeout, func() { f.conn.Close() })
	defer stalled.Stop()
	channel, requests, err := f.conn.OpenChannel(forwardedChannel, ssh.Marshal(TCPIP{host, port, host, port}))
	if err != nil {
		return nil, err
	}
	return NewConn(channel, requests), nil
}
