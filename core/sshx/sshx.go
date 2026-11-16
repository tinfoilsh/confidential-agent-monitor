// Package sshx serves SSH connections and the TCP/IP forwarding of RFC 4254 over them.
package sshx

import (
	"errors"
	"io"
	"log"
	"math"
	"net"
	"sync"
	"time"

	"golang.org/x/crypto/ssh"
)

const (
	maxHandshakes      = 64
	handshakeTimeout   = 10 * time.Second
	forwardOpenTimeout = 10 * time.Second
	keepalive          = "keepalive@openssh.com"
	forwardRequest     = "tcpip-forward"
	cancelRequest      = "cancel-tcpip-forward"
	forwardedChannel   = "forwarded-tcpip"
)

type Session = func(*ssh.ServerConn, <-chan ssh.NewChannel, <-chan *ssh.Request)

// An Extension returns the session of a key it accepts; a nil session and error pass the key on.
type Extension func(ssh.ConnMetadata, ssh.PublicKey) (Session, error)

// Serve accepts connections on ln, bounding concurrent and stalled handshakes.
func Serve(ln net.Listener, config func() *ssh.ServerConfig, session Session) {
	handshakes := make(chan struct{}, maxHandshakes)
	for {
		nc, err := ln.Accept()
		if err != nil {
			if !errors.Is(err, net.ErrClosed) {
				log.Printf("SSH listener: %v", err)
			}
			return
		}
		front := config()
		if front == nil {
			nc.Close()
			continue
		}
		select {
		case handshakes <- struct{}{}:
		default:
			nc.Close()
			continue
		}
		go func() {
			nc.SetDeadline(time.Now().Add(handshakeTimeout))
			conn, chans, reqs, err := ssh.NewServerConn(nc, front)
			<-handshakes
			if err != nil {
				nc.Close()
				return
			}
			nc.SetDeadline(time.Time{})
			defer conn.Close()
			session(conn, chans, reqs)
		}()
	}
}

// AnswerKeepalives answers keepalives and refuses every other request until requests closes.
func AnswerKeepalives(requests <-chan *ssh.Request) {
	for req := range requests {
		req.Reply(req.Type == keepalive, nil)
	}
}

// TCPIP is the payload of direct-tcpip and forwarded-tcpip channels.
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

// HTTP hijacking interrupts a pending read using a deadline. SSH channels have
// no deadlines, so give stream consumers an interruptible, bounded read pipe.
// Writes and half-close continue to use the SSH channel directly. Channel
// requests are rejected; their closure distinguishes full closure from EOF.
func NewConn(ch ssh.Channel, requests <-chan *ssh.Request) Conn {
	r, w := net.Pipe()
	go func() { defer w.Close(); io.Copy(w, ch) }()
	closed := make(chan struct{})
	go func() { ssh.DiscardRequests(requests); close(closed) }()
	return Conn{Channel: ch, reader: r, closed: closed}
}

// Closed reports full SSH channel closure; a peer's CloseWrite leaves it open.
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

// Forwards are the remote forwards one connection asked for. Nothing is bound
// locally; Dial opens a forwarded-tcpip channel back to the client.
type Forwards struct {
	conn      *ssh.ServerConn
	limit     int
	mu        sync.Mutex
	addresses map[address]bool
}

type address struct {
	Host string
	Port uint32
}

func NewForwards(conn *ssh.ServerConn, limit int) *Forwards {
	return &Forwards{conn: conn, limit: limit, addresses: map[address]bool{}}
}

// Serve answers keepalives and forward requests until requests closes.
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
	// OpenChannel cannot be canceled, so a peer that stalls it is closed.
	stalled := time.AfterFunc(forwardOpenTimeout, func() { f.conn.Close() })
	defer stalled.Stop()
	channel, requests, err := f.conn.OpenChannel(forwardedChannel, ssh.Marshal(TCPIP{host, port, host, port}))
	if err != nil {
		return nil, err
	}
	return NewConn(channel, requests), nil
}
