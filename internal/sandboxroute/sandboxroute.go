// Package sandboxroute lets sandboxes publish SSH and HTTPS ports over the Monitor's SSH server.
package sandboxroute

import (
	"context"
	"crypto/sha256"
	"encoding/base32"
	"errors"
	"io"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/tinfoilsh/monitor/connector"
	"golang.org/x/crypto/ssh"
)

const (
	// Extension carries a session's route name in its SSH permissions.
	Extension = "route"

	routeSuffix          = ".sandbox.invalid"
	routeBindAddress     = "127.0.0.1"
	maxRouteOnlySessions = 128
	openTimeout          = 10 * time.Second
	drainTimeout         = 10 * time.Second
)

var ErrUnavailable = errors.New("route unavailable")

type listenAddress struct {
	Host string
	Port uint32
}

// routeSession is the authenticated connection publishing a key's virtual ports.
type routeSession struct {
	conn       *ssh.ServerConn
	ssh, https bool
}

// Table keeps SSH admission and routing independent of mu's policy commits.
// sessions records whether each connection's key had an identity when admitted.
type Table struct {
	mu       sync.Mutex
	routes   map[string]*routeSession
	sessions map[*ssh.ServerConn]bool
}

func Name(key ssh.PublicKey) string {
	digest := sha256.Sum256(key.Marshal())
	return strings.ToLower(base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(digest[:])) + routeSuffix
}

// Bootstrap names locate an unverified publisher by its claimed owner public key. Only
// HTTPS is reachable this way; the caller must attest it before sending secrets.
func Bootstrap(identity string) string {
	digest := sha256.Sum256([]byte(identity))
	return "bootstrap-" + strings.ToLower(base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(digest[:])) + routeSuffix
}

func Reserved(host string) bool {
	host = strings.TrimSuffix(strings.ToLower(host), ".")
	return host == "sandbox.invalid" || strings.HasSuffix(host, routeSuffix)
}

// Admit bounds sessions of keys without an identity, idle or publishing. A new
// session closes its key's previous idle one, so a key holds at most its publisher and
// one replacement, which is admitted at capacity only for a published route.
func (t *Table) Admit(conn *ssh.ServerConn, known bool) bool {
	name := conn.Permissions.Extensions[Extension]
	t.mu.Lock()
	var idle []*ssh.ServerConn
	unknown := 0
	for session, isKnown := range t.sessions {
		if isKnown {
			continue
		}
		if !known && session.Permissions.Extensions[Extension] == name && (t.routes[name] == nil || t.routes[name].conn != session) {
			delete(t.sessions, session)
			idle = append(idle, session)
			continue
		}
		unknown++
	}
	admitted := known || unknown < maxRouteOnlySessions || t.routes[name] != nil && unknown < 2*maxRouteOnlySessions
	if admitted {
		if t.sessions == nil {
			t.sessions = map[*ssh.ServerConn]bool{}
		}
		t.sessions[conn] = known
	}
	t.mu.Unlock()
	for _, session := range idle {
		session.Close()
	}
	return admitted
}

func (t *Table) Remove(conn *ssh.ServerConn) {
	t.mu.Lock()
	defer t.mu.Unlock()
	delete(t.sessions, conn)
	name := conn.Permissions.Extensions[Extension]
	if r := t.routes[name]; r != nil && r.conn == conn {
		delete(t.routes, name)
	}
}

func (t *Table) Serve(conn *ssh.ServerConn, requests <-chan *ssh.Request) {
	for req := range requests {
		ok := req.Type == "keepalive@openssh.com"
		var address listenAddress
		if (req.Type == "tcpip-forward" || req.Type == "cancel-tcpip-forward") && ssh.Unmarshal(req.Payload, &address) == nil && address.Host == routeBindAddress && (address.Port == 22 || address.Port == 443) {
			ok = t.register(conn, address.Port, req.Type == "cancel-tcpip-forward")
		}
		req.Reply(ok, nil)
	}
}

// register changes one virtual port. A registration from another session of the
// same key replaces and closes the publisher; replaced sessions can no longer register.
func (t *Table) register(conn *ssh.ServerConn, port uint32, cancel bool) bool {
	t.mu.Lock()
	if _, admitted := t.sessions[conn]; !admitted {
		t.mu.Unlock()
		return false
	}
	name := conn.Permissions.Extensions[Extension]
	r := t.routes[name]
	var replaced *ssh.ServerConn
	if r == nil || r.conn != conn {
		if cancel {
			t.mu.Unlock()
			return false
		}
		if r != nil {
			replaced = r.conn
			delete(t.sessions, replaced)
		}
		r = &routeSession{conn: conn}
		if t.routes == nil {
			t.routes = map[string]*routeSession{}
		}
		t.routes[name] = r
	}
	flag := &r.ssh
	if port == 443 {
		flag = &r.https
	}
	ok := *flag == cancel
	*flag = !cancel
	if !r.ssh && !r.https {
		delete(t.routes, name)
	}
	t.mu.Unlock()
	if replaced != nil {
		replaced.Close()
	}
	return ok
}

// open opens a channel to a registered virtual port of the exact route name.
func (t *Table) open(host string, port uint32) (ssh.Channel, <-chan *ssh.Request, error) {
	t.mu.Lock()
	r := t.routes[host]
	var publisher *ssh.ServerConn
	if r != nil && (port == 22 && r.ssh || port == 443 && r.https) {
		publisher = r.conn
	}
	if port == 443 && strings.HasPrefix(host, "bootstrap-") {
		for _, candidate := range t.routes {
			if candidate.https && Bootstrap(candidate.conn.User()) == host {
				if publisher != nil { // Ambiguous claims fail closed.
					publisher = nil
					break
				}
				publisher = candidate.conn
			}
		}
	}
	t.mu.Unlock()
	if publisher == nil {
		return nil, nil, ErrUnavailable
	}
	// OpenChannel cannot be canceled, so a publisher that stalls it is closed.
	stalled := time.AfterFunc(openTimeout, func() { publisher.Close() })
	defer stalled.Stop()
	channel, requests, err := publisher.OpenChannel("forwarded-tcpip", ssh.Marshal(struct {
		Host       string
		Port       uint32
		Origin     string
		OriginPort uint32
	}{routeBindAddress, port, routeBindAddress, port}))
	if err != nil {
		return nil, nil, ErrUnavailable
	}
	return channel, requests, nil
}

// Dial connects the Monitor itself to a route.
func (t *Table) Dial(host string, port uint32) (net.Conn, error) {
	channel, requests, err := t.open(host, port)
	if err != nil {
		return nil, err
	}
	go ssh.DiscardRequests(requests)
	return connector.NewChannelConn(channel), nil
}

// Forward relays a channel to a registered virtual port of the exact route name.
// track registers the stream before it carries data, or refuses it.
func (t *Table) Forward(host string, port uint32, incoming ssh.NewChannel, track func(*connector.Stream) bool) {
	upstream, upstreamRequests, err := t.open(host, port)
	if err != nil {
		incoming.Reject(ssh.ConnectionFailed, "route unavailable")
		return
	}
	publisherClosed := make(chan struct{})
	go func() { ssh.DiscardRequests(upstreamRequests); close(publisherClosed) }()
	channel, requests, err := incoming.Accept()
	if err != nil {
		upstream.Close()
		return
	}
	ownerClosed := make(chan struct{})
	go func() { ssh.DiscardRequests(requests); close(ownerClosed) }()
	stream := connector.NewStream(context.Background(), connector.ChannelConn{Channel: channel})
	stream.Host, stream.Port = host, port
	defer stream.Close()
	defer stream.Interrupt(upstream)()
	if !track(stream) {
		return
	}
	// Each direction half-closes on EOF. The stream ends when both have, on a copy error,
	// or once a side that closed its channel has its remaining data relayed.
	input, output := make(chan struct{}), make(chan struct{})
	relay := func(dst, src ssh.Channel, done chan<- struct{}) {
		defer close(done)
		if _, err := io.Copy(dst, src); err != nil {
			stream.Close()
		}
		dst.CloseWrite()
	}
	go relay(upstream, channel, input)
	go relay(channel, upstream, output)
	go func() { <-input; <-output; stream.Close() }()
	var relayed <-chan struct{}
	select {
	case <-ownerClosed:
		relayed = input
	case <-publisherClosed:
		relayed = output
	case <-stream.Context.Done():
	}
	// A peer that stops reading cannot hold the closed side's data, or the stream, forever.
	drain, cancel := context.WithTimeout(stream.Context, drainTimeout)
	defer cancel()
	select {
	case <-relayed:
	case <-drain.Done():
	}
}
