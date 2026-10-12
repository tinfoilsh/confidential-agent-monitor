package main

import (
	"context"
	"crypto/sha256"
	"encoding/base32"
	"io"
	"strings"
	"time"

	"github.com/tinfoilsh/monitor/connector"
	"golang.org/x/crypto/ssh"
)

const (
	routeSuffix          = ".sandbox.invalid"
	routeExtension       = "route"
	routeBindAddress     = "127.0.0.1"
	maxRouteOnlySessions = 128
	maxSSHHandshakes     = 64
	sshHandshakeTimeout  = 10 * time.Second
	routeDrainTimeout    = 10 * time.Second
)

type listenAddress struct {
	Host string
	Port uint32
}

// routeSession is the authenticated connection publishing a key's virtual ports.
type routeSession struct {
	conn       *ssh.ServerConn
	ssh, https bool
}

func routeName(key ssh.PublicKey) string {
	digest := sha256.Sum256(key.Marshal())
	return strings.ToLower(base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(digest[:])) + routeSuffix
}

// Bootstrap names locate an unverified publisher by its claimed owner public key. Only
// HTTPS is reachable this way; the caller must attest it before sending secrets.
func bootstrapRoute(identity string) string {
	digest := sha256.Sum256([]byte(identity))
	return "bootstrap-" + strings.ToLower(base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(digest[:])) + routeSuffix
}

func reservedRoute(host string) bool {
	host = strings.TrimSuffix(strings.ToLower(host), ".")
	return host == "sandbox.invalid" || strings.HasSuffix(host, routeSuffix)
}

// admitSession bounds sessions of keys without an identity, idle or publishing. A new
// session closes its key's previous idle one, so a key holds at most its publisher and
// one replacement, which is admitted at capacity only for a published route.
func (m *monitor) admitSession(conn *ssh.ServerConn) bool {
	_, known := m.live.Load().principals[conn.Permissions.Extensions[fingerprintExtension]]
	name := conn.Permissions.Extensions[routeExtension]
	m.routesMu.Lock()
	var idle []*ssh.ServerConn
	unknown := 0
	for session, isKnown := range m.sessions {
		if isKnown {
			continue
		}
		if !known && session.Permissions.Extensions[routeExtension] == name && (m.routes[name] == nil || m.routes[name].conn != session) {
			delete(m.sessions, session)
			idle = append(idle, session)
			continue
		}
		unknown++
	}
	admitted := known || unknown < maxRouteOnlySessions || m.routes[name] != nil && unknown < 2*maxRouteOnlySessions
	if admitted {
		if m.sessions == nil {
			m.sessions = map[*ssh.ServerConn]bool{}
		}
		m.sessions[conn] = known
	}
	m.routesMu.Unlock()
	for _, session := range idle {
		session.Close()
	}
	return admitted
}

func (m *monitor) removeSession(conn *ssh.ServerConn) {
	m.routesMu.Lock()
	defer m.routesMu.Unlock()
	delete(m.sessions, conn)
	name := conn.Permissions.Extensions[routeExtension]
	if r := m.routes[name]; r != nil && r.conn == conn {
		delete(m.routes, name)
	}
}

func (m *monitor) routeRequests(conn *ssh.ServerConn, requests <-chan *ssh.Request) {
	for req := range requests {
		ok := req.Type == "keepalive@openssh.com"
		var address listenAddress
		if (req.Type == "tcpip-forward" || req.Type == "cancel-tcpip-forward") && ssh.Unmarshal(req.Payload, &address) == nil && address.Host == routeBindAddress && (address.Port == 22 || address.Port == 443) {
			ok = m.registerRoute(conn, address.Port, req.Type == "cancel-tcpip-forward")
		}
		req.Reply(ok, nil)
	}
}

// registerRoute changes one virtual port. A registration from another session of the
// same key replaces and closes the publisher; replaced sessions can no longer register.
func (m *monitor) registerRoute(conn *ssh.ServerConn, port uint32, cancel bool) bool {
	m.routesMu.Lock()
	if _, admitted := m.sessions[conn]; !admitted {
		m.routesMu.Unlock()
		return false
	}
	name := conn.Permissions.Extensions[routeExtension]
	r := m.routes[name]
	var replaced *ssh.ServerConn
	if r == nil || r.conn != conn {
		if cancel {
			m.routesMu.Unlock()
			return false
		}
		if r != nil {
			replaced = r.conn
			delete(m.sessions, replaced)
		}
		r = &routeSession{conn: conn}
		if m.routes == nil {
			m.routes = map[string]*routeSession{}
		}
		m.routes[name] = r
	}
	flag := &r.ssh
	if port == 443 {
		flag = &r.https
	}
	ok := *flag == cancel
	*flag = !cancel
	if !r.ssh && !r.https {
		delete(m.routes, name)
	}
	m.routesMu.Unlock()
	if replaced != nil {
		replaced.Close()
	}
	return ok
}

// forwardRoute relays a channel to a registered virtual port of the exact route name.
func (m *monitor) forwardRoute(key string, p principal, st *state, target forwardedAddress, incoming ssh.NewChannel) {
	if !p.Routes {
		incoming.Reject(ssh.Prohibited, "identity cannot open sandbox routes")
		return
	}
	m.routesMu.Lock()
	r := m.routes[target.Host]
	var publisher *ssh.ServerConn
	if r != nil && (target.Port == 22 && r.ssh || target.Port == 443 && r.https) {
		publisher = r.conn
	}
	if target.Port == 443 && strings.HasPrefix(target.Host, "bootstrap-") {
		for _, candidate := range m.routes {
			if candidate.https && bootstrapRoute(candidate.conn.User()) == target.Host {
				if publisher != nil { // Ambiguous claims fail closed.
					publisher = nil
					break
				}
				publisher = candidate.conn
			}
		}
	}
	m.routesMu.Unlock()
	if publisher == nil {
		incoming.Reject(ssh.ConnectionFailed, "route unavailable")
		return
	}
	// OpenChannel cannot be canceled, so a publisher that stalls it is closed.
	stalled := time.AfterFunc(sshHandshakeTimeout, func() { publisher.Close() })
	upstream, upstreamRequests, err := publisher.OpenChannel("forwarded-tcpip", ssh.Marshal(forwardedAddress{routeBindAddress, target.Port, routeBindAddress, target.Port}))
	stalled.Stop()
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
	stream := connector.NewStream(context.Background(), channelConn{channel})
	defer stream.Close()
	defer stream.Interrupt(upstream)()
	if !m.trackStream(key, stream, st) {
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
	drain, cancel := context.WithTimeout(stream.Context, routeDrainTimeout)
	defer cancel()
	select {
	case <-relayed:
	case <-drain.Done():
	}
}
