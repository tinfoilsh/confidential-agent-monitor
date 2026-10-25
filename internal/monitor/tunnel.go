package monitor

import (
	"context"
	"crypto/ed25519"
	"errors"
	"fmt"
	"log"
	"net"
	"strings"
	"time"

	"github.com/tinfoilsh/monitor/connector"
	"github.com/tinfoilsh/monitor/facts"
	"github.com/tinfoilsh/monitor/internal/config"
	"github.com/tinfoilsh/monitor/internal/tinfoil/ownerauth"
	"github.com/tinfoilsh/monitor/internal/tinfoil/sandboxroute"
	"golang.org/x/crypto/ssh"
)

const (
	channelDirect        = "direct-tcpip"
	fingerprintExtension = "fingerprint"
	sandboxUserPrefix    = "device+sandbox:"
	sandboxEnrollment    = "sandbox-enrollment-v1"
	maxSSHHandshakes     = 64
	sshHandshakeTimeout  = 10 * time.Second
	agentHost            = config.AgentConnection + ".monitor"
	agentPort            = 80
)

type forwardedAddress struct {
	Host       string
	Port       uint32
	Origin     string
	OriginPort uint32
}

func (m *monitor) ServeSSH(ln net.Listener) {
	log.Printf("monitor listening on %s", ln.Addr())
	handshakes := make(chan struct{}, maxSSHHandshakes)
	for {
		nc, err := ln.Accept()
		if err != nil {
			if !errors.Is(err, net.ErrClosed) {
				log.Printf("SSH listener: %v", err)
			}
			return
		}
		hostKey := m.sshHostKey
		if st := m.live.Load(); st != nil {
			hostKey = st.HostKey
		}
		if hostKey == nil {
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
			front := &ssh.ServerConfig{PublicKeyCallback: m.authorized, MaxAuthTries: 3, ServerVersion: "SSH-2.0-Go " + sandboxEnrollment}
			front.AddHostKey(hostKey)
			nc.SetDeadline(time.Now().Add(sshHandshakeTimeout))
			conn, chans, reqs, err := ssh.NewServerConn(nc, front)
			<-handshakes
			if err != nil {
				nc.Close()
				return
			}
			nc.SetDeadline(time.Time{})
			defer conn.Close()
			if conn.Permissions.Extensions[ownerauth.Extension] == "true" {
				go ssh.DiscardRequests(reqs)
				for nc := range chans {
					go ownerauth.ServeChannel(nc, m.ownerAPI, m.generation)
				}
				return
			}
			_, known := m.live.Load().Principals[conn.Permissions.Extensions[fingerprintExtension]]
			if !m.routes.Admit(conn, known) {
				return
			}
			defer m.routes.Remove(conn)
			go m.routes.Serve(conn, reqs)
			for nc := range chans {
				go m.forward(conn.Permissions.Extensions[fingerprintExtension], nc)
			}
		}()
	}
}

func (m *monitor) forward(key string, nc ssh.NewChannel) {
	if nc.ChannelType() != channelDirect {
		nc.Reject(ssh.Prohibited, "only direct-tcpip channels are forwarded")
		return
	}
	var target forwardedAddress
	if err := ssh.Unmarshal(nc.ExtraData(), &target); err != nil {
		nc.Reject(ssh.ConnectionFailed, "malformed direct-tcpip request")
		return
	}
	st := m.live.Load()
	p, known := st.Principals[key]
	if !known {
		nc.Reject(ssh.Prohibited, "key has no agent access")
		return
	}
	if sandboxroute.Reserved(target.Host) {
		if !p.Routes {
			nc.Reject(ssh.Prohibited, "identity cannot open sandbox routes")
			return
		}
		m.routes.Forward(target.Host, target.Port, nc, func(s *connector.Stream) bool { return m.trackStream(key, s, st) })
		return
	}
	ctx := context.Background()
	var name string
	host := target.Host
	var serve func(*connector.Stream)
	switch target.Host {
	case agentHost:
		// The SSH identity supplies authorization; the owner API is never exposed here.
		if target.Port != agentPort {
			nc.Reject(ssh.Prohibited, fmt.Sprintf("%s uses HTTP on port %d inside the SSH tunnel", target.Host, agentPort))
			return
		}
		serve = func(s *connector.Stream) {
			connector.ServeHTTP(s, s, m.agentHandler(key))
		}
	default:
		c, selected := st.route(p, target.Host, target.Port)
		if c == nil {
			log.Printf("%s: dropped %s:%d", p.Name, target.Host, target.Port)
			nc.Reject(ssh.Prohibited, "the monitor does not forward this target")
			return
		}
		if err := m.gate(c.Context(), input{Key: key, Connection: c.Name, Request: &admissionRequest{Host: target.Host, Port: target.Port}}); err != nil {
			nc.Reject(ssh.Prohibited, err.Error())
			return
		}
		ctx = c.Context()
		name = c.Name
		if selected {
			host = ""
		}
		serve = func(s *connector.Stream) {
			s.Gate = func(ctx context.Context, request connector.Request) error {
				return m.gate(ctx, input{stream: s, Key: key, Connection: c.Name, Request: request})
			}
			log.Printf("%s: forwarding %s:%d", p.Name, target.Host, target.Port)
			c.Dispatch(s.Context, func(server connector.Server, env *connector.Env) { server.Serve(s, env) })
		}
	}
	ch, reqs, err := nc.Accept()
	if err != nil {
		return
	}
	s := connector.NewStream(ctx, connector.NewChannelConn(ch))
	s.Name, s.Host, s.Port = name, host, target.Port
	defer s.Close()
	go func() { ssh.DiscardRequests(reqs); s.Close() }()
	// agent.monitor authorizes each request against live state, and an approved proposal must answer on its stream.
	if target.Host != agentHost && !m.trackStream(key, s, st) {
		s.Close()
		return
	}
	serve(s)
}

// Only connections the principal reaches are routed, so their claims never tie with another principal's.
// A name.monitor target selects that connection; a claimer then checks each request's origin itself.
func (st *state) route(p config.Principal, host string, port uint32) (*connection, bool) {
	if name, ok := strings.CutSuffix(host, ".monitor"); ok {
		c := st.connections[name]
		if c == nil || !p.Reaches(c.Account) {
			return nil, false
		}
		return c, true
	}
	best, tied := -1, false
	var selected *connection
	for _, c := range st.connections {
		r, ok := c.Server.(connector.Claimer)
		if !ok || !p.Reaches(c.Account) {
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

// Route publishers need no identity; device setup can require an enrolled sandbox.
// Key probes run without a signature, so this never changes policy. Opening channels
// still needs a live identity.
func (m *monitor) authorized(conn ssh.ConnMetadata, key ssh.PublicKey) (*ssh.Permissions, error) {
	if raw, ok := key.(ssh.CryptoPublicKey); ok && m.ownerPublicKey != nil {
		if public, ok := raw.CryptoPublicKey().(ed25519.PublicKey); ok && m.ownerPublicKey.Equal(public) {
			return &ssh.Permissions{Extensions: map[string]string{ownerauth.Extension: "true"}}, nil
		}
	}
	st := m.live.Load()
	if st == nil {
		return nil, errLocked
	}
	if fingerprint, required := strings.CutPrefix(conn.User(), sandboxUserPrefix); required {
		if !st.Principals[ssh.FingerprintSHA256(key)].Routes {
			return nil, errors.New("device has no sandbox route access")
		}
		if _, enrolled := st.Principals[fingerprint]; !enrolled {
			return nil, errors.New("sandbox is not enrolled")
		}
	}
	return &ssh.Permissions{Extensions: map[string]string{
		fingerprintExtension: ssh.FingerprintSHA256(key), sandboxroute.Extension: sandboxroute.Name(key),
	}}, nil
}

// sameStreamAuthority compares only the authority used by this stream. Sandbox
// routes do not use connector policy; connector streams use their own account.
func (st *state) sameStreamAuthority(old *state, key string, s *connector.Stream) bool {
	p, exists := st.Principals[key]
	if !exists {
		return false
	}
	if sandboxroute.Reserved(s.Host) {
		return p.Routes
	}
	c := old.connections[s.Name]
	if c == nil || st.connections[s.Name] != c || !p.Reaches(c.Account) {
		return false
	}
	return st == old || st.SameAuthority(old.Snapshot, key, c.Account)
}

// trackStream registers a stream before it carries data. A policy published since
// st only invalidates admission if it changed this stream's authority.
func (m *monitor) trackStream(fingerprint string, s *connector.Stream, st *state) bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	if !m.live.Load().sameStreamAuthority(st, fingerprint, s) {
		return false
	}
	m.streams[s] = fingerprint
	context.AfterFunc(s.Context, func() {
		m.mu.Lock()
		delete(m.streams, s)
		m.mu.Unlock()
	})
	return true
}

type admissionRequest facts.TCP

func (r *admissionRequest) Describe(c connector.Context) (facts.Facts, error) {
	return facts.Facts{Kind: facts.KindAdmission, Operation: &facts.Operation{Action: "session.admit", Effects: []string{"session"}},
		Title: "Open " + c.Connection, Parameters: map[string]any{"host": r.Host, "port": r.Port}, Details: facts.Details{TCP: (*facts.TCP)(r)},
		Context: facts.Context{Observes: cleanLabel}}, nil
}
