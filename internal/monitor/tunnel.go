package monitor

import (
	"context"
	"crypto/ed25519"
	"fmt"
	"net"

	"github.com/tinfoilsh/monitor/connector"
	"github.com/tinfoilsh/monitor/facts"
	"github.com/tinfoilsh/monitor/internal/config"
	"github.com/tinfoilsh/monitor/internal/frontdoor"
	"github.com/tinfoilsh/monitor/internal/tinfoil/ownerauth"
	"github.com/tinfoilsh/monitor/internal/tinfoil/sandbox"
	"golang.org/x/crypto/ssh"
)

const fingerprintExtension = "fingerprint"
const agentHost = config.AgentConnection + ".monitor"
const agentPort = 80

func (m *monitor) ServeSSH(ln net.Listener) {
	frontdoor.Serve(ln, func() *ssh.ServerConfig {
		host := m.HostKey()
		if host == nil {
			return nil
		}
		c := &ssh.ServerConfig{MaxAuthTries: 3, PublicKeyCallback: func(conn ssh.ConnMetadata, key ssh.PublicKey) (*ssh.Permissions, error) {
			if raw, ok := key.(ssh.CryptoPublicKey); ok && m.ownerPublicKey != nil {
				if public, ok := raw.CryptoPublicKey().(ed25519.PublicKey); ok && m.ownerPublicKey.Equal(public) {
					return &ssh.Permissions{Extensions: map[string]string{"owner": "true"}}, nil
				}
			}
			if m.live.Load() == nil {
				return nil, errLocked
			}
			extensions, err := sandbox.Authenticate(conn, key, m.Identity)
			if err != nil {
				return nil, err
			}
			extensions[fingerprintExtension] = ssh.FingerprintSHA256(key)
			return &ssh.Permissions{Extensions: extensions}, nil
		}}
		c.AddHostKey(host)
		return c
	}, func(conn *ssh.ServerConn, chans <-chan ssh.NewChannel, reqs <-chan *ssh.Request) {
		// Grant SSH-authenticated access to the control API to owners
		if conn.Permissions.Extensions["owner"] == "true" {
			go ssh.DiscardRequests(reqs)
			for nc := range chans {
				go ownerauth.ServeChannel(nc, m.ownerAPI, m.generation)
			}
			return
		}

		fingerprint := conn.Permissions.Extensions[fingerprintExtension]
		if conn.Permissions.Extensions[sandbox.RouteExtension] != "" {
			known, _ := m.Identity(fingerprint)
			// A sandbox registers a reverse-ssh route that principals can connect to
			m.forwards.ServePublisher(conn, chans, reqs, frontdoor.Publisher{
				Name:    conn.Permissions.Extensions[sandbox.RouteExtension],
				Alias:   conn.Permissions.Extensions[sandbox.BootstrapExtension],
				Trusted: known,
			})
			return
		}

		go func() {
			for req := range reqs {
				req.Reply(req.Type == "keepalive@openssh.com", nil)
			}
		}()
		for nc := range chans {
			target, err := frontdoor.Parse(nc)
			if err != nil {
				nc.Reject(ssh.Prohibited, err.Error())
				continue
			}
			if sandbox.ReservedRoute(target.Host) {
				// Forward to a registered reverse-ssh route
				go m.forwardSandbox(fingerprint, nc, target)
			} else {
				// Forward to a connector
				go m.forward(fingerprint, nc, target)
			}
		}
	})
}

func (m *monitor) forwardSandbox(key string, nc ssh.NewChannel, target frontdoor.Target) {
	st := m.live.Load()
	p, known := st.Principal(key)
	if !known {
		nc.Reject(ssh.Prohibited, "key has no agent access")
		return
	}
	if !st.Identities[p.Name].Routes {
		nc.Reject(ssh.Prohibited, "identity cannot open sandbox routes")
		return
	}
	upstream, err := sandbox.Dial(m.forwards, target.Host, target.Port)
	if err != nil {
		nc.Reject(ssh.ConnectionFailed, "route unavailable")
		return
	}
	defer upstream.Close()
	ch, reqs, err := nc.Accept()
	if err != nil {
		return
	}
	s := connector.NewStream(context.Background(), connector.NewChannelConn(ch, reqs))
	s.Host, s.Port = target.Host, target.Port
	defer s.Close()
	if m.trackStream(s, st, streamAuthority{key: key, route: true}) {
		connector.Relay(s.Context, s.Conn, upstream)
	}
}

func (m *monitor) forward(key string, nc ssh.NewChannel, target frontdoor.Target) {
	st := m.live.Load()
	p, known := st.Principal(key)
	if !known {
		nc.Reject(ssh.Prohibited, "key has no agent access")
		return
	}
	ctx := context.Background()
	host, name := target.Host, ""
	var c *connection
	var binding streamAuthority
	var env connector.Env
	if target.Host == agentHost {
		if target.Port != agentPort {
			nc.Reject(ssh.Prohibited, fmt.Sprintf("%s uses HTTP on port %d inside the SSH tunnel", target.Host, agentPort))
			return
		}
	} else {
		m.mu.Lock()
		var candidates []frontdoor.Candidate
		for name, c := range m.connections {
			if st.Reaches(p.Name, c.Account) && c.Status().State == "ready" {
				route := frontdoor.Candidate{Name: name}
				route.Claim = c.setup.Claim
				candidates = append(candidates, route)
			}
		}
		selected, explicit := frontdoor.Select(target.Host, target.Port, candidates)
		c = m.connections[selected]
		if c != nil {
			ctx, name, binding, env = c.ctx, c.Name, streamAuthority{key: key, connection: c, setup: c.setup}, c.env
		}
		m.mu.Unlock()
		if c == nil {
			nc.Reject(ssh.Prohibited, "the monitor does not forward this target")
			return
		}
		if explicit {
			host = ""
		}
		f := facts.Facts{Kind: facts.KindAdmission, Operation: &facts.Operation{Action: "session.admit", Effects: []string{"session"}}, Title: "Open " + name, Parameters: map[string]any{"host": target.Host, "port": target.Port}, Details: map[string]any{"tcp": map[string]any{"host": target.Host, "port": target.Port}}, Context: facts.Context{Observes: cleanLabel}}
		if err := m.gate(ctx, input{streamAuthority: binding, admission: true, Event: facts.Capture(f, nil)}); err != nil {
			nc.Reject(ssh.Prohibited, err.Error())
			return
		}
	}
	ch, reqs, err := nc.Accept()
	if err != nil {
		return
	}
	conn := connector.NewChannelConn(ch, reqs)
	s := connector.NewStream(ctx, conn)
	s.Name, s.Host, s.Port = name, host, target.Port
	defer s.Close()
	// Disconnects cancel pending operations.
	go func() { <-conn.Closed(); s.Close() }()
	if c == nil {
		connector.ServeHTTP(s, s, m.agentHandler(key))
		return
	}
	if !m.trackStream(s, st, binding) {
		return
	}
	s.Gate = func(ctx context.Context, event facts.Event) error {
		return m.gate(ctx, input{stream: s, streamAuthority: binding, Event: event})
	}
	defer c.active.Done()
	c.Server.Serve(s, &env)
}

func (m *monitor) sameStreamAuthority(old *state, a streamAuthority) bool {
	st := m.live.Load()
	p, ok := st.Principal(a.key)
	if !ok {
		return false
	}
	if a.route {
		return st.Identities[p.Name].Routes
	}
	c := a.connection
	// Unrelated edits preserve authority.
	return c != nil && m.connections[c.Name] == c && c.setup == a.setup && c.ready && st.Reaches(p.Name, c.Account) && (st == old || st.Engine.Program == old.Engine.Program && st.Config.SameAuthority(old.Config, a.key, c.Account))
}
func (m *monitor) trackStream(s *connector.Stream, st *state, a streamAuthority) bool {
	// Prevent admission racing with revocation.
	m.mu.Lock()
	defer m.mu.Unlock()
	if !m.sameStreamAuthority(st, a) || !a.route && m.acquire(a.connection, a.setup) != nil {
		return false
	}
	m.streams[s] = a
	context.AfterFunc(s.Context, func() { m.mu.Lock(); delete(m.streams, s); m.mu.Unlock() })
	return true
}

func (m *monitor) Identity(key string) (known, routes bool) {
	s := m.live.Load()
	if s == nil {
		return false, false
	}
	p, known := s.Principal(key)
	return known, s.Identities[p.Name].Routes
}
func (m *monitor) HostKey() ssh.Signer {
	if s := m.live.Load(); s != nil {
		return s.HostKey
	}
	return m.sshHostKey
}
