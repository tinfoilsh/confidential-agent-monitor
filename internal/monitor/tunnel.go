package monitor

import (
	"bytes"
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
const agentHost = config.AgentConnection + connector.Domain
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
			if m.settings.Load() == nil {
				return nil, errLocked
			}
			extensions, err := sandbox.Authenticate(conn, key, m.keyAccess)
			if err != nil {
				return nil, err
			}
			extensions[fingerprintExtension] = ssh.FingerprintSHA256(key)
			return &ssh.Permissions{Extensions: extensions}, nil
		}}
		c.AddHostKey(host)
		return c
	}, func(conn *ssh.ServerConn, chans <-chan ssh.NewChannel, reqs <-chan *ssh.Request) {
		if conn.Permissions.Extensions["owner"] == "true" {
			go ssh.DiscardRequests(reqs)
			for nc := range chans {
				go ownerauth.ServeChannel(nc, m.ownerAPI, m.generation)
			}
			return
		}

		fingerprint := conn.Permissions.Extensions[fingerprintExtension]
		if conn.Permissions.Extensions[sandbox.RouteExtension] != "" {
			known, _ := m.keyAccess(fingerprint)
			m.forwards.ServePublisher(conn, chans, reqs, sandbox.Publisher{
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
				go m.forwardSandbox(fingerprint, nc, target)
			} else if target.Host == agentHost {
				go m.serveAgentAPI(fingerprint, nc, target)
			} else {
				go m.forwardConnection(fingerprint, nc, target)
			}
		}
	})
}

func (m *monitor) forwardSandbox(key string, nc ssh.NewChannel, target frontdoor.Target) {
	known, operator := m.keyAccess(key)
	if !known {
		nc.Reject(ssh.Prohibited, "key has no agent access")
		return
	}
	if !operator {
		m.forwardConnection(key, nc, target)
		return
	}
	upstream, err := m.forwards.Dial(target.Host, target.Port)
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
	if release, ok := m.admitStream(s, m.settings.Load(), admission{fingerprint: key, route: true}); ok {
		defer release()
		connector.Relay(s.Context, s.Conn, upstream)
	}
}

func (m *monitor) serveAgentAPI(key string, nc ssh.NewChannel, target frontdoor.Target) {
	if _, known := m.settings.Load().Principal(key); !known {
		nc.Reject(ssh.Prohibited, "key has no agent access")
		return
	}
	if target.Port != agentPort {
		nc.Reject(ssh.Prohibited, fmt.Sprintf("%s uses HTTP on port %d inside the SSH tunnel", agentHost, agentPort))
		return
	}
	ch, reqs, err := nc.Accept()
	if err != nil {
		return
	}
	conn := connector.NewChannelConn(ch, reqs)
	s := connector.NewStream(context.Background(), conn)
	defer s.Close()
	go func() { <-conn.Closed(); s.Close() }()
	connector.ServeHTTP(s, s, m.agentHandler(key))
}

func (m *monitor) forwardConnection(key string, nc ssh.NewChannel, target frontdoor.Target) {
	st := m.settings.Load()
	p, known := st.Principal(key)
	if !known {
		nc.Reject(ssh.Prohibited, "key has no agent access")
		return
	}
	m.mu.Lock()
	var candidates []frontdoor.Candidate
	for name, c := range m.connections {
		if st.Reaches(p.Name, c.Name) && c.Status().State == statusReady {
			route := frontdoor.Candidate{Name: name}
			route.Claim = c.prepared.Claim
			candidates = append(candidates, route)
		}
	}
	selected, explicit := frontdoor.Select(target.Host, target.Port, candidates)
	c := m.connections[selected]
	if c == nil {
		m.mu.Unlock()
		nc.Reject(ssh.Prohibited, "the monitor does not forward this target")
		return
	}
	ctx, name, admitted, env := c.setupCtx, c.Name, admission{fingerprint: key, connection: c, prepared: c.prepared}, c.env
	m.mu.Unlock()
	host := target.Host
	if explicit {
		host = ""
	}
	if err := m.authorizeAdmission(ctx, admitted, target); err != nil {
		nc.Reject(ssh.Prohibited, err.Error())
		return
	}
	ch, reqs, err := nc.Accept()
	if err != nil {
		return
	}
	conn := connector.NewChannelConn(ch, reqs)
	s := connector.NewStream(ctx, conn)
	s.Name, s.Host, s.Port = name, host, target.Port
	defer s.Close()
	go func() { <-conn.Closed(); s.Close() }()
	release, ok := m.admitStream(s, st, admitted)
	if !ok {
		return
	}
	defer release()
	s.Gate = func(ctx context.Context, event facts.Event) error {
		return m.authorizeOperation(ctx, s, admitted, event)
	}
	// A worker proxy relays the bytes into the concrete connector and sends its
	// Gate calls back to this stream. Identity and policy remain owned by Monitor.
	c.Server.Serve(s, &env)
}

// stillAdmitted runs under mu. Commit compares each surviving stream with
// the previous settings: preserving authority at every transition preserves the
// original admission without storing another settings snapshot on the stream.
func (m *monitor) stillAdmitted(old *settings, admitted admission) bool {
	st := m.settings.Load()
	p, ok := st.Principal(admitted.fingerprint)
	if !ok {
		return false
	}
	if admitted.route {
		return st.Identities[p.Name].Operator
	}
	c := admitted.connection
	if !m.usable(c, admitted.prepared) || !st.Reaches(p.Name, c.Name) {
		return false
	}
	if st == old {
		return true
	}
	previous, _ := old.Principal(admitted.fingerprint)
	return previous == p && st.Engine.Program == old.Engine.Program && bytes.Equal(old.Authority(p.Name, c.Name), st.Authority(p.Name, c.Name))
}

// admitStream registers s for revocation and pins its connector until release.
func (m *monitor) admitStream(s *connector.Stream, st *settings, admitted admission) (release func(), ok bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if !m.stillAdmitted(st, admitted) {
		return nil, false
	}
	release = func() {}
	if !admitted.route {
		if release, _ = m.acquire(admitted.connection, admitted.prepared); release == nil {
			return nil, false
		}
	}
	m.streams[s] = admitted
	context.AfterFunc(s.Context, func() { m.mu.Lock(); delete(m.streams, s); m.mu.Unlock() })
	return release, true
}

func (m *monitor) keyAccess(key string) (known, operator bool) {
	s := m.settings.Load()
	if s == nil {
		return false, false
	}
	p, known := s.Principal(key)
	return known, s.Identities[p.Name].Operator
}
func (m *monitor) HostKey() ssh.Signer {
	if s := m.settings.Load(); s != nil {
		return s.HostKey
	}
	return m.sshHostKey
}
