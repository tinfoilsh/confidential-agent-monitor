package monitor

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"strings"

	"github.com/tinfoilsh/confidential-agent-monitor/connector"
	"github.com/tinfoilsh/confidential-agent-monitor/facts"
	"github.com/tinfoilsh/confidential-agent-monitor/internal/config"
	"github.com/tinfoilsh/confidential-agent-monitor/netx"
	"github.com/tinfoilsh/confidential-agent-monitor/routes"
	"golang.org/x/crypto/ssh"
)

const agentHost = config.AgentConnection + connector.Domain
const agentPort = 80

var errNoAccess = errors.New("key has no agent access")

// Open admits key's stream to host and port, calls accept, and serves the accepted stream
// until it ends. An error returned before accept refuses the stream. ctx ends when the
// stream's peer closes it.
func (m *Monitor) Open(ctx context.Context, key, host string, port uint32, accept func() (net.Conn, error)) error {
	if m.settings.Load() == nil {
		return errLocked
	}
	switch {
	case host == agentHost:
		return m.serveAgentAPI(ctx, key, port, accept)
	default:
		return m.forwardConnection(ctx, key, host, port, accept)
	}
}

func (m *Monitor) serveAgentAPI(ctx context.Context, key string, port uint32, accept func() (net.Conn, error)) error {
	if _, known := m.settings.Load().Principal(key); !known {
		return errNoAccess
	}
	if port != agentPort {
		return fmt.Errorf("%s uses HTTP on port %d inside the SSH tunnel", agentHost, agentPort)
	}
	conn, err := accept()
	if err != nil {
		return err
	}
	netx.ServeConn(ctx, conn, &http.Server{Handler: m.agentHandler(key)})
	return nil
}

func (m *Monitor) forwardConnection(ctx context.Context, key, target string, port uint32, accept func() (net.Conn, error)) error {
	st := m.settings.Load()
	p, known := st.Principal(key)
	if !known {
		return errNoAccess
	}
	m.mu.Lock()
	var candidates []candidate
	for name, c := range m.connections {
		if st.Reaches(p.Name, c.Name) && c.Status().State == statusReady && (!routes.ReservedRoute(target) || routes.RouteAllowed(c.prepared.Routes, target)) {
			route := candidate{Name: name}
			route.Claim = c.prepared.Claim
			candidates = append(candidates, route)
		}
	}
	selected, explicit := selectTarget(target, port, candidates)
	c := m.connections[selected]
	if c == nil {
		m.mu.Unlock()
		return errors.New("the Perimeter does not forward this target")
	}
	setup, name, admitted, env := c.setupCtx, c.Name, &admission{fingerprint: key, connection: c, prepared: c.prepared}, c.env
	m.mu.Unlock()
	host := target
	if explicit {
		host = ""
	}
	if err := m.authorizeAdmission(setup, admitted, target, port); err != nil {
		return err
	}
	conn, err := accept()
	if err != nil {
		return err
	}
	s := connector.NewStream(setup, conn)
	s.Name, s.Host, s.Port = name, host, port
	defer s.Close()
	context.AfterFunc(ctx, func() { s.Close() })
	release, ok := m.admitStream(s, admitted)
	if !ok {
		return nil
	}
	defer release()
	s.Gate = func(ctx context.Context, event facts.Event) error {
		return m.authorizeOperation(ctx, s, admitted, event)
	}
	// A worker proxy relays the bytes into the concrete connector and sends its
	// Gate calls back to this stream. Identity and policy remain owned by Monitor.
	c.Server.Serve(s, &env)
	return nil
}

// recheck runs under mu: the stream's identity, access and connector remain, and
// its admission and latest operation would be allowed outright under current settings.
func (m *Monitor) recheck(admitted *admission) bool {
	st := m.settings.Load()
	p, ok := st.Principal(admitted.fingerprint)
	if !ok {
		return false
	}
	if !st.Reaches(p.Name, admitted.connection.Name) {
		return false
	}
	for _, g := range admitted.grants {
		if d, err := m.decide(context.Background(), admitted, g); err != nil || len(d.Deny) != 0 || len(d.Requirements) != 0 {
			return false
		}
	}
	return true
}

// admitStream registers s for revocation and pins its connector until release.
func (m *Monitor) admitStream(s *connector.Stream, admitted *admission) (release func(), ok bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if !m.recheck(admitted) {
		return nil, false
	}
	if release, _ = m.acquire(admitted.connection, admitted.prepared); release == nil {
		return nil, false
	}
	m.streams[s] = admitted
	context.AfterFunc(s.Context, func() { m.mu.Lock(); delete(m.streams, s); m.mu.Unlock() })
	return release, true
}

// Capable reports whether key is an identity's, and whether that identity holds capability.
func (m *Monitor) Capable(key, capability string) (known, capable bool) {
	s := m.settings.Load()
	if s == nil {
		return false, false
	}
	p, known := s.Principal(key)
	return known, known && s.capable(p, capability)
}

type hold struct{ key, capability string }

// Hold leases capability while key's identity holds it. The context it returns ends
// when a settings commit leaves that identity unknown or without the capability.
func (m *Monitor) Hold(ctx context.Context, key, capability string) (context.Context, context.CancelFunc, bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	st := m.settings.Load()
	if st == nil {
		return nil, nil, false
	}
	if p, known := st.Principal(key); !known || !st.capable(p, capability) {
		return nil, nil, false
	}
	ctx, cancel := context.WithCancel(ctx)
	h := &hold{key, capability}
	m.holds[h] = cancel
	context.AfterFunc(ctx, func() { m.mu.Lock(); delete(m.holds, h); m.mu.Unlock() })
	return ctx, cancel, true
}

func (m *Monitor) identityKey(name string) (ssh.PublicKey, bool) {
	s := m.settings.Load()
	if s == nil {
		return nil, false
	}
	id, ok := s.Identities[name]
	if !ok {
		return nil, false
	}
	key, _, _, _, err := ssh.ParseAuthorizedKey([]byte(id.Key))
	return key, err == nil
}
func (m *Monitor) HostKey() ssh.Signer {
	if s := m.settings.Load(); s != nil {
		return s.HostKey
	}
	return m.sshHostKey
}

type candidate struct {
	Name  string
	Claim func(string, uint32) int
}

// selectTarget resolves only supplied candidates, so inaccessible connections cannot tie.
func selectTarget(host string, port uint32, candidates []candidate) (name string, explicit bool) {
	if name, ok := strings.CutSuffix(host, connector.Domain); ok {
		for _, c := range candidates {
			if c.Name == name {
				return name, true
			}
		}
		return "", true
	}
	best, tied := -1, false
	for _, c := range candidates {
		if c.Claim == nil {
			continue
		}
		score := c.Claim(host, port)
		if score < 0 {
			continue
		}
		if score > best {
			name, best, tied = c.Name, score, false
		} else if score == best {
			tied = true
		}
	}
	if tied {
		return "", false
	}
	return name, false
}
