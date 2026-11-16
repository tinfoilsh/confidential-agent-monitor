package monitor

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"

	"github.com/tinfoilsh/confidential-agent-monitor/connector"
	"github.com/tinfoilsh/confidential-agent-monitor/core"
	"github.com/tinfoilsh/confidential-agent-monitor/core/facts"
	"github.com/tinfoilsh/confidential-agent-monitor/core/identity"
	"github.com/tinfoilsh/confidential-agent-monitor/core/netx"
	"github.com/tinfoilsh/confidential-agent-monitor/perimeter/internal/authz"
	"github.com/tinfoilsh/confidential-agent-monitor/perimeter/internal/config"
	"golang.org/x/crypto/ssh"
)

const agentHost = config.AgentConnection + connector.Domain
const agentPort = 80

var errNoAccess = errors.New("key has no agent access")

// Open admits the stream of the identity ctx carries to host and port, calls accept, and serves
// the accepted stream until it ends. An error returned before accept refuses the stream. ctx ends
// when the stream's peer closes it.
func (m *Monitor) Open(ctx context.Context, host string, port uint32, accept func() (net.Conn, error)) error {
	if m.settings.Load() == nil {
		return errLocked
	}
	key, _ := identity.ID(ctx)
	switch {
	case host == agentHost:
		return m.serveAgentAPI(ctx, key, port, accept)
	default:
		if _, known := m.identities.Lookup(key); !known {
			return errNoAccess
		}
		return m.table.Open(ctx, host, port, accept)
	}
}

func (m *Monitor) serveAgentAPI(ctx context.Context, key string, port uint32, accept func() (net.Conn, error)) error {
	if _, known := m.identities.Lookup(key); !known {
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

// access answers the table from the identity registry, the settings and the gatekeeper.
type access struct{ m *Monitor }

func (a access) Reaches(ctx context.Context, connection string) bool {
	key, _ := identity.ID(ctx)
	p, known := a.m.identities.Lookup(key)
	return known && a.m.settings.Load().Reaches(p.Name, connection)
}

func (a access) Admit(ctx context.Context, r core.Request) (core.Watch, error) {
	m := a.m
	key, _ := identity.ID(ctx)
	admitted := &authz.Admission{Key: key, Connection: r.Connection, PerMessage: r.PerMessage, Valid: r.Valid}
	event := facts.Capture(facts.Facts{
		Operation:  &facts.Operation{Action: "session.admit", Effects: []string{"session"}},
		Title:      "Open " + admitted.Connection,
		Parameters: map[string]any{"host": r.Host, "port": r.Port},
		Details:    map[string]any{"tcp": map[string]any{"host": r.Host, "port": r.Port}},
		Context:    facts.Context{Observes: m.vocabulary.Initial},
	}, nil)
	if err := m.gate.Admit(ctx, admitted, event); err != nil {
		return nil, err
	}
	return func(ctx context.Context, end func()) (connector.Gate, bool) {
		m.mu.Lock()
		defer m.mu.Unlock()
		return m.gate.Watch(ctx, end, admitted)
	}, nil
}

// Hold leases capability while the identity ctx carries holds it. The context it returns ends
// when that identity is unregistered or a settings commit takes the capability away.
func (m *Monitor) Hold(ctx context.Context, capability string) (context.Context, context.CancelFunc, bool) {
	return m.gate.Hold(ctx, capability)
}

// Identities are the keys agents authenticate with.
func (m *Monitor) Identities() *identity.Registry { return m.identities }

func (m *Monitor) HostKey() ssh.Signer {
	if s := m.settings.Load(); s != nil {
		return s.HostKey
	}
	return m.sshHostKey
}
