package tinfoil

import (
	"context"
	"errors"
	"net/http"
	"net/url"

	"github.com/tinfoilsh/monitor/connector"
	"github.com/tinfoilsh/monitor/connector/mcp"
)

var MCPDefinition = connector.Definition{NewConfig: func() connector.Server { return new(MCP) }, Requests: mcp.Definition.Requests}

// MCP owns attestation for a Tinfoil MCP endpoint. The protocol implementation
// owns discovery, tool forwarding, pins, and per-call policy admission.
type MCP struct {
	mcp.Server
	Repo string `json:"repo"`
}

func (m *MCP) Prepare() error {
	if err := m.Server.Prepare(); err != nil {
		return err
	}
	u, _ := url.Parse(m.URL)
	if u.Scheme != "https" || u.User != nil {
		return errors.New("Tinfoil MCP requires an HTTPS URL without user information")
	}
	return validateEnclave(u.Host, m.Repo)
}

func (m *MCP) Run(ctx context.Context, e *connector.Env, serve func(context.Context)) error {
	client := e.Client()
	base := client.Transport.(*http.Transport)
	defer base.CloseIdleConnections()
	u, _ := url.Parse(m.URL)
	transport, err := newAttestedTransport(ctx, m.Secrets["token"], u.Host, m.Repo, base)
	if err != nil {
		return err
	}
	defer transport.CloseIdleConnections()
	client.Transport = transport
	return m.Server.RunWithClient(ctx, client, serve)
}
