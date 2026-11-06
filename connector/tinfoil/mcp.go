package tinfoil

import (
	"context"
	"errors"
	"net/http"
	"net/url"

	"github.com/tinfoilsh/monitor/connector"
	"github.com/tinfoilsh/monitor/connector/credential"
	"github.com/tinfoilsh/monitor/connector/mcp"
)

var MCPKind = connector.Kind{Parse: parseMCP, New: func() connector.Server { return new(MCP) }}

type mcpSetup struct {
	mcp.Setup
	Repo string `json:"repo"`
}

func parseMCP(source connector.Setup) (connector.Prepared, error) {
	setup := new(mcpSetup)
	prepared, err := mcp.ParseSetup(source, setup, &setup.Setup)
	if err != nil {
		return connector.Prepared{}, err
	}
	u, _ := url.Parse(setup.URL)
	if u.Scheme != "https" || u.User != nil {
		return connector.Prepared{}, errors.New("Tinfoil MCP requires an HTTPS URL without user information")
	}
	if err := validateEnclave(u.Host, setup.Repo); err != nil {
		return connector.Prepared{}, err
	}
	prepared.Value = setup
	return prepared, nil
}

// MCP uses the SDK session owner for its attested transport pool too.
type MCP struct{ mcp.Server }

func (m *MCP) Update(ctx context.Context, prepared connector.Prepared, secrets map[string]*credential.Value, env *connector.Env) error {
	m.Server.Close()
	setup := *prepared.Value.(*mcpSetup)
	setup.Bind(secrets)
	client := env.Client()
	base := client.Transport.(*http.Transport)
	u, _ := url.Parse(setup.URL)
	transport, err := newAttestedTransport(ctx, setup.Secrets["token"], u.Host, setup.Repo, base)
	if err != nil {
		base.CloseIdleConnections()
		return err
	}
	client.Transport = transport
	return m.Server.UpdateWithClient(ctx, setup.Setup, client, func() {
		transport.CloseIdleConnections()
		base.CloseIdleConnections()
	})
}
