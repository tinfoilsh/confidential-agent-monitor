package tinfoil

import (
	"context"
	"errors"
	"net/http"
	"net/url"

	"github.com/tinfoilsh/confidential-agent-monitor/connector"
	"github.com/tinfoilsh/confidential-agent-monitor/connector/mcp"
)

var MCPKind = connector.Kind{Parse: parseMCP, Open: openMCP}

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

// openMCP gives the SDK session ownership of its attested transport pool too.
func openMCP(ctx context.Context, prepared connector.Prepared, secrets map[string]connector.Secret, env *connector.Env) (connector.Handler, error) {
	setup := *prepared.Value.(*mcpSetup)
	setup.Bind(secrets)
	client := env.Client()
	base := client.Transport.(*http.Transport)
	u, _ := url.Parse(setup.URL)
	transport, err := newAttestedTransport(ctx, setup.Secrets["token"], u.Host, setup.Repo, base)
	if err != nil {
		base.CloseIdleConnections()
		return nil, err
	}
	client.Transport = transport
	return mcp.OpenWithClient(ctx, setup.Setup, env, client, func() {
		transport.CloseIdleConnections()
		base.CloseIdleConnections()
	})
}
