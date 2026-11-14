// Package kinds lists the standard connector kinds by the protocol name policies see.
package kinds

import (
	"github.com/tinfoilsh/confidential-agent-monitor/connector"
	"github.com/tinfoilsh/confidential-agent-monitor/connector/email"
	"github.com/tinfoilsh/confidential-agent-monitor/connector/mcp"
	"github.com/tinfoilsh/confidential-agent-monitor/connector/mqtt"
	"github.com/tinfoilsh/confidential-agent-monitor/connector/nats"
	"github.com/tinfoilsh/confidential-agent-monitor/connector/postgres"
	"github.com/tinfoilsh/confidential-agent-monitor/connector/redis"
	"github.com/tinfoilsh/confidential-agent-monitor/connector/session"
	"github.com/tinfoilsh/confidential-agent-monitor/connector/signer"
	"github.com/tinfoilsh/confidential-agent-monitor/connector/tcp"
	"github.com/tinfoilsh/confidential-agent-monitor/connector/web"
)

func Standard() map[string]connector.Kind {
	// The kind is also the protocol policies see.
	return map[string]connector.Kind{
		"tcp":       tcp.Kind,
		"http":      web.Kind,
		"mcp":       mcp.Kind,
		"ssh":       session.SSHKind,
		"sftp":      session.SFTPKind,
		"cli":       session.CLIKind,
		"mqtt":      mqtt.Kind,
		"nats":      nats.Kind,
		"imap":      email.IMAPKind,
		"smtp":      email.SMTPKind,
		"redis":     redis.Kind,
		"postgres":  postgres.Kind,
		"ssh-agent": signer.SSHAgentKind,
		"gpg-agent": signer.GPGAgentKind,
	}
}
