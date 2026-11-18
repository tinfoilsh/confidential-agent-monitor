module github.com/tinfoilsh/confidential-agent-monitor/cmd/slackreview

go 1.27.3

require (
	github.com/slack-go/slack v0.36.0
	github.com/tinfoilsh/confidential-agent-monitor v0.0.0
	github.com/tinfoilsh/confidential-agent-monitor/connector/postgres v0.0.0
	golang.org/x/crypto v0.57.0
)

require (
	code.dny.dev/ssrf v0.3.0 // indirect
	github.com/gorilla/websocket v1.5.3 // indirect
	github.com/jackc/pgpassfile v1.0.0 // indirect
	github.com/jackc/pgservicefile v0.0.0-20240606120523-5a60cdf6a761 // indirect
	github.com/jackc/pgx/v5 v5.8.0 // indirect
	golang.org/x/sys v0.48.0 // indirect
	golang.org/x/text v0.42.0 // indirect
)

replace (
	github.com/tinfoilsh/confidential-agent-monitor => ../..
	github.com/tinfoilsh/confidential-agent-monitor/connector/postgres => ../../connector/postgres
)
