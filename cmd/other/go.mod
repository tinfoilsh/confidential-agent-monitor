module github.com/tinfoilsh/confidential-agent-monitor/cmd/other

go 1.27.3

require (
	github.com/cedar-policy/cedar-go v1.9.2
	github.com/tinfoilsh/confidential-agent-monitor v0.0.0
	github.com/tinfoilsh/confidential-agent-monitor/connector/postgres v0.0.0
	golang.org/x/crypto v0.57.0
)

require (
	code.dny.dev/ssrf v0.3.0 // indirect
	github.com/go-json-experiment/json v1.27.2 // indirect
	github.com/jackc/pgpassfile v1.0.0 // indirect
	github.com/jackc/pgservicefile v0.0.0-20240606120523-5a60cdf6a761 // indirect
	github.com/jackc/pgx/v5 v5.8.0 // indirect
	golang.org/x/exp v0.0.0-20220921023135-46d9e7742f1e // indirect
	golang.org/x/sys v0.48.0 // indirect
	golang.org/x/text v0.42.0 // indirect
)

replace (
	github.com/tinfoilsh/confidential-agent-monitor => ../..
	github.com/tinfoilsh/confidential-agent-monitor/connector/postgres => ../../connector/postgres
)
