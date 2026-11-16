module github.com/tinfoilsh/confidential-agent-monitor/connector/postgres

go 1.27.3

require (
	github.com/jackc/pgx/v5 v5.8.0
	github.com/tinfoilsh/confidential-agent-monitor v0.0.0
)

require (
	github.com/jackc/pgpassfile v1.0.0 // indirect
	github.com/jackc/pgservicefile v0.0.0-20240606120523-5a60cdf6a761 // indirect
	golang.org/x/text v0.42.0 // indirect
)

replace github.com/tinfoilsh/confidential-agent-monitor => ../..
