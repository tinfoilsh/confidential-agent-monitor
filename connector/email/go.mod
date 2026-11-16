module github.com/tinfoilsh/confidential-agent-monitor/connector/email

go 1.27.3

require (
	github.com/emersion/go-sasl v0.0.0-20241020182733-b788ff22d5a6
	github.com/emersion/go-smtp v0.25.0
	github.com/tinfoilsh/confidential-agent-monitor v0.0.0
)

replace github.com/tinfoilsh/confidential-agent-monitor => ../..
