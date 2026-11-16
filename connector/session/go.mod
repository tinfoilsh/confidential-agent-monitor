module github.com/tinfoilsh/confidential-agent-monitor/connector/session

go 1.27.3

require (
	github.com/tinfoilsh/confidential-agent-monitor v0.0.0
	golang.org/x/crypto v0.57.0
	mvdan.cc/sh/v3 v3.14.1
)

require golang.org/x/sys v0.48.0 // indirect

replace github.com/tinfoilsh/confidential-agent-monitor => ../..
