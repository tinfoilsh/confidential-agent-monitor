module github.com/tinfoilsh/confidential-agent-monitor/connector/web

go 1.27.3

require (
	github.com/coder/websocket v1.8.15
	github.com/tinfoilsh/confidential-agent-monitor v0.0.0
	github.com/vektah/gqlparser/v2 v2.5.58
)

replace github.com/tinfoilsh/confidential-agent-monitor => ../..
