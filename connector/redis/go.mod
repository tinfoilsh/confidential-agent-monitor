module github.com/tinfoilsh/confidential-agent-monitor/connector/redis

go 1.27.3

require (
	github.com/tidwall/redcon v1.6.4
	github.com/tinfoilsh/confidential-agent-monitor v0.0.0
)

require (
	github.com/tidwall/btree v1.1.0 // indirect
	github.com/tidwall/match v1.2.0 // indirect
)

replace github.com/tinfoilsh/confidential-agent-monitor => ../..
