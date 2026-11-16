module github.com/tinfoilsh/confidential-agent-monitor/connector/mqtt

go 1.27.3

require (
	github.com/eclipse/paho.mqtt.golang v1.5.1
	github.com/tinfoilsh/confidential-agent-monitor v0.0.0
)

replace github.com/tinfoilsh/confidential-agent-monitor => ../..
