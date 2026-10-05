package monitor.messages

# Channel writes use label flow, without the connector send effect's trust requirement.
deny contains msg if some msg in data.sentinel.deny

deny contains "the agent's label cannot flow to this message channel" if not data.monitor.labels.valid(input.label)

deny contains "the agent's label cannot flow to this message channel" if {
	input.action != "message.receive"
	not data.monitor.labels.flows_to(input.label, input.channel_label)
}

decision := {
	"deny": deny,
	"next": data.monitor.labels.observe(input.label, input.channel_label, input.cause),
}
