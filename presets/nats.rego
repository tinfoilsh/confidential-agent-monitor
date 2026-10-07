package handlers.nats

import data.monitor.action_effects

command := input.nats.command
queue := object.get(input.nats, "queue", "")

action := "connect" if command == "connect"
action := command if { command in {"subscribe", "receive"}; queue == "" }
action := "consume" if { command in {"subscribe", "receive"}; queue != "" }

# Reserved subjects can change broker state, acknowledge durable work, or invoke
# service controls. Treat all $ subjects conservatively rather than guessing.
control if startswith(input.nats.subject, "$")
control if {
	some name, _ in object.get(input.nats, "headers", {})
	startswith(lower(name), "nats-")
}
action := "admin" if { command == "publish"; control }
action := "publish" if { command == "publish"; not control }

operation := {"id": command, "action": action, "effects": action_effects(action), "scope": input.nats, "sends": input.account.sends, "trust": action == "consume"}
title := sprintf("NATS %s %s", [command, input.nats.subject])
