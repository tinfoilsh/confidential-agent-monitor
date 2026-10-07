package handlers.mqtt

import data.monitor.action_effects

command := input.mqtt.command
action := command if command in {"connect", "subscribe", "receive"}
action := "publish" if { command == "publish"; not input.mqtt.retain }
action := "retain" if { command == "publish"; input.mqtt.retain }

# Publishing sends data to the configured broker's audience. Payload and retain
# flag bind approvals, so a command approval cannot authorize another payload.
operation := {"id": command, "action": action, "effects": action_effects(action), "scope": input.mqtt, "sends": input.account.sends}
title := sprintf("MQTT %s %s", [command, input.mqtt.topic])
