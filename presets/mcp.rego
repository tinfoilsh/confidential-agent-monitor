package handlers.mcp

import data.monitor.action_effects

action := sprintf("read.%s", [input.mcp.tool]) if input.mcp.read_only

action := sprintf("use.%s", [input.mcp.tool]) if {
	input.mcp
	not input.mcp.read_only
}

title := sprintf("Use %s", [input.mcp.tool])

operation := {
	"id": action, "action": action, "effects": action_effects(action), "scope": {}, "trust": startswith(action, "use."),
}
