package templates.mcp

catalog := {
	"title": "MCP server",
	"fields": [
		{"key": "url", "label": "Server URL", "path": ["connections", "", "mcp", "url"]},
		{
			"key": "token",
			"label": "Token",
			"secret": true,
			"hint": "Leave empty to sign in",
			"oauth": {"resource": "{url}"},
			"path": ["connections", "", "mcp", "token"]
		}
	],
	"connections": {"": {"mcp": {"url": "{url}"}}},
	"defaults": {"contents": "team", "strangers": true, "sends": "me"},
	"actions": {"read": {"title": "Use read-only tools"}, "use": {"title": "Use tools that change things"}}
}

effects := {"read": {"read"}, "use": {"write"}}

action := sprintf("read.%s", [input.mcp.tool]) if input.mcp.read_only

action := sprintf("use.%s", [input.mcp.tool]) if {
	input.mcp
	not input.mcp.read_only
}

title := sprintf("Use %s", [input.mcp.tool])

operation := {
	"id": action, "action": action, "effects": effects[split(action, ".")[0]], "scope": {}, "trust": startswith(action, "use.")
}
