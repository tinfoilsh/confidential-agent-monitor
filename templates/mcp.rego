package templates.mcp

catalog := {
	"title": "MCP server",
	"fields": [{"key": "url", "label": "Server URL"}, {"key": "token", "label": "Token", "secret": true, "hint": "Leave empty to sign in", "oauth": {"resource": "{url}"}}],
	"connections": {"": {"mcp": {"url": "{url}", "token": {"$secret": "token"}}}},
	"defaults": {"contents": "team", "strangers": true, "sends": "me"},
	"actions": {
		"read": {"title": "Use read-only tools"},
		"use": {"title": "Use tools that change things", "save": "Allow {tool}"},
	},
}

changes := {"use"}

needs_trust := {"use"}

action := "read" if input.mcp.read_only

action := "use" if {
	input.mcp
	not input.mcp.read_only
}

scope := {"tool": input.mcp.tool}

title := sprintf("Use %s", [input.mcp.tool])
