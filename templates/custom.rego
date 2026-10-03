package templates.custom

catalog := {
	"title": "Custom",
	"fields": [
		{"key": "connections", "label": "Connections", "json": true, "path": ["connections"]}
	],
	"defaults": {"contents": "me", "strangers": false, "sends": "me"},
	"actions": {}
}

# A Custom account has no actions of its own; the owner's policies may name them.
action := data.sentinel.action

changes := data.sentinel.changes

needs_trust := data.sentinel.needs_trust
