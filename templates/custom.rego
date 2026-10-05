package templates.custom

catalog := {
	"title": "Custom",
	"fields": [
		{"key": "connections", "label": "Connections", "json": true, "path": ["connections"]}
	],
	"defaults": {"contents": "me", "strangers": false, "sends": "me"},
	"actions": {}
}

# A Custom account has no actions of its own; the owner's policies recognize operations.
operation := data.sentinel.operation
