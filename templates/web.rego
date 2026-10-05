package templates.web

catalog := {
	"title": "Web",
	"fields": [],
	"connections": {"": {"http": {"hosts": ["*"]}}},
	"defaults": {"contents": "anyone", "strangers": true, "sends": "anyone"},
	"actions": {
		"browse": {"title": "Browse"},
		"submit": {"title": "Submit forms and post"}
	}
}

import data.monitor.write

effects := {"browse": {"read"}, "submit": {"send"}}

action := "submit" if write

action := "browse" if {
	input.http
	not write
}

scope := {"host": input.http.host}

operation := {
	"id": action, "action": action, "effects": effects[action], "scope": scope
}

title := sprintf("%s %s%s", [input.http.method, input.http.host, input.http.path])
