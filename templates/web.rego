package templates.web

catalog := {
	"title": "Web",
	"fields": [],
	"connections": {"": {"http": {"hosts": ["*"]}}},
	"defaults": {"contents": "anyone", "strangers": true, "sends": "anyone"},
	"actions": {
		"browse": {"title": "Browse", "save": "Trust {host} with this agent's data"},
		"submit": {"title": "Submit forms and post", "save": "Allow posting to {host}"}
	}
}

import data.monitor.write

changes := {"submit"}

needs_trust := {"submit"}

action := "submit" if write

action := "browse" if {
	input.http
	not write
}

scope := {"host": input.http.host}

title := sprintf("%s %s%s", [input.http.method, input.http.host, input.http.path])
