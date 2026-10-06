package templates.browser

catalog := {
	"title": "Browser",
	"fields": [],
	"connections": {"": {"browser": {}}},
	"defaults": {"contents": "anyone", "strangers": true, "sends": "anyone"},
	"actions": {
		"browse": {"title": "Open and read pages"},
		"submit": {"title": "Click and type"},
		"login": {"title": "Fill saved credentials"}
	}
}

effects := {"browse": {"read"}, "submit": {"send"}, "login": {"session", "write"}}

login if count(object.get(input.browser, "secrets", [])) > 0

action := "browse" if input.browser.command in {"navigate", "snapshot", "text", "screenshot"}

action := "submit" if {
	input.browser.command in {"click", "type", "fill"}
	not login
}

action := "login" if login

scope := {"host": input.browser.host, "secrets": input.browser.secrets} if login
else := {"host": input.browser.host}

# english-only censors every reply, so without credentials a read reveals what anyone may see.
operation := object.union(base, {"reveals": {"contents": "anyone"}}) if count(object.get(input, ["connection_config", "slots"], [])) == 0
else := base

base := {"id": action, "action": action, "effects": effects[action], "scope": scope, "trust": action == "login"}

title := sprintf("%s %s", [input.browser.command, input.browser.url])
