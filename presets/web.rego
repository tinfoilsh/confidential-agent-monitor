package handlers.web

import data.monitor.action_effects
import data.monitor.write

action := "submit" if write

action := "browse" if {
	input.http
	not write
}

scope := {"host": input.http.host}

operation := {
	"id": action, "action": action, "effects": action_effects(action), "scope": scope,
}

title := sprintf("%s %s%s", [input.http.method, input.http.host, input.http.path])
