package handlers.custom_api

import data.monitor.action_effects

# The owner grants access to an API address, without claiming to know what its
# endpoints do. Even GET can change things, so every request needs use access.
in_scope if {
	some slot in input.connection_config.slots
	slot.origin == input.http.origin
	prefix := trim_suffix(object.get(slot, "path", "/"), "/")
	input.http.path == prefix
}

in_scope if {
	some slot in input.connection_config.slots
	slot.origin == input.http.origin
	prefix := trim_suffix(object.get(slot, "path", "/"), "/")
	startswith(input.http.path, concat("", [prefix, "/"]))
}

operation := {
	"id": "request", "action": "request", "effects": action_effects("request"),
	"scope": {"origin": input.http.origin, "method": input.http.method, "path": input.http.path},
	"grant": {"origin": input.http.origin}, "sends": input.account.sends,
} if in_scope

title := sprintf("%s %s%s", [input.http.method, input.http.origin, input.http.path])

deny contains "the request is outside this API's address" if {
	input.http
	not in_scope
}

deny contains "only HTTP requests reach a custom API" if not input.http
