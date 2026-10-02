package monitor

write if {
	input.http.method
	not input.http.method in {"GET", "HEAD", "OPTIONS"}
}

route(pattern) if glob.match(pattern, ["/"], input.http.path)

mutation if input.graphql.kind == "mutation"

audiences := {"me": 0, "team": 1, "anyone": 2}

t := data.templates[input.account.template]

default action := null

action := t.action

changes := object.get(t, "changes", set())

scope := object.get(t, "scope", {})

sends := object.get(t, "sends", input.account.sends)

# Every mode but allow asks, so a value this chain does not expect fails closed.
mode := "off" if not input.access.level in {"read", "ask", "allow"}
else := "off" if {
	action == null
	input.access.level == "read"
}
else := "ask" if action == null
else := m if m := input.access.actions[action]
else := "allow" if not action in changes
else := "off" if input.access.level == "read"
else := input.access.level

custom contains msg if some msg in data.sentinel.deny with input.action as action

deny contains msg if some msg in custom

deny contains msg if some msg in t.deny

deny contains "this agent may not do this on the account" if mode == "off"

needs_trust if action == null

needs_trust if action in object.get(t, "needs_trust", set())

gap contains "ask" if mode != "allow"

gap contains "audience" if not audiences[sends] <= audiences[input.label.audience]

gap contains "trust" if {
	input.label.trust == "untrusted"
	needs_trust
}

waived contains w if {
	some r in input.rules
	r.account == input.account.name
	r.action == action
	r.scope == scope
	some w in r.waives
}

reveal := object.union({"contents": input.account.contents, "strangers": input.account.strangers}, object.get(t, "reveals", {})) if action != null
else := {"contents": "me", "strangers": true}

lowered contains "audience" if audiences[reveal.contents] < audiences[input.label.audience]

lowered contains "trust" if {
	reveal.strangers
	input.label.trust == "trusted"
}

trust := "untrusted" if "trust" in lowered
else := input.label.trust

audience := reveal.contents if "audience" in lowered
else := input.label.audience

next := {
	"trust": trust,
	"audience": audience,
	"because": object.union(object.get(input.label, "because", {}), {g: input.account.name | some g in lowered}),
}

decision := {"deny": custom} if input.tcp
else := {
	"deny": deny,
	"action": action,
	"title": object.get(t, "title", ""),
	"scope": scope,
	"sends": sends,
	"gaps": gap - waived,
	"next": next,
}
