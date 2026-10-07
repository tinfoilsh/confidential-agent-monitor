package monitor

write if {
	input.http.method
	not input.http.method in {"GET", "HEAD", "OPTIONS"}
}

route(pattern) if glob.match(pattern, ["/"], input.http.path)

mutation if input.graphql.kind == "mutation"

audiences := data.monitor.labels.audiences

# Each effect carries fixed obligations. An operation's obligations are the union over its effects.
vocabulary := {
	"read": {"change": false, "trust": false, "ask": false, "discloses": false},
	"session": {"change": false, "trust": false, "ask": false, "discloses": false},
	"write": {"change": true, "trust": false, "ask": false, "discloses": false},
	"generate": {"change": true, "trust": false, "ask": false, "discloses": false},
	"delete": {"change": true, "trust": true, "ask": false, "discloses": false},
	"admin": {"change": true, "trust": true, "ask": false, "discloses": false},
	"execute": {"change": true, "trust": true, "ask": false, "discloses": false},
	"send": {"change": true, "trust": true, "ask": false, "discloses": true},
	"share": {"change": true, "trust": true, "ask": false, "discloses": true},
	"publish": {"change": true, "trust": true, "ask": true, "discloses": true},
	"pay": {"change": true, "trust": true, "ask": true, "discloses": false},
}

# Module actions inherit effects from their nearest configured ancestor.
# Record operations keep their own effects even when they share an action.
action_effects(action) := [effects |
	path := split(action, ".")
	some i in numbers.range(count(path), 1)
	name := concat(".", array.slice(path, 0, i))
	effects := data.presets[input.account.preset].catalog.actions[name].effects
][0]

# A preset module owns recognition, including unknown requests and denials.
recognizer := handler if handler := data.handlers[input.account.preset]

else := data.handlers.mcp if input.mcp

else := data.monitor.api

op := recognizer.operation

default title := ""

title := recognizer.title

fields := {"id", "action", "effects", "scope", "grant", "trust", "sends", "reveals", "definition"}

valid if {
	is_object(op)
	every field, _ in op {
		field in fields
	}
	is_string(op.id)
	op.id != ""
	is_string(op.action)
	op.action != ""
	collection(op.effects)
	count(op.effects) > 0
	every e in op.effects {
		vocabulary[e]
	}
	is_object(op.scope)
	is_object(object.get(op, "grant", {}))
	is_boolean(object.get(op, "trust", false))
	audiences[object.get(op, "sends", "me")]
	is_object(object.get(op, "reveals", {}))
	every field, value in object.get(op, "reveals", {}) {
		revealed(field, value)
	}
}

revealed("contents", value) if audiences[value]

revealed("strangers", value) if is_boolean(value)

collection(x) if is_array(x)

collection(x) if is_set(x)

default action := null

action := op.action if valid

default operation := ""

operation := op.id if valid

effects := {e | some e in op.effects} if valid

else := set()

obligation(name) if {
	some e in effects
	vocabulary[e][name]
}

grant := object.get(op, "grant", op.scope) if valid

else := {}

scope := op.scope if valid

else := {}

# A saved approval trusts this digest: the policy program, the account's policy settings, the connection and its settings without secrets,
# the recognizer's reviewed input and the facts it resolved. Labels, saved rules and unrelated edits leave it unchanged.
definition := crypto.sha256(json.marshal([
	data.definitions.program,
	data.lattices,
	input.account.preset,
	object.get(input, "connection", ""),
	object.get(input, "connection_config", null),
	object.get(input.account, "policy_options", {}),
	[input.account.contents, input.account.strangers, input.account.sends],
	object.get(op, "definition", null),
	[sort([e | some e in effects]), object.get(op, "trust", false), sends, reveal],
])) if valid

else := ""

sends := op.sends if {
	valid
	op.sends
}

else := "anyone" if obligation("discloses")

else := input.account.sends

# An action is a dotted path, and the most specific setting along it wins.
lineage := [concat(".", array.slice(path, 0, i)) | path := split(action, "."); some i in numbers.range(count(path), 1)]

# Every mode but allow asks, so a value this chain does not expect fails closed.
mode := "off" if not input.access.level in {"read", "ask", "allow"}

else := "off" if {
	action == null
	input.access.level == "read"
}

else := "ask" if action == null

else := m if m := [o | some a in lineage; o := input.access.actions[a]][0]

else := "ask" if {
	input.access.level == "allow"
	obligation("ask")
}

else := "allow" if not obligation("change")

else := "off" if input.access.level == "read"

else := input.access.level

custom contains msg if some msg in data.sentinel.deny with input.action as action

deny contains msg if some msg in custom

deny contains msg if some msg in recognizer.deny

deny contains "this agent may not do this on the account" if mode == "off"

deny contains "the recognized operation is malformed" if {
	op
	not valid
}

needs_trust if action == null

needs_trust if obligation("trust")

needs_trust if {
	valid
	op.trust == true
}

gap contains "ask" if mode != "allow"

gap contains "audience" if {
	data.lattices.confidentiality
	not audiences[sends] <= audiences[input.label.audience]
}

gap contains "trust" if {
	data.lattices.integrity
	input.label.trust == "untrusted"
	needs_trust
}

# A saved approval names the operation and the definition it trusted; rules from before that bind nothing.
waived contains w if {
	some r in input.rules
	r.account == input.account.name
	r.action == action
	r.operation == op.id
	r.definition == definition
	r.scope == grant
	some w in r.waives
}

reveal := object.union({"contents": input.account.contents, "strangers": input.account.strangers}, object.get(op, "reveals", {})) if action != null

else := {"contents": "me", "strangers": true}

observed_trust := "untrusted" if reveal.strangers

else := "trusted"

next := data.monitor.labels.observe(input.label, {"audience": reveal.contents, "trust": observed_trust}, input.account.name)

decision := {"deny": custom} if input.tcp

else := {
	"deny": deny,
	"action": action,
	"operation": operation,
	"definition": definition,
	"effects": effects,
	"title": title,
	"scope": scope,
	"grant": grant,
	"sends": sends,
	"gaps": gap - waived,
	"next": next,
}
