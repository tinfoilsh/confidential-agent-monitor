package monitor

import data.monitor.labels.audiences
import input.authorization as a
import input.facts as f
import input.facts.operation as op
import input.facts.operation.action as action

obligation(name) if {
	some e in op.effects
	vocabulary[e][name]
}

lineage := [concat(".", array.slice(parts, 0, i)) | parts := split(action, "."); some i in numbers.range(count(parts), 1)]

mode := "off" if not a.access.level in {"read", "ask", "allow"}

else := "off" if {
	op == null
	a.access.level == "read"
}

else := "ask" if op == null

else := m if m := [v | some name in lineage; v := a.access.actions[name]][0]

else := "allow" if f.kind == "admission"

else := "ask" if {
	a.access.level == "allow"
	obligation("ask")
}

else := "allow" if not obligation("change")

else := "off" if a.access.level == "read"

else := a.access.level

default owner_deny := []

owner_deny := data.sentinel.deny

valid_owner_deny if {
	is_array(owner_deny)
	every msg in owner_deny { is_string(msg) }
}

valid_owner_deny if {
	is_set(owner_deny)
	every msg in owner_deny { is_string(msg) }
}

deny contains "owner policy deny must be a set or array of strings" if not valid_owner_deny

deny contains msg if {
	valid_owner_deny
	some msg in owner_deny
}

deny contains msg if some msg in a.errors
deny contains "this agent may not do this on the account" if mode == "off"

needs_trust if op == null
needs_trust if obligation("trust")
needs_trust if op.requires_trust

gap contains "ask" if mode != "allow"

gap contains "audience" if {
	data.lattices.confidentiality
	not audiences[f.context.sends] <= audiences[f.context.label.audience]
}

gap contains "trust" if {
	data.lattices.integrity
	f.context.label.trust == "untrusted"
	needs_trust
}

waived contains w if {
	some r in a.rules
	r.account == f.account
	r.action == action
	r.operation == op.id
	r.definition == a.definition
	r.scope == a.grant
	some w in r.waives
}

deny contains "the agent's label cannot flow to this message channel" if {
	f.kind == "message"
	action != "message.receive"
	not data.monitor.labels.flows_to(f.context.label, f.context.channel)
}

gaps := set() if f.kind in {"admission", "message"}

else := gap - waived

decision := {"deny": deny, "gaps": gaps}
