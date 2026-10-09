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

base_gaps := set() if f.kind in {"admission", "message"}

else := gap - waived

default owner_approvals := []

owner_approvals := data.sentinel.approvals

approval_collection if is_array(owner_approvals)
approval_collection if is_set(owner_approvals)

valid_owner_approvals if {
	approval_collection
	every r in owner_approvals {
		is_object(r)
		object.keys(r) == {"id", "message"}
		is_string(r.id)
		regex.match(`^owner\.[a-zA-Z0-9][a-zA-Z0-9_.-]*$`, r.id)
		is_string(r.message)
		trim_space(r.message) != ""
	}
	# Repeated identical entries are harmless; conflicting messages for one ID are not.
	count({r.id | some r in owner_approvals}) == count({r | some r in owner_approvals})
}

deny contains "owner policy approvals must be a set or array of {id, message} objects with unique owner.* IDs and nonempty messages" if not valid_owner_approvals

# Messages cannot wait for interactive approval.
deny contains sprintf("Message delivery requires approval: %s", [r.message]) if {
	f.kind == "message"
	valid_owner_approvals
	some r in owner_approvals
}

ask_message := sprintf("This request has no recognized operation on %s.", [f.account]) if op == null
else := sprintf("This request needs your approval on %s.", [f.account])

because := object.get(f.context.label, "because", {})
recipients := {"me": "you", "team": "your team", "anyone": "anyone"}

builtin_messages := {
	"ask": ask_message,
	"audience": sprintf("This agent has seen private data from %s; this request can disclose it to %s.", [object.get(because, "audience", "an earlier request"), object.get(recipients, f.context.sends, "an unknown audience")]),
	"trust": sprintf("This agent has read untrusted content from %s; this operation requires trust.", [object.get(because, "trust", "an earlier request")]),
}

reasons contains {"id": id, "message": builtin_messages[id]} if some id in base_gaps

reasons contains r if {
	f.kind != "message"
	valid_owner_approvals
	some r in owner_approvals
	not r.id in waived
}

gaps := {r.id | some r in reasons}

decision := {"deny": deny, "gaps": gaps, "reasons": reasons}
