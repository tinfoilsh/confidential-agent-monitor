package monitor

import input.account as acct
import input.authorization as a
import input.facts as f
import input.facts.operation as op

audiences := {name: rank | some rank, name in data.levels.audiences}

ranks := {"audience": audiences, "trust": {name: rank | some rank, name in data.levels.trusts}}

obligation(name) if {
	some effect in op.effects
	data.levels.effects[effect][name]
}

mode := "off" if not a.access.level in {"read", "ask", "allow"}

else := "off" if {
	op == null
	a.access.level == "read"
}

else := "ask" if op == null

else := m if m := [v | some name in op.lineage; v := a.access.actions[name]][0]

else := "allow" if f.kind == "admission"

else := "allow" if not obligation("change")

else := "off" if a.access.level == "read"

else := a.access.level

# A request names a resource when every public scope parameter is a nonempty string.
scope := [v | some key in acct.public_scope; v := f.parameters[key]; is_string(v); v != ""]

scoped if {
	some _ in acct.public_scope
	count(scope) == count(acct.public_scope)
}

private if {
	some pattern in acct.private
	glob.match(pattern, ["/"], concat("/", scope))
}

public if {
	scoped
	not private
}

observation := {"audience": acct.contents, "trust": "untrusted"} if acct.strangers
else := {"audience": acct.contents, "trust": "trusted"}

hinted := object.union(observation, {k: v | some k in {"audience", "trust"}; v := f.context.observes[k]; v != ""})

observes := {"audience": "me", "trust": "untrusted"} if op == null
else := object.union(hinted, {"audience": "anyone"}) if public
else := hinted

sends := "anyone" if {
	public
	obligation("change")
} else := acct.sends if {
	scoped
	obligation("change")
	f.context.sends == ""
} else := "anyone" if {
	f.context.sends == ""
	obligation("discloses")
} else := acct.sends if f.context.sends in {"", "account"}
else := f.context.sends

# The label keeps each axis's provenance unless this request makes it more restrictive.
lowered contains axis if {
	some axis, rank in ranks
	rank[observes[axis]] < rank[f.context.label[axis]]
}

level(axis) := observes[axis] if axis in lowered
else := f.context.label[axis]

next := {
	"audience": level("audience"),
	"trust": level("trust"),
	"because": object.union(because, {axis: f.account | some axis in lowered}),
}

default owner_deny := []

owner_deny := data.sentinel.deny

# Element types are checked when the decision is decoded; a wrong container would deny nothing.
deny contains "owner policy deny must be a set or array of strings" if {
	not is_array(owner_deny)
	not is_set(owner_deny)
}

deny contains msg if some msg in owner_deny

deny contains "this agent may not do this on the account" if mode == "off"

deny contains sprintf("The %s effect is set to Deny.", [effect]) if {
	some effect in op.effects
	a.effects[effect] == "off"
}

needs_trust if op == null
needs_trust if obligation("trust")

gap contains "ask" if mode != "allow"

gap contains "audience" if {
	data.lattices.confidentiality
	not audiences[sends] <= audiences[f.context.label.audience]
}

gap contains "trust" if {
	data.lattices.integrity
	f.context.label.trust == "untrusted"
	needs_trust
}

waived contains w if {
	some r in a.rules
	object.get(r, "enabled", true)
	r.account == f.account
	r.definition == a.definition
	r.scope == a.grant
	some requirement in r.requirements
	w := requirement.id
}

base_gaps := set() if f.kind == "admission"

else := gap - waived

default owner_approvals := []

owner_approvals := data.sentinel.approvals

approval_collection if is_array(owner_approvals)
approval_collection if is_set(owner_approvals)

valid_owner_approvals if {
	approval_collection
	every r in owner_approvals {
		regex.match(`^owner\.[a-zA-Z0-9][a-zA-Z0-9_.-]*$`, r.id)
		trim_space(r.message) != ""
	}
	# Repeated identical entries are harmless; conflicting messages for one ID are not.
	count({r.id | some r in owner_approvals}) == count({r | some r in owner_approvals})
}

deny contains "owner policy approvals must be a set or array of {id, message} objects with unique owner.* IDs and nonempty messages" if not valid_owner_approvals

ask_message := sprintf("This request has no recognized operation on %s.", [f.account]) if op == null
else := sprintf("This request needs your approval on %s.", [f.account])

because := object.get(f.context.label, "because", {})
recipients := {"me": "you", "team": "your team", "anyone": "anyone"}

builtin_messages := {
	"ask": ask_message,
	"audience": sprintf("This agent has seen private data from %s; this request can disclose it to %s.", [object.get(because, "audience", "an earlier request"), object.get(recipients, sends, "an unknown audience")]),
	"trust": sprintf("This agent has read untrusted content from %s; this operation requires trust.", [object.get(because, "trust", "an earlier request")]),
}

reasons contains {"id": id, "message": builtin_messages[id]} if some id in base_gaps

reasons contains {"id": id, "message": sprintf("The %s effect requires approval (Ask).", [effect])} if {
	some effect in op.effects
	a.effects[effect] == "ask"
	id := concat("", ["effect.", effect])
	not id in waived
}

reasons contains r if {
	valid_owner_approvals
	some r in owner_approvals
	not r.id in waived
}

gaps := {r.id | some r in reasons}

decision := {"deny": deny, "requirements": reasons, "sends": sends, "next": next}
