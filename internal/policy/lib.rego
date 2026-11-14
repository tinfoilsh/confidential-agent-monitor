package perimeter

import input.authorization as auth
import input.connection as conn
import input.facts
import input.facts.context as hint
import input.facts.context.label
import input.facts.operation as op

# Each axis orders its levels from most to least restrictive.
rank := {
	"audience": {name: i | some i, name in data.levels.audiences},
	"trust": {name: i | some i, name in data.levels.trusts},
}

obligations contains name if {
	some effect in op.effects
	some name, true in data.levels.effects[effect]
}

unknown if op == null
admission if facts.kind == "admission"
changes if "change" in obligations
discloses if "discloses" in obligations

default request := "read"

request := "unknown" if {
	unknown
} else := "change" if {
	changes
}

grants := {
	"read": {"unknown": "off", "read": "allow", "change": "off"},
	"ask": {"unknown": "ask", "read": "allow", "change": "ask"},
	"allow": {"unknown": "ask", "read": "allow", "change": "allow"},
}

# Lineage runs from the operation's own action up through its ancestors.
overrides := [m | some action in op.lineage; m := auth.access.actions[action]]

default mode := "off"

mode := overrides[0] if {
	overrides != []
} else := "allow" if {
	# A session opens to any service the bunker reaches.
	admission
	auth.reaches
} else := grants[auth.access.level][request] if {
	grants[auth.access.level]
}

effect_defaults := {effect: {true: "ask", false: "allow"}[o.ask] | some effect, o in data.levels.effects}

# Paid model operations carry both generate and pay; an explicit pay setting at any scope still wins.
paid := {"pay": "allow"} if {
	auth.allow_paid_inference
	"generate" in op.effects
	"pay" in op.effects
} else := {}

# Scopes run from global settings to this bunker's access on this service; the most specific wins.
effects := object.union_n(array.concat([effect_defaults, paid], auth.effects))

# A preset's public scope lists the parameters that together name one resource, such as owner and repo.
names := [v | some key in conn.public_scope; v := facts.parameters[key]; is_string(v); v != ""]

resource := concat("/", names) if {
	names != []
	count(names) == count(conn.public_scope)
}

# The owner marks resources private with globs such as tinfoilsh/*; any other named resource is public.
private if {
	some pattern in conn.private
	glob.match(pattern, ["/"], resource)
}

public if {
	resource
	not private
}

target := resource if changes

# A change to a public resource reaches anyone, whatever the connector hints; so does an unplaced disclosure.
sends := "anyone" if {
	changes
	public
} else := "anyone" if {
	hint.sends == ""
	discloses
	not target
} else := conn.sends if {
	hint.sends in {"", "connection"}
} else := hint.sends

expected := object.union(
	{"audience": conn.contents, "trust": {true: "untrusted", false: "trusted"}[conn.strangers]},
	{axis: level | some axis, _ in rank; level := hint.observes[axis]; level != ""},
)

# An unrecognized request may return anything; a public resource holds nothing private.
observes := {"audience": "me", "trust": "untrusted"} if {
	unknown
} else := object.union(expected, {"audience": "anyone"}) if {
	public
} else := expected

# The label keeps each axis's provenance unless this request makes it more restrictive.
lowered[axis] := level if {
	some axis, level in observes
	rank[axis][level] < rank[axis][label[axis]]
}

because := object.get(label, "because", {})

next := {
	"audience": object.get(lowered, "audience", label.audience),
	"trust": object.get(lowered, "trust", label.trust),
	"because": object.union(because, {axis: facts.connection | some axis, _ in lowered}),
}

# Owner policy is package sentinel. The base policy is package perimeter.base, which owner policy cannot change.
denies["owner"] := data.sentinel.deny

denies["base"] := data.perimeter.base.deny

collection(x) if is_array(x)

collection(x) if is_set(x)

approvals["owner"] := data.sentinel.approvals

approvals["base"] := data.perimeter.base.approvals

valid_approvals contains source if {
	some source, a in approvals
	collection(a)
	every r in a {
		regex.match(sprintf(`^%s\.[a-zA-Z0-9][a-zA-Z0-9_.-]*$`, [source]), r.id)
		trim_space(r.message) != ""
	}

	# Repeated identical entries are harmless; conflicting messages for one ID are not.
	count({r.id | some r in a}) == count({r | some r in a})
}

deny contains "This bunker does not have permission for this action." if mode == "off"

deny contains sprintf("The %s effect is set to Deny.", [effect]) if {
	some effect in op.effects
	effects[effect] == "off"
}

# Element types are checked when the decision is decoded; a wrong container would deny nothing.
deny contains sprintf("%s policy deny must be a set or array of strings", [source]) if {
	some source, hook in denies
	not collection(hook)
}

deny contains msg if some msg in denies[_]

deny contains sprintf("%s policy approvals must be a set or array of {id, message} objects with unique %s.* IDs and nonempty messages", [source, source]) if {
	some source, _ in approvals
	not source in valid_approvals
}

# A waiver of this gap covers only the audience it was approved for.
disclosure := concat(".", ["audience", sends])

needs_trust if unknown
needs_trust if "trust" in obligations

builtin contains "ask" if mode != "allow"

# Confidentiality: what the agent has seen goes to no wider an audience than its label.
builtin contains disclosure if {
	data.lattices.confidentiality
	not rank.audience[sends] <= rank.audience[label.audience]
}

# Integrity: an agent that has read untrusted content does nothing that requires trust.
builtin contains "trust" if {
	data.lattices.integrity
	label.trust == "untrusted"
	needs_trust
}

waived contains id if some id in auth.approved

waived contains requirement.id if {
	some r in auth.rules
	not r.enabled == false
	r.version == facts.version
	r.connection == facts.connection
	r.operation == op.id
	r.scope == auth.grant
	some requirement in r.requirements
}

base_gaps := builtin - waived if not admission
base_gaps := set() if admission

ask_message := sprintf("This request has no recognized operation on %s.", [facts.connection]) if unknown
ask_message := sprintf("This request needs your approval on %s.", [facts.connection]) if not unknown

recipients := {"me": "you", "team": "your team", "anyone": "anyone"}

messages := {
	"ask": ask_message,
	disclosure: sprintf("This agent has seen private data from %s; this request can disclose it to %s.", [object.get(because, "audience", "an earlier request"), object.get(recipients, sends, "an unknown audience")]),
	"trust": sprintf("This agent has read untrusted content from %s; this operation requires trust.", [object.get(because, "trust", "an earlier request")]),
}

requirements contains {"id": id, "message": message} if some id, message in object.filter(messages, base_gaps)

requirements contains {"id": id, "message": sprintf("The %s effect requires approval (Ask).", [effect])} if {
	some effect in op.effects
	effects[effect] == "ask"
	id := concat("", ["effect.", effect])
	not id in waived
}

requirements contains r if {
	some source in valid_approvals
	some r in approvals[source]
	not r.id in waived
}

gaps contains r.id if some r in requirements

decision := {"deny": deny, "requirements": requirements, "sends": sends, "next": next}

# input is an admin call: its caller and route, plus the answer and record of an answer.
default admin_allow := false

admin_allow if input.caller.owner

admin_allow if data.perimeter.base.admin_allow == true

admin_deny contains "The base policy does not allow this caller to make this call." if not admin_allow

admin_deny contains "base policy admin_deny must be a set or array of strings" if {
	hook := data.perimeter.base.admin_deny
	not collection(hook)
}

admin_deny contains msg if some msg in data.perimeter.base.admin_deny
