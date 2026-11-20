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
	# A session opens to any connection the bunker reaches.
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

# Scopes run from global settings to this bunker's access on this connection; the most specific wins.
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
# A request needs the allow of the owner policy, and of the base policy when the Perimeter is started with one.
needed := {true: {"owner", "base"}, false: {"owner"}}[data.base_policy]

allows contains "owner" if data.sentinel.allow == true

allows contains "base" if data.perimeter.base.allow == true

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

reasons contains "This bunker does not have permission for this action." if mode == "off"

reasons contains sprintf("The %s effect is set to Deny.", [effect]) if {
	some effect in op.effects
	effects[effect] == "off"
}

reasons contains sprintf("The %s policy does not allow this request.", [source]) if {
	some source in needed
	not source in allows
}

# A refused request that matched no operation says so, since that is usually why it was refused.
reasons contains ask_message if {
	unknown
	mode == "off"
}

reasons contains ask_message if {
	unknown
	some source in needed
	not source in allows
}

reasons contains sprintf("%s policy approvals must be a set or array of {id, message} objects with unique %s.* IDs and nonempty messages", [source, source]) if {
	some source, _ in approvals
	not source in valid_approvals
}

# A waiver of this gap covers only the audience it was approved for.
disclosure := concat(".", ["audience", sends])

needs_trust if unknown
needs_trust if "trust" in obligations

# Confidentiality: what the agent has seen goes to no wider an audience than its label.
confidentiality := "allow" if {
	data.lattices.confidentiality == false
} else := "allow" if {
	rank.audience[sends] <= rank.audience[label.audience]
} else := "ask"

# Integrity: an agent that has read untrusted content does nothing that requires trust.
integrity := "allow" if {
	data.lattices.integrity == false
} else := "allow" if {
	label.trust == "trusted"
} else := "allow" if {
	not needs_trust
} else := "ask"

standing := {"ask": mode, disclosure: confidentiality, "trust": integrity}

# Opening a session asks for nothing; its operations ask for themselves.
checks := object.union(standing, {id: "allow" | admission; some id, "ask" in standing})

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

# A check set to allow passes; one set to ask passes with the owner's approval of its ID, once or as a saved rule.
passes(_, "allow") := true

passes(id, "ask") if id in waived

base_gaps := {id | some id, "ask" in checks; not id in waived}

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

default allow := false

# Nothing else lets a request through. The reasons and requirements only say what is missing.
allow if {
	every id, setting in checks { passes(id, setting) }

	# An unrecognized request has no operation, and so no effects.
	every effect in [e | some e in op.effects] { passes(concat("", ["effect.", effect]), effects[effect]) }
	allows == needed
	every source, asked in approvals {
		source in valid_approvals
		every r in asked { r.id in waived }
	}
}

decision := {"allow": allow, "deny": reasons, "requirements": requirements, "sends": sends, "next": next}

# input is an admin call: its caller and route, plus the answer and record of an answer.
# An identity calling under the agent API's /admin/ is a non-owner caller whose claims are its key and groups.
default admin_allow := false

admin_allow if input.caller.owner

# An identity cannot answer its own request.
admin_allow if {
	data.perimeter.base.admin_allow == true
	not input.record.facts.principal.name == input.caller.name
}

# input is an identity's capability: its principal, its stored routes flag and the capability's name.
default capable := false

capable if input.routes

capable if data.perimeter.base.capable == true
