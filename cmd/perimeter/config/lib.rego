package perimeter

import input.authorization as auth
import input.connection as conn
import input.facts
import input.facts.flow
import input.facts.label
import input.facts.operation as op

# Each axis orders its levels from most to least restrictive.
rank := {
	"audience": {name: i | some i, name in data.levels.audiences},
	"trust": {name: i | some i, name in data.levels.trusts},
}

admission if facts.kind == "admission"

# An admission has no operation either, but is not an unrecognized request; an operation without effects is.
unknown if {
	not admission
	not has_effects
}

has_effects if count(op.effects) != 0

effects_of := ["session"] if {
	admission
} else := ["unknown"] if {
	unknown
} else := op.effects

# Each effect's place in the two lattices, as Vocabulary in policy.go lists it.
traits := [data.levels.effects[effect] | some effect in effects_of]

# Delivered data is also stored where it lands, such as a post in a public channel.
stores if {
	some t in traits
	t.confidentiality in {"stored", "delivered"}
}

delivers if {
	some t in traits
	t.confidentiality == "delivered"
}

denied_mode := {"mode": "off", "from": "the Perimeter"}

mode_of(effect) := object.get(auth.modes, effect, denied_mode)

# A preset's resource lists the parameters that together name one resource, such as owner and repo.
names := [v | some key in conn.resource; v := facts.parameters[key]; is_string(v); v != ""]

resource := concat("/", names) if {
	names != []
	count(names) == count(conn.resource)
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

target := resource if stores

# Data stored in a public resource reaches anyone, whatever the connector hints; so does a delivery to unnamed recipients.
sends_to := "anyone" if {
	stores
	public
} else := "anyone" if {
	flow.sends_to == ""
	delivers
	not target
} else := "anyone" if {
	some to in facts.details.smtp.to
	not same_address(to, conn.address)
} else := conn.sends_to if {
	flow.sends_to in {"", "connection"}
} else := flow.sends_to

# (?i) folds case as Go's strings.EqualFold does; lower() does not for every rune.
same_address(a, b) if regex.match(concat("", [`(?i)\A\Q`, replace(b, `\E`, `\E\\E\Q`), `\E\z`]), a)

# What the connection returns, overridden axis by axis by what the connector says this request returns.
stated := object.union(
	{axis: conn.returns[axis] | some axis, _ in rank},
	{axis: level | some axis, _ in rank; level := flow.returns[axis]; level != ""},
)

# An unrecognized request may return anything; a public resource holds nothing private.
returns := {"audience": "me", "trust": "untrusted"} if {
	unknown
} else := object.union(stated, {"audience": "anyone"}) if {
	public
} else := stated

# The label keeps each axis's provenance unless this request makes it more restrictive.
lowered[axis] := level if {
	some axis, level in returns
	rank[axis][level] < rank[axis][label[axis]]
}

because := object.get(label, "because", {})

# An admission exposes nothing, so it keeps the label as it is.
next := label if {
	admission
} else := {
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

# Anything but allow or ask is off, so a malformed mode refuses.
off contains effect if {
	some effect in effects_of
	not mode_of(effect).mode in {"allow", "ask"}
}

denied_by[from] contains effect if {
	some effect in off
	from := mode_of(effect).from
}

reasons contains sprintf("Set to Deny by %s: %s.", [from, concat(", ", sort(effects))]) if some from, effects in denied_by

reasons contains sprintf("The %s policy does not allow this request.", [source]) if {
	some source in needed
	not source in allows
}

# A refused request that matched no operation says so, since that is usually why it was refused.
reasons contains unknown_message if "unknown" in off

reasons contains unknown_message if {
	unknown
	some source in needed
	not source in allows
}

reasons contains "WebSocket requests require a reviewed operation." if {
	unknown
	facts.details.http.websocket == true
}

reasons contains sprintf("%s policy approvals must be a set or array of {id, message} objects with unique %s.* IDs and nonempty messages", [source, source]) if {
	some source, _ in approvals
	not source in valid_approvals
}

perimeter_action := op.action if facts.connection == "perimeter"

reasons contains "An identity cannot answer, save, or approve its own request." if {
	perimeter_action in {"requests.answer", "requests.save", "proposals.answer"}
	facts.parameters.subject == facts.principal.name
}

reasons contains "An identity cannot write its own label." if {
	perimeter_action == "labels.write"
	facts.parameters.identity == facts.principal.name
}

reasons contains "An identity cannot enroll itself." if {
	perimeter_action == "enroll"
	facts.principal.name in facts.parameters.identities
}

reasons contains "An identity cannot enroll itself." if {
	perimeter_action == "enroll"
	facts.principal.key in facts.parameters.keys
}

# A waiver of this gap covers only the audience it was approved for.
disclosure := concat(".", ["audience", sends_to])

needs_trust if {
	some t in traits
	t.integrity
}

# Confidentiality: what the agent has seen goes to no wider an audience than its label.
confidentiality := "allow" if {
	data.lattices.confidentiality == false
} else := "allow" if {
	rank.audience[sends_to] <= rank.audience[label.audience]
} else := "ask"

# Integrity: an agent that has read untrusted content does nothing that requires trust.
integrity := "allow" if {
	data.lattices.integrity == false
} else := "allow" if {
	label.trust == "trusted"
} else := "allow" if {
	not needs_trust
} else := "ask"

standing := {disclosure: confidentiality, "trust": integrity}

waived contains id if some id in auth.approved

# Go passes only rules that are not stale.
waived contains requirement.id if {
	some r in auth.rules
	not r.enabled == false
	r.connection == facts.connection
	r.operation == op.id
	r.scope == auth.scope
	some requirement in r.requirements
}

# Opening a session asks nothing of the lattices; its operations ask for themselves.
base_gaps := {id | not admission; some id, "ask" in standing; not id in waived}

unknown_message := sprintf("This request has no recognized operation on %s.", [facts.connection])

recipients := {"me": "you", "team": "your team", "anyone": "anyone"}

messages := {
	disclosure: sprintf("This agent has seen private data from %s; this request can disclose it to %s.", [object.get(because, "audience", "an earlier request"), object.get(recipients, sends_to, "an unknown audience")]),
	"trust": sprintf("This agent has read untrusted content from %s; this operation requires trust.", [object.get(because, "trust", "an earlier request")]),
}

requirements contains {"id": id, "message": message} if some id, message in object.filter(messages, base_gaps)

effect_message("unknown") := unknown_message

effect_message(effect) := sprintf("The %s effect requires approval (Ask).", [effect]) if effect != "unknown"

requirements contains {"id": id, "message": effect_message(effect)} if {
	some effect in effects_of
	mode_of(effect).mode == "ask"
	id := concat("", ["effect.", effect])
	not id in waived
}

requirements contains r if {
	some source in valid_approvals
	some r in approvals[source]
	not r.id in waived
}

gaps contains r.id if some r in requirements

decision := {"outcome": "deny", "sends_to": sends_to, "reasons": reasons} if {
	count(reasons) != 0
} else := {"outcome": "ask", "sends_to": sends_to, "gaps": requirements} if {
	count(requirements) != 0
} else := {"outcome": "allow", "sends_to": sends_to, "next": next}
