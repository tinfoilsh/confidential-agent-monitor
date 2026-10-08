package monitor

f := input.facts
a := input.authorization
op := f.operation
action := op.action

audiences := data.monitor.labels.audiences
obligation(name) if { some e in op.effects; vocabulary[e][name] }

lineage := [concat(".", array.slice(parts, 0, i)) | parts := split(action, "."); some i in numbers.range(count(parts), 1)]

mode := "off" if not a.access.level in {"read", "ask", "allow"}
else := "off" if { op == null; a.access.level == "read" }
else := "ask" if op == null
else := m if m := [v | some name in lineage; v := a.access.actions[name]][0]
else := "allow" if f.kind == "admission"
else := "ask" if { a.access.level == "allow"; obligation("ask") }
else := "allow" if not obligation("change")
else := "off" if a.access.level == "read"
else := a.access.level

deny contains msg if some msg in data.sentinel.deny
deny contains msg if some msg in a.errors
deny contains "this agent may not do this on the account" if mode == "off"

needs_trust if op == null
needs_trust if obligation("trust")
needs_trust if op.requires_trust

gap contains "ask" if mode != "allow"
gap contains "audience" if { data.lattices.confidentiality; not audiences[f.context.sends] <= audiences[f.context.label.audience] }
gap contains "trust" if { data.lattices.integrity; f.context.label.trust == "untrusted"; needs_trust }

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

decision := {"deny": deny, "gaps": []} if f.kind in {"admission", "message"}
else := {"deny": deny, "gaps": gap - waived}
