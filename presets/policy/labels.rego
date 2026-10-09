package monitor.labels

audiences := {name: rank | some rank, name in levels.audiences}
trusts := {name: rank | some rank, name in levels.trusts}

valid(l) if {
	audiences[l.audience]
	trusts[l.trust]
}

flows_to(from, to) if {
	valid(from)
	valid(to)
	every axis, ranks in {"audience": audiences, "trust": trusts} {
		flow_axis(axis, ranks, from, to)
	}
}

enabled := {"audience": data.lattices.confidentiality, "trust": data.lattices.integrity}

flow_axis(axis, ranks, from, to) if not enabled[axis]
flow_axis(axis, ranks, from, to) if ranks[from[axis]] >= ranks[to[axis]]
