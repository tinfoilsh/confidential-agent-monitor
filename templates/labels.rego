package monitor.labels

audiences := {"me": 0, "team": 1, "anyone": 2}
trusts := {"untrusted": 0, "trusted": 1}

valid(l) if {
	audiences[l.audience]
	trusts[l.trust]
}

flows_to(from, to) if {
	audiences[from.audience] >= audiences[to.audience]
	trusts[from.trust] >= trusts[to.trust]
}

lowered(current, observed) := {axis |
	some axis, levels in {"audience": audiences, "trust": trusts}
	levels[observed[axis]] < levels[current[axis]]
}

observe(current, observed, because) := object.union(current, object.union(values, {"because": reasons})) if {
	axes := lowered(current, observed)
	values := {axis: observed[axis] | some axis in axes}
	reasons := object.union(object.get(current, "because", {}), {axis: because | some axis in axes})
}
