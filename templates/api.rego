package templates.api

# An account names a preset in data.presets, whose operations are checked by malformed when the monitor starts.
# Only its operations are allowed, and each request must match exactly one of them.

options := input.account.policy_options

service := data.presets[options.preset]

# A record is data, so anything this template would not read is refused rather than ignored.
operation_keys := {"id", "action", "effects", "method", "origin", "path", "query", "headers", "fields", "params", "open_params", "body", "graphql", "scope", "grant"}

well_formed(o) if {
	every key, _ in o {
		key in operation_keys
	}
	is_array(o.effects)
	every e in o.effects {
		data.monitor.vocabulary[e]
	}
	is_object(o.scope)
	every _, spec in o.scope {
		is_string(spec.from)
	}
	is_array(object.get(o, "grant", []))
	every k in object.get(o, "grant", []) {
		o.scope[k]
	}
	is_array(object.get(o, "params", []))
	every m in ["query", "headers", "fields"] {
		is_object(object.get(o, m, {}))
	}
	graphql_body(o)
}

graphql_body(o) if not "graphql" in object.keys(o)

graphql_body(o) if o.body == "graphql"

malformed contains [name, object.get(o, "id", i)] if {
	some name, s in data.presets
	some i, o in s.operations
	not well_formed(o)
}

matches := [o | some o in service.operations; matched(o)]

record := matches[0] if count(matches) == 1

scope := {name: v |
	some name, spec in record.scope
	v := extract(spec)
	type_name(v) == object.get(spec, "type", "string")
}

# Every change needs trust. A saved approval binds the listed grant fields, or every scope field,
# and the exact record defines the operation.
operation := {
	"id": record.id,
	"action": record.action,
	"effects": record.effects,
	"scope": scope,
	"grant": {k: scope[k] | some k in object.get(record, "grant", object.keys(record.scope))},
	"trust": count({e | some e in record.effects; e != "read"}) > 0,
	"definition": record,
}

title := sprintf("%s: %s", [service.title, record.id])

# A request no operation matches is the unreviewed action, off until an agent's access names it.
operation := {
	"id": "unreviewed",
	"action": "unreviewed",
	"effects": [unreviewed_effect],
	"scope": {"method": input.http.method, "path": input.http.path},
	"definition": {"origin": input.http.origin},
} if count(matches) == 0

unreviewed_effect := "send" if data.monitor.write
else := "read"

title := sprintf("%s: %s %s", [service.title, input.http.method, input.http.path]) if count(matches) == 0

deny contains "the account names no service record" if not service

deny contains "only HTTP requests reach a service" if not input.http

deny contains "the request matches no reviewed operation" if {
	service
	count(matches) == 0
	not input.access.actions.unreviewed
}

deny contains "the service record is malformed" if {
	some o in service.operations
	not well_formed(o)
}

deny contains "the request matches more than one reviewed operation" if count(matches) > 1

deny contains sprintf("the request has no %s of the expected type", [name]) if {
	some name, _ in record.scope
	not name in object.keys(scope)
}

matched(o) if {
	o.method == input.http.method
	origin(o) == input.http.origin
	captures(o.path)
	every key, value in object.get(o, "query", {}) {
		condition(input.http.query, key, value)
	}
	every key, value in object.get(o, "headers", {}) {
		condition({lower(k): v | some k, v in input.http.headers}, lower(key), value)
	}
	every key, value in object.get(o, "fields", {}) {
		field(o.body, key, value)
	}
	every key, _ in input.http.query {
		param(o, key)
	}
	body(object.get(o, "body", "none"), o)
}

# Query keys outside query and params are refused unless open_params says otherwise.
param(o, _) if o.open_params == true

param(o, key) if key in object.get(o, "params", [])

param(o, key) if key in object.keys(object.get(o, "query", {}))

# A string must be the only value; null requires absence.
condition(values, key, value) if {
	value == null
	not values[key]
}

condition(values, key, value) if {
	is_string(value)
	values[key] == [value]
}

# A tenant record's origin is the one the owner chose for the account.
origin(o) := o.origin if o.origin != "{origin}"

origin(o) := options.origin if o.origin == "{origin}"

field("form", key, value) if condition(object.get(input.http, "form", {}), key, value)

field("json", at, value) if {
	value != null
	pointer(input.http.body, at) == value
}

# A null condition requires the member to be absent, not present with a null value.
field("json", at, null) if {
	object.get(input.http.body, steps(at), false) == false
	object.get(input.http.body, steps(at), true) == true
}

body("none", _) if input.http.body_kind == "none"

body("json", _) if input.http.body_kind == "json"

body("form", _) if input.http.body_kind == "form"

body("any", _)

body("graphql", o) if {
	input.http.body_kind == "json"
	count(input.graphql.fields) == 1
	input.graphql.kind == o.graphql.operation
	input.graphql.fields[0].name == o.graphql.field
}

# Pattern segments are literals or prefix{name}suffix; a final {name*} takes the rest of the path.
captures(pattern) := c if {
	not endswith(pattern, "*}")
	c := segments(split(pattern, "/"), split(input.http.path, "/"))
}

captures(pattern) := object.union(segments(head, array.slice(parts, 0, n)), {name: rest}) if {
	endswith(pattern, "*}")
	all := split(pattern, "/")
	n := count(all) - 1
	head := array.slice(all, 0, n)
	name := trim_suffix(trim_prefix(all[n], "{"), "*}")
	parts := split(input.http.path, "/")
	count(parts) > n
	rest := concat("/", array.slice(parts, n, count(parts)))
	rest != ""
}

segments(patterns, parts) := {name: v | some i, p in patterns; [name, v] := segment(p, parts[i]); name != ""} if {
	count(patterns) == count(parts)
	every i, p in patterns {
		segment(p, parts[i])
	}
}

segment(p, part) := ["", part] if {
	not contains(p, "{")
	p == part
}

segment(p, part) := [name, v] if {
	[prefix, rest] := split(p, "{")
	[name, suffix] := split(rest, "}")
	startswith(part, prefix)
	endswith(part, suffix)
	v := substring(part, count(prefix), (count(part) - count(prefix)) - count(suffix))
	v != ""
}

extract(spec) := captures(record.path)[spec.at] if spec.from == "path"

extract(spec) := input.http.query[spec.at][0] if {
	spec.from == "query"
	spec.at != ""
	count(input.http.query[spec.at]) == 1
}

# An empty key takes the whole query or form, so an approval binds every parameter.
extract(spec) := input.http.query if {
	spec.from == "query"
	spec.at == ""
}

extract(spec) := object.get(input.http, "form", {}) if {
	spec.from == "form"
	spec.at == ""
}

extract(spec) := input.http.headers[spec.at][0] if {
	spec.from == "header"
	count(input.http.headers[spec.at]) == 1
}

extract(spec) := input.http.form[spec.at][0] if {
	spec.from == "form"
	spec.at != ""
}

extract(spec) := pointer(input.http.body, spec.at) if spec.from == "body"

extract(spec) := pointer(input.http.header_json[spec.header], spec.at) if spec.from == "header_json"

extract(spec) := pointer(input.graphql.fields[0].arguments, spec.at) if spec.from == "argument"

# A JSON pointer whose numeric segments index arrays; ~ escapes are not supported.
pointer(doc, at) := object.get(doc, steps(at), null)

steps(at) := [step(s) | some s in array.slice(parts, 1, count(parts))] if {
	parts := split(at, "/")
	parts[0] == ""
	not contains(at, "~")
}

step(s) := to_number(s) if regex.match(`^(0|[1-9][0-9]*)$`, s)

step(s) := s if not regex.match(`^(0|[1-9][0-9]*)$`, s)
