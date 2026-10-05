package templates.postgres

catalog := {
	"title": "Postgres",
	"fields": [
		{"key": "url", "label": "Connection URL", "hint": "postgres://user@host/db", "path": ["connections", "", "postgres", "url"]},
		{"key": "password", "label": "Password", "secret": true, "default": "", "path": ["connections", "", "postgres", "password"]}
	],
	"connections": {"": {"postgres": {"url": "{url}"}}},
	"defaults": {"contents": "me", "strangers": true, "sends": "me"},
	"actions": {"read": {"title": "Run SELECT, SHOW and EXPLAIN"}, "write": {"title": "Change data and schema"}}
}

effects := {"read": {"read"}, "write": {"write"}}

sql := trim_suffix(trim_space(input.postgres.sql), ";")

# Anything this cannot read as one plain query is a write, so a misreading asks instead of passing.
read if {
	not contains(sql, ";")
	upper(regex.find_n(`^\w+`, sql, 1)[0]) in {"SELECT", "SHOW", "TABLE", "VALUES", "EXPLAIN", "BEGIN", "COMMIT", "ROLLBACK", "END"}
	not regex.match(`(?i)\b(into|for\s+(no\s+key\s+)?(update|share)|for\s+key\s+share|analyze)\b`, sql)
}

action := "read" if read

action := "write" if {
	input.postgres
	not read
}

default scope := {}

scope := {"sql": input.postgres.sql}

operation := {
	"id": action, "action": action, "effects": effects[action], "scope": scope, "trust": action == "write"
}

title := sprintf("Run %s", [input.postgres.sql])
