package templates.email

catalog := {
	"title": "Email",
	"fields": [
		{"key": "address", "label": "Own email address, for policy", "path": ["policy_options", "address"]},
		{
			"key": "password",
			"label": "App password",
			"secret": true,
			"paths": [["connections", "imap", "imap", "password"], ["connections", "smtp", "smtp", "password"]]
		},
		{"key": "imap_url", "label": "IMAP URL", "default": "imaps://imap.gmail.com", "path": ["connections", "imap", "imap", "url"]},
		{"key": "smtp_url", "label": "SMTP URL", "default": "smtps://smtp.gmail.com", "path": ["connections", "smtp", "smtp", "url"]},
		{"key": "imap_user", "label": "IMAP user", "path": ["connections", "imap", "imap", "user"], "edit_only": true},
		{"key": "smtp_user", "label": "SMTP user", "path": ["connections", "smtp", "smtp", "user"], "edit_only": true}
	],
	"connections": {
		"imap": {"imap": {"url": "{imap_url}", "user": "{address}"}},
		"smtp": {"smtp": {"url": "{smtp_url}", "user": "{address}"}}
	},
	"defaults": {"contents": "me", "strangers": true, "sends": "me"},
	"actions": {"read": {"title": "Read mail"}, "organize": {"title": "Move, flag and delete mail"}, "send": {"title": "Send mail", "save": "Allow mail to {to}"}}
}

changes := {"organize", "send"}

needs_trust := {"send"}

command := input.imap.command

action := "read" if command in {
	"CAPABILITY", "CHECK", "ENABLE", "EXAMINE", "FETCH", "ID", "IDLE", "LIST", "LOGOUT",
	"LSUB", "NAMESPACE", "NOOP", "SEARCH", "SELECT", "STATUS", "UNSELECT",
}

action := "organize" if command in {
	"APPEND", "CLOSE", "COPY", "CREATE", "DELETE", "EXPUNGE", "MOVE", "RENAME",
	"STORE", "SUBSCRIBE", "UNSUBSCRIBE",
}

action := "send" if input.smtp

sends := "anyone" if {
	some to in input.smtp.to
	not lower(to) == lower(input.account.policy_options.address)
}

scope := {"to": sort(input.smtp.to)}

title := sprintf("Send mail to %s", [concat(", ", input.smtp.to)])

title := sprintf("%s %s", [command, object.get(input.imap, "mailbox", "")]) if input.imap
