package templates.email

catalog := {
	"title": "Email",
	"fields": [
		{"key": "address", "label": "Address"},
		{"key": "password", "label": "App password", "secret": true},
		{"key": "imap_host", "label": "IMAP server", "default": "imap.gmail.com"},
		{"key": "smtp_host", "label": "SMTP server", "default": "smtp.gmail.com"},
	],
	"connections": {
		"imap": {"imap": {"url": "imaps://{imap_host}", "user": "{address}", "password": {"$secret": "password"}}},
		"smtp": {"smtp": {"url": "smtps://{smtp_host}", "user": "{address}", "password": {"$secret": "password"}}},
	},
	"defaults": {"contents": "me", "strangers": true, "sends": "me"},
	"actions": {
		"read": {"title": "Read mail"},
		"organize": {"title": "Move, flag and delete mail"},
		"send": {"title": "Send mail", "save": "Allow mail to {to}"},
	},
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
	not lower(to) == lower(input.account.fields.address)
}

scope := {"to": sort(input.smtp.to)}

title := sprintf("Send mail to %s", [concat(", ", input.smtp.to)])

title := sprintf("%s %s", [command, object.get(input.imap, "mailbox", "")]) if input.imap
