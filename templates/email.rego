package templates.email

changes := {"organize", "send"}

needs_trust := {"send"}

command := upper(split(input.imap.args, " ")[0]) if input.imap.command == "UID"
else := input.imap.command

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
