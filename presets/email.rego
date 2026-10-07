package handlers.email

import data.monitor.action_effects

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

# Mail to the account's own address stays within the account's audience.
sends := "anyone" if {
	some to in input.smtp.to
	not lower(to) == lower(input.account.policy_options.address)
} else := input.account.sends

default scope := {}

scope := {"to": sort(input.smtp.to)}

operation := {
	"id": action, "action": action, "effects": action_effects(action), "scope": scope, "sends": sends,
}

title := sprintf("Send mail to %s", [concat(", ", input.smtp.to)])

title := sprintf("%s %s", [command, object.get(input.imap, "mailbox", "")]) if input.imap
