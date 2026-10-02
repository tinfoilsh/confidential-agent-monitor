package templates.ssh

catalog := {
	"title": "SSH server",
	"fields": [
		{"key": "host", "label": "Host"},
		{"key": "user", "label": "User"},
		{"key": "host_key", "label": "Host key", "hint": "a line of ssh-keyscan <host>"},
		{"key": "key", "label": "Private key", "secret": true, "multiline": true},
	],
	"connections": {"": {"ssh": {"host": "{host}", "user": "{user}", "host_key": "{host_key}", "key": {"$secret": "key"}}}},
	"defaults": {"contents": "me", "strangers": true, "sends": "me"},
	"actions": {
		"session": {"title": "Set up terminals and send signals"},
		"run": {"title": "Run commands", "save": "Allow {command}"},
		"shell": {"title": "Open interactive shells", "save": "Allow shells"},
		"files": {"title": "Transfer files", "save": "Allow file transfers"},
	},
}

changes := {"run", "shell", "files"}

needs_trust := {"run", "shell", "files"}

action := "session" if input.ssh.request in {"pty-req", "env", "window-change", "signal", "break"}

action := "run" if input.ssh.request == "exec"

action := "shell" if input.ssh.request == "shell"

action := "files" if input.ssh.subsystem == "sftp"

scope := {"command": input.ssh.command} if input.ssh.command

host := input.account.fields.host

title := sprintf("Run %s on %s", [input.ssh.command, host]) if input.ssh.command

title := sprintf("Open a shell on %s", [host]) if action == "shell"

title := sprintf("Transfer files on %s", [host]) if action == "files"
