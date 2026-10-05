package templates.ssh

catalog := {
	"title": "SSH server",
	"fields": [
		{"key": "host", "label": "Host", "path": ["connections", "", "ssh", "host"]},
		{"key": "user", "label": "User", "path": ["connections", "", "ssh", "user"]},
		{"key": "host_key", "label": "Host key", "hint": "a line of ssh-keyscan <host>", "path": ["connections", "", "ssh", "host_key"]},
		{"key": "key", "label": "Private key", "secret": true, "multiline": true, "path": ["connections", "", "ssh", "key"]}
	],
	"connections": {"": {"ssh": {"host": "{host}", "user": "{user}", "host_key": "{host_key}"}}},
	"defaults": {"contents": "me", "strangers": true, "sends": "me"},
	"actions": {
		"session": {"title": "Set up terminals and send signals"},
		"run": {"title": "Run commands"},
		"shell": {"title": "Open interactive shells"},
		"files": {"title": "Transfer files"}
	}
}

# Session requests (terminal, environment, signals) carry no change obligation; file transfer needs trust.
effects := {"session": {"session"}, "run": {"execute"}, "shell": {"execute"}, "files": {"read", "write"}}

action := "session" if input.ssh.request in {"pty-req", "env", "window-change", "signal", "break"}

action := "run" if input.ssh.request == "exec"

action := "shell" if input.ssh.request == "shell"

action := "files" if input.ssh.subsystem == "sftp"

default scope := {}

scope := {"command": input.ssh.command} if input.ssh.command

operation := {
	"id": action, "action": action, "effects": effects[action], "scope": scope, "trust": action == "files"
}

host := input.connection_config.host

title := sprintf("Run %s on %s", [input.ssh.command, host]) if input.ssh.command

title := sprintf("Open a shell on %s", [host]) if action == "shell"

title := sprintf("Transfer files on %s", [host]) if action == "files"
