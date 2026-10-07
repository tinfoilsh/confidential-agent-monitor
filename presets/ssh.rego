package handlers.ssh

import data.monitor.action_effects

# Session requests (terminal, environment, signals) carry no change obligation; file transfer needs trust.
action := "session" if input.ssh.request in {"pty-req", "env", "window-change", "signal", "break"}

action := "run" if input.ssh.request == "exec"

action := "shell" if input.ssh.request == "shell"

action := "files" if input.ssh.subsystem == "sftp"

default scope := {}

scope := {"command": input.ssh.command} if input.ssh.command

operation := {
	"id": action, "action": action, "effects": action_effects(action), "scope": scope, "trust": action == "files",
}

host := input.connection_config.host

title := sprintf("Run %s on %s", [input.ssh.command, host]) if input.ssh.command

title := sprintf("Open a shell on %s", [host]) if action == "shell"

title := sprintf("Transfer files on %s", [host]) if action == "files"
