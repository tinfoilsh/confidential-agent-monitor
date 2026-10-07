package handlers.sftp

import data.monitor.action_effects

command := input.sftp.command

action := "read" if command in {"read", "stat", "lstat", "fstat", "opendir", "readdir", "realpath"}
action := "read" if { command == "open"; input.sftp.read; not object.get(input.sftp, "write", false) }
action := "write" if command in {"write", "mkdir"}
action := "write" if { command == "open"; input.sftp.write; not object.get(input.sftp, "read", false) }
action := "readwrite" if { command == "open"; input.sftp.read; input.sftp.write }
action := "delete" if command in {"remove", "rmdir"}
action := "rename" if command == "rename"
action := "metadata" if command in {"setstat", "fsetstat"}

scope := object.filter(input.sftp, {"path", "target", "read", "write", "flags", "attributes"})
operation := {"id": command, "action": action, "effects": action_effects(action), "scope": scope}
title := sprintf("SFTP %s %s", [command, input.sftp.path])
