package templates.mcp

changes := {"use"}

needs_trust := {"use"}

action := "read" if input.mcp.read_only

action := "use" if {
	input.mcp
	not input.mcp.read_only
}

scope := {"tool": input.mcp.tool}

title := sprintf("Use %s", [input.mcp.tool])
