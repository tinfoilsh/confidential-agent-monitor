package templates.web

import data.monitor.write

changes := {"submit"}

needs_trust := {"submit"}

action := "submit" if write

action := "browse" if {
	input.http
	not write
}

scope := {"host": input.http.host}

title := sprintf("%s %s%s", [input.http.method, input.http.host, input.http.path])
