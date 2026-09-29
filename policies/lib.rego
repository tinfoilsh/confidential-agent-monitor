package sentinel

write if {
	input.http.method
	not input.http.method in {"GET", "HEAD", "OPTIONS"}
}

route(pattern) if glob.match(pattern, ["/"], input.http.path)

mutation if input.graphql.kind == "mutation"
