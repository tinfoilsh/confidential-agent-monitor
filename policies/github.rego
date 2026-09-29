package sentinel

deny contains "push is not allowed" if {
	input.connection == "github"
	endswith(input.http.path, "/git-receive-pack")
}

deny contains sprintf("%s %s is not an allowed write", [input.http.method, input.http.path]) if {
	input.connection == "github"
	write
	not allowed_write
}

allowed_write if {
	some pattern in data.github.writes
	route(pattern)
}

deny contains "the GraphQL document could not be decoded" if {
	input.connection == "github"
	route("/graphql")
	not input.graphql
}

deny contains sprintf("mutation %s is not allowed", [root]) if {
	input.connection == "github"
	mutation
	some root in input.graphql.roots
	not root in data.github.mutations
}
