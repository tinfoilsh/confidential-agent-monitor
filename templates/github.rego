package templates.github

import data.monitor.mutation
import data.monitor.route
import data.monitor.write

changes := {"comment", "open", "push", "merge", "use"}

needs_trust := {"push", "merge", "use"}

writes := {
	"/repos/*/*/issues/*/comments": "comment",
	"/repos/*/*/issues/comments/*": "comment",
	"/repos/*/*/pulls/*/comments": "comment",
	"/repos/*/*/pulls/*/reviews": "comment",
	"/repos/*/*/issues": "open",
	"/repos/*/*/issues/*": "open",
	"/repos/*/*/pulls": "open",
	"/repos/*/*/pulls/*": "open",
	"/repos/*/*/pulls/*/merge": "merge",
}

mutations := {
	"addComment": "comment",
	"addPullRequestReview": "comment",
	"createIssue": "open",
	"updateIssue": "open",
	"createPullRequest": "open",
	"updatePullRequest": "open",
	"mergePullRequest": "merge",
}

action := data.templates.mcp.action if input.mcp

action := "read" if {
	input.http
	not write
}

action := "read" if route("/*/*/git-upload-pack")

action := "push" if endswith(input.http.path, "/git-receive-pack")

action := a if {
	write
	some pattern, a in writes
	route(pattern)
}

action := "read" if input.graphql.kind == "query"

action := a if {
	mutation
	some root in input.graphql.roots
	a := mutations[root]
	every r in input.graphql.roots {
		mutations[r] == a
	}
}

deny contains "the GraphQL document could not be decoded" if {
	route("/graphql")
	not input.graphql
}

parts := split(input.http.path, "/")

repo := concat("/", array.slice(parts, 2, 4)) if {
	input.http.host == "api.github.com"
	parts[1] == "repos"
	count(parts) > 3
}

repo := concat("/", [parts[1], trim_suffix(parts[2], ".git")]) if {
	input.http.host != "api.github.com"
	count(parts) > 2
}

repo := concat("/", [input.mcp.arguments.owner, input.mcp.arguments.repo])

private if {
	some pattern in input.account.fields.private
	glob.match(pattern, ["/"], repo)
}

scope := {"repo": repo}

public if {
	repo
	not private
}

reveals := {"contents": "anyone"} if public

sends := "anyone" if {
	public
	action in changes
}

verbs := {
	"read": "Read",
	"comment": "Comment on",
	"open": "Open or edit an issue or pull request on",
	"push": "Push to",
	"merge": "Merge a pull request on",
}

default where := "GitHub"

where := repo

title := data.templates.mcp.title if input.mcp

title := sprintf("%s %s", [verbs[action], where]) if not input.mcp
