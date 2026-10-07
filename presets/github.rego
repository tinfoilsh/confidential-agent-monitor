package handlers.github

import data.monitor.action_effects
import data.monitor.route

# Select the protocol before recognition. An unknown or malformed request stays
# with its recognizer, including its denials, rather than trying another one.
protocol := "mcp" if input.mcp

else := "graphql" if {
	input.http.origin == "https://api.github.com"
	input.http.path == "/graphql"
}

else := "git" if {
	input.http.origin == "https://github.com"
	some pattern in {"/*/*/info/refs", "/*/*/git-upload-pack", "/*/*/git-receive-pack"}
	route(pattern)
}

else := "rest"

mutations := {
	"addComment": "comment",
	"addPullRequestReview": "comment.reviews",
	"createIssue": "open.issues",
	"updateIssue": "open.issues",
	"createPullRequest": "open.pulls",
	"updatePullRequest": "open.pulls",
	"mergePullRequest": "merge",
}

action := data.handlers.mcp.action if protocol == "mcp"

action := "read" if {
	protocol == "git"
	input.http.method == "GET"
	route("/*/*/info/refs")
	input.http.query.service in {["git-upload-pack"], ["git-receive-pack"]}
}

action := "read" if {
	protocol == "git"
	input.http.method == "POST"
	route("/*/*/git-upload-pack")
}

action := "push" if {
	protocol == "git"
	input.http.method == "POST"
	route("/*/*/git-receive-pack")
}

action := "read" if {
	protocol == "graphql"
	input.graphql.kind == "query"
}

action := a if {
	protocol == "graphql"
	input.graphql.kind == "mutation"
	some field in input.graphql.fields
	a := mutations[field.name]
	every f in input.graphql.fields {
		mutations[f.name] == a
	}
}

deny contains msg if {
	protocol == "rest"
	some msg in data.monitor.api.deny
}

deny contains "the GraphQL document could not be decoded" if {
	protocol == "graphql"
	not input.graphql
}

parts := split(input.http.path, "/")

repo := concat("/", array.slice(parts, 2, 4)) if {
	input.http.origin == "https://api.github.com"
	parts[1] == "repos"
	count(parts) > 3
}

repo := concat("/", [parts[1], trim_suffix(parts[2], ".git")]) if protocol == "git"

repo := concat("/", [input.mcp.arguments.owner, input.mcp.arguments.repo]) if protocol == "mcp"

private if {
	some pattern in input.account.policy_options.private
	glob.match(pattern, ["/"], repo)
}

default scope := {}

scope := {"repo": repo}

recognized := data.monitor.api.operation if protocol == "rest"

recognized := {
	"id": action, "action": action, "effects": action_effects(action), "scope": scope,
	"trust": root in {"push", "merge", "use"},
} if {
	protocol != "rest"
	root := split(action, ".")[0]
}

# Keep the record's ID, effects, scope, grant and definition. GitHub's repository
# audience applies to both record operations and the specialized protocols.
operation := object.union(recognized, {"sends": sends, "reveals": reveals})

public if {
	repo
	not private
}

reveals := {"contents": "anyone"} if public

else := {}

sends := "anyone" if {
	public
	some e in recognized.effects
	data.monitor.vocabulary[e].change
}

else := recognized.sends if recognized.sends

else := input.account.sends

verbs := {
	"read": "Read",
	"comment": "Comment on",
	"comment.lines": "Comment on code in",
	"comment.reviews": "Review a pull request on",
	"open.issues": "Open or edit an issue on",
	"open.pulls": "Open or edit a pull request on",
	"push": "Push to",
	"merge": "Merge a pull request on",
}

default where := "GitHub"

where := repo

title := data.monitor.api.title if protocol == "rest"

title := data.handlers.mcp.title if protocol == "mcp"

title := sprintf("%s %s", [verbs[action], where]) if protocol in {"git", "graphql"}
