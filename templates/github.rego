package templates.github

catalog := {
	"title": "GitHub",
	"fields": [
		{
			"key": "token",
			"label": "Personal access token",
			"secret": true,
			"paths": [["connections", "", "http", "values", "GITHUB_TOKEN"], ["connections", "mcp", "mcp", "token"]]
		},
		{"key": "private", "label": "Private orgs and repos", "list": true, "hint": "owner/* or owner/repo", "path": ["policy_options", "private"]}
	],
	"connections": {
		"": {"http": {"hosts": ["api.github.com", "github.com", "*.githubusercontent.com"], "slots": [
			{"value": "GITHUB_TOKEN", "origin": "https://api.github.com", "header": "Authorization", "prefix": "Bearer "},
			{"value": "GITHUB_TOKEN", "origin": "https://api.github.com", "header": "Authorization", "prefix": "token "},
			{"value": "GITHUB_TOKEN", "origin": "https://github.com", "basic": "password"},
		]}},
		"mcp": {"mcp": {"url": "https://api.githubcopilot.com/mcp/"}}
	},
	"defaults": {"contents": "team", "strangers": true, "sends": "me"},
	"actions": {
		"read": {"title": "Read code, issues and pull requests"},
		"comment": {"title": "Comment on issues and pull requests"},
		"comment.lines": {"title": "Comment on lines of code"},
		"comment.reviews": {"title": "Review pull requests"},
		"open": {"title": "Open and edit issues and pull requests"},
		"open.issues": {"title": "Open and edit issues"},
		"open.pulls": {"title": "Open and edit pull requests"},
		"push": {"title": "Push commits"},
		"merge": {"title": "Merge pull requests"},
		"use": {"title": "Use tools that change things"}
	}
}

import data.monitor.mutation
import data.monitor.route
import data.monitor.write

effects := {"read": {"read"}, "comment": {"write"}, "open": {"write"}, "push": {"write"}, "merge": {"write"}, "use": {"write"}}

root := split(action, ".")[0]

writes := {
	"/repos/*/*/issues/*/comments": "comment",
	"/repos/*/*/issues/comments/*": "comment",
	"/repos/*/*/pulls/*/comments": "comment.lines",
	"/repos/*/*/pulls/*/reviews": "comment.reviews",
	"/repos/*/*/issues": "open.issues",
	"/repos/*/*/issues/*": "open.issues",
	"/repos/*/*/pulls": "open.pulls",
	"/repos/*/*/pulls/*": "open.pulls",
	"/repos/*/*/pulls/*/merge": "merge",
}

mutations := {
	"addComment": "comment",
	"addPullRequestReview": "comment.reviews",
	"createIssue": "open.issues",
	"updateIssue": "open.issues",
	"createPullRequest": "open.pulls",
	"updatePullRequest": "open.pulls",
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
	some field in input.graphql.fields
	a := mutations[field.name]
	every f in input.graphql.fields {
		mutations[f.name] == a
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
	some pattern in input.account.policy_options.private
	glob.match(pattern, ["/"], repo)
}

default scope := {}

scope := {"repo": repo}

operation := {
	"id": action, "action": action, "effects": effects[root], "scope": scope,
	"trust": root in {"push", "merge", "use"}, "sends": sends, "reveals": reveals
}

public if {
	repo
	not private
}

reveals := {"contents": "anyone"} if public
else := {}

sends := "anyone" if {
	public
	root != "read"
}
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

title := data.templates.mcp.title if input.mcp

title := sprintf("%s %s", [verbs[action], where]) if not input.mcp
