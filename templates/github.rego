package templates.github

catalog := {
	"title": "GitHub",
	"fields": [
		{"key": "token", "label": "Personal access token", "secret": true},
		{"key": "private", "label": "Private orgs and repos", "list": true, "hint": "owner/* or owner/repo"},
	],
	"connections": {
		"": {"http": {"hosts": ["api.github.com", "github.com", "*.githubusercontent.com"], "secrets": {"GITHUB_TOKEN": {"$secret": "token"}}}},
		"mcp": {"mcp": {"url": "https://api.githubcopilot.com/mcp/", "token": {"$secret": "token"}}},
	},
	"defaults": {"contents": "team", "strangers": true, "sends": "me"},
	"actions": {
		"read": {"title": "Read code, issues and pull requests"},
		"comment": {"title": "Comment on issues and pull requests", "save": "Allow comments on {repo}"},
		"comment.lines": {"title": "Comment on lines of code", "save": "Allow line comments on {repo}"},
		"comment.reviews": {"title": "Review pull requests", "save": "Allow reviews on {repo}"},
		"open": {"title": "Open and edit issues and pull requests"},
		"open.issues": {"title": "Open and edit issues", "save": "Allow opening and editing issues on {repo}"},
		"open.pulls": {"title": "Open and edit pull requests", "save": "Allow opening and editing pull requests on {repo}"},
		"push": {"title": "Push commits", "save": "Allow pushes to {repo}"},
		"merge": {"title": "Merge pull requests", "save": "Allow merges on {repo}"},
		"use": {"title": "Use tools that change things"},
	},
}

import data.monitor.mutation
import data.monitor.route
import data.monitor.write

changes := {"comment", "open", "push", "merge", "use"}

needs_trust := {"push", "merge", "use"}

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
