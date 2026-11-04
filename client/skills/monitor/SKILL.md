---
name: monitor
description: Discover Monitor connection types and granted connections, inspect identity-scoped policy, propose connection setup or access changes for owner review, and use HTTP or MCP connections without handling credentials.
---

# Monitor

Monitor is the policy and credential boundary between an AI agent and external
services. Use the installed `monitor` CLI unless you are integrating directly
with the agent HTTP API.

## Safety rules

- Never ask for, read, copy, or submit the Monitor owner key.
- Never ask for provider credentials. Credentials are configured separately by
  the owner and never belong in a proposal.
- Treat catalog `warning` text as part of the connection definition. Explain it
  to the owner when proposing a Generic connection.
- A submitted proposal is not approval. Do not assume access changed until it
  appears in `monitor connections` or `monitor policy show`.
- Prefer a named service connection over Generic Web, SSH, network, API, or MCP
  connections when one exists.
- Connection approval does not approve MCP tool definitions. The owner reviews
  new or changed MCP tools separately.

## Discover capabilities

Inspect safe setup metadata available to every sandbox and trusted device:

```sh
monitor catalog --json
```

Each preset can include its name, title, group, defaults, setup fields,
connection templates, and shared `warning` copy. The final `generic` group is a
fallback for broad connection types.

Inspect connections this identity may actually use:

```sh
monitor connections --json
```

Connection discovery includes routing names, protocol, readiness, effective
access, safe credential placeholders, and allowed upstream hosts. It never
contains credential values.

Inspect policy visible to this identity:

```sh
monitor policy show
monitor policy show --json
```

A sandbox sees only its own identity, its own access and rules, and semantics
for accounts it can reach. A trusted device sees a credential-free, expanded
configuration projection, including accounts, identities, public keys, routes,
sandbox access and global settings. Inherited access and resolved connections are
materialized, so this projection is not source TOML and must not be round-tripped.
Neither view includes values from Monitor's credential store.

## Propose connection changes

Use a paired trusted-device identity for host automation. Code running inside a
sandbox uses that sandbox's identity. Do not borrow an owner-panel session.

Structured changes are preferred for automation:

```sh
monitor policy propose --changes changes.json \
  --reason "Grant this sandbox GitHub access for issue triage"
```

`changes.json` is a non-empty JSON array:

```json
[
  {
    "path": ["identities", "my-sandbox", "accounts", "github", "level"],
    "value": "ask"
  }
]
```

A deletion uses `"delete": true` and omits `value`. TOML fragments are also
supported:

```sh
monitor policy propose change.toml \
  --reason "Grant this sandbox GitHub access for issue triage"
```

Trusted-device proposals may change only:

- `accounts.<connection>...`
- `default_access.<connection>...`
- `identities.<sandbox>.accounts.<connection>...`

A sandbox may propose shared connection setup under `accounts`, but may change
access only for its own identity and cannot change `default_access`. No proposal
may change credentials, MCP tool pins, identity keys or routes, global policies,
data, global effect defaults, lattice settings, or unrelated owner configuration.
Monitor validates all submitted changes and removes semantic no-ops before
publishing them for review.

A batch affecting several connections is split into one proposal per connection.
Setup and default/sandbox access for the same connection stay together. The CLI
prints pending receipts; the owner reviews each connection independently.

If relevant configuration changes before review, Monitor consumes the proposal
as Outdated and records that outcome in Activity. Submit a new proposal against
the latest policy if the request is still needed.

## Use granted connections

HTTP and HTTPS tools can run through Monitor:

```sh
monitor run --connection CONNECTION -- curl -fsS https://example.com
monitor run -- your-command
monitor shell
```

The wrapper configures proxy and certificate settings and exposes safe credential
placeholders. Monitor substitutes real credentials upstream. Map a placeholder
to the environment variable expected by a tool inside the wrapped command;
never replace it with a real credential.

For MCP connections:

```sh
monitor mcp serve --listen 127.0.0.1:8400
```

Keep the process running and configure the MCP client with the reported local
URL. Only ready, granted MCP connections are served.

Requests requiring owner approval may wait and time out. After an uncertain
write timeout, inspect the target or Activity before retrying.

## Direct agent HTTP API

Inside a managed sandbox, `agent.monitor` exposes the identity-authenticated API.
Authentication comes from the sandbox or trusted-device SSH identity; do not add
an owner bearer token.

| Method | Path                | Purpose                                      |
| ------ | ------------------- | -------------------------------------------- |
| `GET`  | `/catalog`          | Safe preset catalog and shared warnings      |
| `GET`  | `/connections`      | Connections this identity can use            |
| `GET`  | `/policy`           | Identity-scoped non-secret policy TOML       |
| `POST` | `/policy/proposals` | Submit TOML or structured connection changes |

Examples from a sandbox where `agent.monitor` is directly routable:

```sh
curl -fsS http://agent.monitor/catalog
curl -fsS http://agent.monitor/connections
curl -fsS http://agent.monitor/policy
curl -fsS -X POST http://agent.monitor/policy/proposals \
  -H 'Content-Type: application/json' \
  --data-binary @proposal.json
```

A structured request body has `reason`, optional `idempotency_key`, and `changes`:

```json
{
  "reason": "Grant this sandbox GitHub access for issue triage",
  "idempotency_key": "github-issue-triage-v1",
  "changes": [
    {
      "path": ["identities", "my-sandbox", "accounts", "github", "level"],
      "value": "ask"
    }
  ]
}
```

A TOML request body uses `source`, optional path arrays in `delete`, and
`reason`. Agent proposal responses contain only pending receipts;
owner-only source diffs and configuration are not returned.

On a paired host, use the `monitor` CLI because it carries these requests through
the authenticated SSH transport. Run `monitor --help` for SSH host, config, and
profile options.
