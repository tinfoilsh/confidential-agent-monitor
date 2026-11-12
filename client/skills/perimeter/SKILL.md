---
name: perimeter
description: Discover Perimeter service types and granted services, inspect identity-scoped policy, propose service setup or access changes for owner review, and use HTTP or MCP services without handling credentials.
---

# Perimeter

The Perimeter is the policy and credential boundary between an AI agent and external
services. Use the installed `perimeter` CLI unless you are integrating directly
with the agent HTTP API.

## Safety rules

- Never ask for, read, copy, or submit the Perimeter owner key.
- Never ask for provider credentials. Credentials are configured separately by
  the owner and never belong in a proposal.
- Treat catalog `warning` text as part of the service definition. Explain it
  to the owner when proposing a Generic service.
- A submitted proposal is not approval. Do not assume access changed until it
  appears in `perimeter services` or `perimeter policy show`.
- Prefer a named service over Generic Web, SSH, network, API, or MCP
  when one exists.
- Service approval does not approve MCP tool definitions. The owner reviews
  new or changed MCP tools separately.

## Discover capabilities

Inspect safe setup metadata available to every bunker and trusted device:

```sh
perimeter catalog --json
```

Each preset can include its name, title, group, defaults, setup fields,
service templates, and shared `warning` copy. `vocabulary` describes the
effects referenced by catalog actions, including change and approval defaults.
The final `generic` group is a fallback for broad service types.

Inspect services this identity may actually use:

```sh
perimeter services --json
```

Service discovery includes routing names, protocol, readiness, effective
access, allowed upstream hosts, safe credential placeholders, and credential
states such as `unset`, `static`, `oauth`, or `oauth-required`. It never contains
credential values or verified credential account identifiers.

Inspect policy visible to this identity:

```sh
perimeter policy show
perimeter policy show --json
```

A bunker sees only its own identity, its own access and rules, and semantics
for services it can reach. A trusted device sees a credential-free, expanded
configuration projection, including services, identities, public keys, routes,
bunker access and global settings. Inherited access and resolved services are
materialized, so this projection is not source TOML and must not be round-tripped.
Neither view includes values from the Perimeter's credential store.

## Propose service changes

Use a paired trusted-device identity for host automation. Code running inside a
bunker uses that bunker's identity. Do not borrow an owner-panel session.

Structured changes are preferred for automation:

```sh
perimeter policy propose --changes changes.json \
  --reason "Grant this bunker GitHub access for issue triage"
```

`changes.json` is a non-empty JSON array:

```json
[
  {
    "path": ["identities", "my-bunker", "connections", "github", "level"],
    "value": "ask"
  }
]
```

A deletion uses `"delete": true` and omits `value`. TOML fragments are also
supported:

```sh
perimeter policy propose change.toml \
  --reason "Grant this bunker GitHub access for issue triage"
```

Trusted-device proposals may change only:

- `connections.<connection>...`
- `default_access.<connection>...`
- `identities.<sandbox>.connections.<connection>...`

A bunker may propose shared service setup under `connections`, but may change
access only for its own identity and cannot change `default_access`. No proposal
may change credentials, MCP tool pins, identity keys or routes, global policies,
data, global effect defaults, lattice settings, or unrelated owner configuration.
The Perimeter validates all submitted changes and removes semantic no-ops before
publishing them for review.

A batch affecting several services is split into one proposal per service.
Setup and default/bunker access for the same service stay together. The CLI
prints one receipt per service; poll a receipt without owner credentials:

```sh
perimeter policy status PROPOSAL_ID
```

The result is a receipt, `{id, state, connection}`, with state `pending`,
`approved`, `denied`, or `outdated`. Status is process-local like the pending
proposal itself, so a Perimeter restart may make an old receipt unavailable.

A proposal stays pending across other policy changes and is reviewed against the
current policy. The Perimeter records it as Outdated in Activity when it no longer
applies or you propose again for the same service.

## Use granted services

HTTP and HTTPS tools can run through the Perimeter:

```sh
perimeter run --service SERVICE -- curl -fsS https://example.com
perimeter run -- your-command
perimeter shell
```

The wrapper configures proxy and certificate settings and exposes safe credential
placeholders. The Perimeter substitutes real credentials upstream. Map a placeholder
to the environment variable expected by a tool inside the wrapped command;
never replace it with a real credential.

For MCP services:

```sh
perimeter mcp serve --listen 127.0.0.1:8400
```

Keep the process running and configure the MCP client with the reported local
URL. Only ready, granted MCP services are served.

Requests requiring owner approval may wait and time out. After an uncertain
write timeout, inspect the target or Activity before retrying.

## Direct agent HTTP API

Inside a managed bunker, `agent.perimeter` exposes the identity-authenticated API.
Authentication comes from the bunker or trusted-device SSH identity; do not add
an owner bearer token.

| Method | Path                | Purpose                                      |
| ------ | ------------------- | -------------------------------------------- |
| `GET`  | `/catalog`          | Safe preset catalog and shared warnings      |
| `GET`  | `/connections`      | Services this identity can use            |
| `GET`  | `/policy`                | Identity-scoped credential-free policy TOML  |
| `GET`  | `/policy/proposals/{id}` | Poll one proposal submitted by this identity |
| `POST` | `/policy/proposals`      | Submit TOML or structured service changes |

Examples from a bunker where `agent.perimeter` is directly routable:

```sh
curl -fsS http://agent.perimeter/catalog
curl -fsS http://agent.perimeter/connections
curl -fsS http://agent.perimeter/policy
curl -fsS -X POST http://agent.perimeter/policy/proposals \
  -H 'Content-Type: application/json' \
  --data-binary @proposal.json
```

A structured request body has `reason` and `changes`:

```json
{
  "reason": "Grant this sandbox GitHub access for issue triage",
  "changes": [
    {
      "path": ["identities", "my-bunker", "connections", "github", "level"],
      "value": "ask"
    }
  ]
}
```

A TOML request body uses `source`, optional path arrays in `delete`, and
`reason`. Agent proposal responses contain only receipts, and resubmitting
identical changes returns the pending one; owner-only source diffs and
configuration are not returned.

On a paired host, use the `perimeter` CLI because it carries these requests through
the authenticated SSH transport. Run `perimeter --help` for SSH host, config, and
profile options.
