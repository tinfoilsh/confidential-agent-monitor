---
name: perimeter
description: Discover and use services granted to this bunker, inspect its own Perimeter policy, and propose service or access changes for owner review without handling credentials.
---

# Perimeter in a bunker

The Perimeter is this bunker's policy and credential boundary for external services.
Use the installed `perimeter` CLI unless directly integrating with the internal
agent API.

## Rules

- Never ask for or use the Perimeter owner key.
- Never ask for provider credentials. The owner configures them separately.
- Inspect the catalog warning before proposing a Generic service.
- Prefer a named service over Generic Web, SSH, network, API, or MCP.
- A proposal is only a request. Do not assume access changed until discovery or
  policy shows it.
- Propose only services and access needed by this bunker. Do not request
  changes for another bunker.
- Service approval does not approve MCP tools; the owner reviews tool
  definitions separately.

## Discover

See the safe service catalog:

```sh
perimeter catalog --json
```

Catalog entries describe setup fields, defaults, service templates, and
shared `warning` copy. `vocabulary` describes the effects referenced by catalog
actions. The final `generic` group contains broad fallback types.

See services this bunker can currently use:

```sh
perimeter services --json
```

Discovery includes service names, protocols, readiness, effective access,
allowed hosts, safe credential placeholders, and credential states such as
`unset`, `static`, `oauth`, or `oauth-required`. It never includes credential
values or verified credential account identifiers.

See this bunker's own policy projection:

```sh
perimeter policy show
perimeter policy show --json
```

The bunker view contains this identity's access and saved rules plus semantics
for services it can reach. It does not reveal other bunkers, owner-only policy,
or credentials.

## Request a service or access change

Prefer structured changes for automation:

```sh
perimeter policy propose --changes changes.json \
  --reason "Grant this bunker GitHub access for issue triage"
```

Example `changes.json`:

```json
[
  {
    "path": ["identities", "my-bunker", "connections", "github", "level"],
    "value": "ask"
  }
]
```

Use the exact bunker identity shown by `perimeter policy show`. A deletion uses
`"delete": true` and omits `value`. TOML fragments are also accepted:

```sh
perimeter policy propose change.toml \
  --reason "Grant this bunker GitHub access for issue triage"
```

Proposals may contain shared service setup or access for this bunker only.
They cannot change default access, credentials, MCP tool pins, identity keys or
routes, global policies, data, global effect defaults, or other owner
configuration. The Perimeter validates the candidate and removes semantic no-ops before
publishing it.

A batch is split into one proposal per service. The owner reviews each
service independently. Poll the ID from a submitted receipt with:

```sh
perimeter policy status PROPOSAL_ID
```

Status is limited to this bunker's own proposals and reports `pending`,
`approved`, `denied`, or `outdated`. It is process-local like the
pending proposal itself. A proposal stays pending across other policy changes and is
reviewed against the current policy. The Perimeter records it as Outdated when it
no longer applies or this bunker proposes again for the same service.

## Use services

HTTP and HTTPS traffic already goes through the Perimeter system-wide, and its CA is
in the system trust store. Direct internet egress is closed; the owner must keep
the Perimeter reverse forward connected. Transparent routing also covers tools
that ignore proxy settings.

Use the wrapper when you need credential placeholders or a specific service:

```sh
perimeter run --service SERVICE -- curl -fsS https://example.com
perimeter run -- your-command
perimeter shell
```

The wrapper configures proxy and certificate settings and exposes safe credential
placeholders. The Perimeter substitutes real credentials upstream. Never replace a
placeholder with a real credential.

For MCP services:

```sh
perimeter mcp serve --listen 127.0.0.1:8400
```

Keep it running and configure the MCP client with the reported local URL. Only
ready services granted to this bunker are served.

A request that needs approval may wait and time out. After an uncertain write
timeout, inspect the destination or Activity before retrying.

## Direct internal API

Inside the managed bunker, the identity-authenticated API is available at
`agent.perimeter`:

| Method | Path | Purpose |
| --- | --- | --- |
| `GET` | `/catalog` | Safe service catalog and warnings |
| `GET` | `/connections` | Services granted to this bunker |
| `GET` | `/policy` | This bunker's credential-free policy view |
| `GET` | `/policy/proposals/{id}` | Poll this bunker's submitted proposal |
| `POST` | `/policy/proposals` | Submit owner-reviewed service changes |

```sh
curl -fsS http://agent.perimeter/catalog
curl -fsS http://agent.perimeter/connections
curl -fsS http://agent.perimeter/policy
curl -fsS -X POST http://agent.perimeter/policy/proposals \
  -H 'Content-Type: application/json' \
  --data-binary @proposal.json
```

A structured proposal body has `reason` and a non-empty `changes` array.
Responses contain `{id, state, connection}` receipts, not owner-only
configuration or diffs. Resubmitting replaces the pending proposal with a new receipt.
