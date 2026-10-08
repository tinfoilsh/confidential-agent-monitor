Each preset has a `<name>.json` record. Accounts select it with
`"preset": "<name>"`. Owner entries in `config.presets` replace the entire
record of the same name.

The catalog contains setup fields, connections, defaults, and permission actions.
Protocol definitions have their own sections:

- `http.operations` contains reviewed HTTP operations, including GraphQL matchers.
- `http.slots` requires requests to stay within the connection's configured API addresses.
- `mcp.scope` selects service resource identifiers from MCP tool arguments.
- `public_scope` names the extracted parameters that identify public or private resources across protocols.

For example:

```json
{
  "title": "Example",
  "catalog": {"actions": {"items.read": {"title": "Read items"}}},
  "http": {
    "operations": [{
      "id": "items.get",
      "action": "items.read",
      "effects": ["read"],
      "method": "GET",
      "origin": "https://api.example.com",
      "path": "/items/{id}",
      "scope": {"id": {"from": "path", "at": "id"}}
    }]
  },
  "mcp": {
    "scope": {"id": {"at": "/id", "optional": true}}
  }
}
```

HTTP selectors choose a source with `from`, then a field or JSON path with `at`.
MCP selectors always read arguments, so they need only `at`, an optional `type`,
and `optional`. Missing optional values are accepted; present values must have
the declared type. The default type is `string`. Unknown configuration fields
are rejected.

Each connector describes its own parsed requests in Go. HTTP and GraphQL matching
live in `connector/web`; MCP argument selection lives in `connector/mcp`.
Preset validation compiles JSON paths, orders selectors, and indexes HTTP
operations by origin, method, and path. Matching still rejects overlapping
operations. HTTP metadata selectors read struct fields directly, without
serializing the request body.
The shared `facts` package defines and validates the snapshot, owns label
observation, and supplies label ordering and the effect vocabulary. The same
effect obligations drive Go validation and disclosure defaults, Rego policy, and
the app's permission display. They are included in the policy program's approval
hash. `facts.Details` has typed fields for each protocol, such as
`f.Details.HTTP.Method` and `f.Details.MCP.Arguments`. Protocol data types live in
`facts`; parsing and description methods stay in their connectors. A new protocol
adds its detail type and snapshot copying to `facts`.

A parsed request implements `connector.Request.Describe`. It returns facts,
approval scope and definition dependencies, and any validation error. It must
not mutate its input or perform I/O. The monitor supplies current redacted
connection settings and preset sections on every evaluation, including after
an owner approves a waiting request.

`policy.go` finalizes every description by resolving catalog effects, account
labels, and public/private resource settings, then calling `Facts.Validate`.
Invalid effects, labels, and request kinds are refused. A connector returns a null
operation for an unknown request. An action with no configured effects also stays
unknown; an explicit empty effect list is malformed.
Action effects inherit from the nearest configured ancestor. HTTP
operations supply their own effects. Renaming a preset does not change how its
requests are described. An explicit, empty `http.operations` list leaves HTTP
requests unknown. A preset without an HTTP section uses the connector's generic
browse/submit actions when its catalog defines their effects.

Policy and audit receive the same frozen snapshot. `Facts.Clone` copies mutable
maps, slices, and pointers while sharing immutable strings. Bodies and
service-specific parameters retain exact JSON numbers. Common fields live at
`input.facts.operation`, `input.facts.parameters`, and `input.facts.context`.
`input.facts.principal.key` and `.name` identify the requesting agent and come from
the monitor's current identity settings. `input.facts.kind` is `operation`,
`admission`, or `message`; omitted kinds from connector descriptions default to
`operation`. Admission and message authorization use this field. Protocol detail
keys do not select authorization behavior.
Protocol details live at `input.facts.details.http`, `input.facts.details.mcp`,
and the corresponding names for other connectors. For example:

```rego
package sentinel

deny contains "restricted host" if {
    input.facts.account == "web"
    input.facts.details.http.host == "restricted.example"
}
```

Owner policies remain in `config.policies`. They can deny requests using both
common and protocol-specific facts. They do not supply operation descriptions.
Unknown requests have a null operation and require approval; malformed or
ambiguous matches are refused. Approval grants and definition hashes stay
outside the facts snapshot. Decisions contain `facts`, `deny`, `gaps`, `next`,
`grant`, and `definition`; the app reads operation, title, parameters, principal,
account, and the current label from `facts`. Audit records add lifecycle fields
and results without duplicating those facts. Failed message evaluations retain
the requesting principal, account, title, and current label.

Configurations without owner policies or custom data use the built-in Go
decision path. Equivalence tests compare it with the shipped Rego rules. Owner
policies and custom data use the complete Rego program, preserving access to its
helper rules. Request evaluation runs outside the global flow lock. Before
admission, the monitor verifies that the configuration snapshot and agent label
are unchanged; otherwise it reevaluates under the lock. Label updates and their
durable writes remain ordered with authorization.

Go computes `next` with the same label observation function used for mailbox
history. Admission leaves the current label unchanged. Observations continue to
record both label axes when their enforcement switches are off.

Saved approvals bind the selected operation, effects, scope, disclosure, relevant
preset definitions, connection settings, and policy program. Current labels and
display titles do not change that binding. A changed operation or configuration
cannot resume under an earlier approval. This schema replaces the old top-level
`operations`, `http_slots`, and `mcp_scope` fields without compatibility aliases.
Custom policies must use the facts paths above. Existing saved approvals do not
apply to the new facts version.

`facts.Version` versions the public snapshot schema. Separately,
`approvalSemanticsVersion` in `policy.go` binds compiled Go behavior into every
approval definition. Bump it when parsing, description, normalization, label, or
approval semantics change, even if the facts schema and Rego sources stay the
same. Display-only changes do not require a bump. Changes to either version
invalidate earlier saved approvals.

GitHub's HTTP section covers REST, Git smart HTTP, and GraphQL. Its MCP section
extracts repository identifiers. The common `public_scope` setting applies the
account's private repository patterns to both protocols. Unlisted API requests
remain unknown.

For an API without a preset, choose **Add account → API → Custom API**. Its API
address limits requests to the configured origin and path. Permissions cover all
requests within that address, including changes and deletions. There is no
read-only access option. Saved approvals bind the origin and connection settings.

API catalogs use resource parents and capability leaves. The most specific
permission override wins. The account and agent views display the same hierarchy.
The [preset generator](../dev/presets/README.md) reads these files as its baseline
and writes proposals under `dev/presets/`. Edit accepted definitions here.
`drafts/` holds records loaded only with `-drafts`; `policy/` contains shared
authorization rules. Service-specific Rego modules are no longer loaded.

The SFTP, MQTT, and NATS presets include setup forms and operation permissions.
See [file and broker protocols](../docs/file-and-broker-protocols.md) for supported
commands, limits, and scoped owner policies.

`dev/setup`, also called by `dev/sandbox`, seeds a fresh store with only the
credential-free Web account. Set `MONITOR_CONFIG=/path/to/config.json` to import
an initial config. Later runs keep stored accounts, credentials, and permissions.
`monitor.example.json` contains placeholders and is never imported automatically.
