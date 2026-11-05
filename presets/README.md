Each shipped preset has a `<name>.json` record. Accounts select it with
`"preset": "<name>"`. Monitor accepts only these shipped definitions.

For the authoring and test workflow, see [adding protocol presets](../dev/presets/README.md#adding-protocol-presets).

## Slack Socket Mode

`slack_socket_mode.json` adds a separate **Slack Socket Mode** connection using
the shared HTTP/WebSocket connector. Enable Socket Mode in the Slack app and set
an app-level `xapp-` token with `connections:write`. The normal **Slack** connection
uses a separate bot/user token for Web API calls.

The app token is substituted only in the Authorization header for
[`apps.connections.open`](https://docs.slack.dev/reference/methods/apps.connections.open),
which returns a temporary WebSocket URL. The client SDK manages the session and
reconnection, following [Slack's protocol](https://docs.slack.dev/apis/events-api/using-socket-mode).

The opening POST accepts an empty body, JSON or form. WebSocket handshakes use
port 443, `/link/`, and `ticket`, `app_id` and `debug_reconnects` query parameters.
Supported hosts are `wss.slack.com`, `wss-primary.slack.com` and
`wss-backup.slack.com`; other returned hosts require a reviewed preset update.

Permissions are `connect` (session), `receive` (read) and `respond` (send).
All acknowledgements count as send because they can contain interactive responses.
The whole response is bound to approval scope, not just its envelope ID; read-only
access therefore cannot acknowledge events.

Incoming deliveries use the account's contents/trust labels and remain opaque to
policy. Monitor does not filter them by channel or correlate acknowledgement IDs
with received envelopes. These descriptors authorize traffic, not validate the
complete Slack message schema.

The temporary `ticket` is a bearer credential. `http.sensitive_query` replaces it
with a SHA-256 fingerprint before description, so policy, approval scope and audit
see the fingerprint while the upstream request keeps the real value.

## Preset format and authorization

The catalog contains setup fields, connections, defaults, and permission actions.
Protocol definitions have their own sections:

- `http.operations` maps operation IDs to reviewed HTTP operations, including GraphQL matchers. IDs also determine candidate evaluation order; ambiguous matches are rejected.
- `http.slots` requires requests to stay within the connection's configured API addresses.
- `http.sensitive_query` lists high-entropy bearer query values to fingerprint before capture, including unknown or invalid requests. Extracted parameters see the same fingerprints, preserving approval distinctions without retaining the credentials. Literal query-value matchers cannot use these fields.
- `mcp.scope` selects service resource identifiers from MCP tool arguments.
- `public_scope` names the extracted parameters that identify public or private resources across protocols.

For example:

```json
{
  "title": "Example",
  "catalog": {"actions": {"items.read": {"title": "Read items"}}},
  "http": {
    "operations": {"items.get": {
      "action": "items.read",
      "effects": ["read"],
      "method": "GET",
      "origin": "https://api.example.com",
      "path": "/items/{id}",
      "scope": {"id": {"from": "path", "at": "id"}}
    }}
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
operations. HTTP metadata selectors use the shared JSON field conversion.
The shared `facts` package defines the snapshot, owns label
observation, and supplies label ordering and the effect vocabulary. The same
effect vocabulary drives preset validation and the app's permission display.
Go computes `operation.obligations` and `operation.lineage` for Rego to read.
These facts are included in each operation's approval definition hash. `facts.Details` has typed fields for each protocol, such as
`f.Details.HTTP.Method` and `f.Details.MCP.Arguments`. Protocol data types live in
`facts`; parsing and description methods stay in their connectors. A new protocol
adds its detail type to `facts`.

A parsed request implements `connector.Request.Describe`. It returns facts,
with non-serialized approval scope and definition dependencies, and any
validation error. It must not mutate its input or perform I/O. The monitor
supplies the live connector, typed policy options, and protocol preset on every
evaluation, including after
an owner approves a waiting request.

`policy.go` finalizes every description by resolving catalog effects, account
labels, and public/private resource settings. Effects and configured labels are
validated when loaded or compiled. Connectors supply request kinds, which default
to `operation`. The monitor treats an empty action or one without configured
effects as unknown; preset compilation rejects explicit empty effect lists.
Action effects inherit from the nearest configured ancestor. HTTP
operations supply their own effects. Renaming a preset does not change how its
requests are described. An explicit, empty `http.operations` map leaves HTTP
requests unknown. A preset without an HTTP section uses the connector's generic
browse/submit actions when its catalog defines their effects.

Policy and audit receive independent views of the same JSON snapshot.
`Facts.Snapshot` uses standard JSON encoding and preserves exact numbers
in bodies and service-specific parameters. Common fields live at
`input.facts.operation`, `input.facts.parameters`, and `input.facts.context`.
`input.facts.principal.key` and `.name` identify the requesting agent and come from
the monitor's current identity settings. `input.facts.kind` is `operation`,
`admission`; omitted kinds from connector descriptions default to
`operation`. Admission authorization uses this field. Protocol detail
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

Owner policies remain in `config.policies`. They can deny requests or require
approval using both common and protocol-specific facts. They do not supply
operation descriptions.
Unknown requests have a null operation and require approval; malformed or
ambiguous matches are refused. Approval grants and definition hashes stay
outside the facts snapshot. Decisions contain `facts`, `deny`, `requirements`, `next`,
`grant`, and `definition`; the app reads operation, title, parameters, principal,
account, and the current label from `facts`. Audit records add lifecycle fields
without duplicating those facts.

The Rego rules in `../internal/policy/` compute access restrictions, label-flow checks, and
saved approval waivers. Every request evaluates the same prepared query,
`data.monitor.decision`. Owner policies receive `input.facts` and
`input.authorization`; they can also read `data.monitor.gaps` to inspect remaining
approval requirements. Lattice settings are available in `data.lattices`, and
label levels in `data.levels`. Description errors are appended to denials in Go.
`data.sentinel.deny` adds owner denial messages. Owner policies cannot define
rules or data under `monitor`, `lattices`, or `levels`, which the monitor reserves.
An undefined deny rule adds no restrictions. A defined rule must return a set or
array of strings; malformed output and evaluation errors refuse the request.

`data.sentinel.approvals` adds approval requirements. For example:

```rego
package sentinel

approvals contains {"id": "owner.payment_limit", "message": "Payments above $500 need approval."} if {
    input.facts.account == "payments"
    "pay" in input.facts.operation.effects
    input.facts.parameters.amount > 500
}
```

The amount field must be extracted by the preset; the rule uses the units of that
field. Built-in requirements still apply, including the default approval for
payments. A custom requirement also applies when an action override allows the
operation.

An undefined approvals rule adds no requirements. A defined rule must return a
set or array of objects containing exactly `id` and `message`. IDs must start
with `owner.`, followed by an ASCII letter or digit and then letters, digits,
underscores, dots, or hyphens. Messages must be nonempty strings. Repeated
identical entries are accepted; conflicting messages for one ID, malformed
entries, and evaluation errors refuse the request. Owner requirements add to
built-in checks and cannot override a denial.

`requirements` contains the remaining `{id, message}` objects, including
explanations for built-in requirements. Saved rules carry the same collection;
only each requirement's ID grants authority. Messages are for display.
Saved approvals waive IDs for the same operation, scope, and definition.
Use a stable ID for each requirement. A new requirement that appears while a
request waits cannot be covered by an approval of the earlier requirements.
Policy and data edits invalidate saved approvals through the existing definition
hash, including edits to literal messages in policy source.

Approval rules can inspect `data.monitor.base_gaps`, the remaining built-in
requirements after saved waivers. Denial rules can inspect `data.monitor.gaps`,
which also includes custom requirements. An approval rule that depends on the
final gaps or reasons is recursive and is rejected when the policy is compiled.
Custom requirements can pause operations and connection admission.

Configuration publication requires compiled accounts, presets, selectors, and
Rego. Request handlers accept those compiled types and never compile on demand.
`facts.Facts.Snapshot` encodes facts with `encoding/json` and decodes independent
audit and policy views with `facts.DecodeNumbers`. The audit view retains the original
encoding, including exact numbers and JSON omission rules.
OPA receives a fresh lazy object for each evaluation.

`monitor.transact` owns configuration publication, labels, approval
records, and stream retirement under one mutex. Connector requests read the
current configuration and label, evaluate, record the decision and persist the
observation in one transaction.

Approval waits release the transaction. Resuming a request requires a fresh
check of the approved operation and requirement IDs. Owner HTTP bodies are read
before the transaction. Handlers explicitly capture or update state under the
lock, then write responses after it ends. Compilation and OAuth network calls
run outside the transaction.

Observations use the same commit path. Failed persistence keeps restrictive
labels in memory and marks the request refused. A later observation retries any
outstanding label write.

Go computes `next` by joining the current label with the observation.
Admission leaves the current label unchanged. Observations continue to
record both label axes when their enforcement switches are off.

Saved approvals bind the selected operation, effects, scope, disclosure, relevant
preset definitions, connection settings, and policy program. Current labels and
display titles do not change that binding. A changed operation or configuration
cannot resume under an earlier approval. This schema replaces the old top-level
`operations`, `http_slots`, and `mcp_scope` fields without compatibility aliases.
Custom policies must use the facts paths above. Existing saved approvals do not
apply to the new facts version.

`facts.Version` versions the public snapshot schema and binds compiled Go
behavior into every approval definition. Bump it when parsing, description,
normalization, label, or approval semantics change, even if the facts schema and
Rego sources stay the same. Display-only changes do not require a bump. A version
change invalidates earlier saved approvals.

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
Authorization rules live in `../internal/policy/`; owner Rego policies live in
`config.policies`.

The SFTP, MQTT, and NATS presets include setup forms and operation permissions.
See [file and broker protocols](../docs/file-and-broker-protocols.md) for supported
commands, limits, and scoped owner policies.

IMAP and Redis destinations require `imaps://` and `rediss://` URLs. Configuration
validation rejects plaintext and unknown schemes before a connection starts.

`dev/setup`, also called by `dev/sandbox`, seeds a fresh store with only the
credential-free Web account. Set `MONITOR_CONFIG=/path/to/config.json` to import
an initial config. Later runs keep stored accounts, credentials, and permissions.
`monitor.example.json` contains placeholders and is never imported automatically.
