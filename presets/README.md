Each shipped preset has a `<name>.json` record. Connections select it with
`"preset": "<name>"`. Perimeter accepts these shipped definitions and those in the `-presets` directory.

For authoring, see [adding protocol presets](../dev/presets/README.md#adding-protocol-presets).
Provider request definitions live in the JSON files; SDK scenarios and coverage
live in [tf-test's use cases](https://github.com/tinfoilsh/tf-test/tree/eaf007c2890ca041df40a2cf3bc79c23507bb8cf/services/connections-flywheel/usecases).
For local live smoke checks and service setup, see the
[manual connector tests](../dev/manual_tests/README.md).

## Preset format and authorization

The catalog contains setup fields, the connection's default setup under its kind,
defaults, and permission actions. Field paths are relative to the connection. A
`credential` field sets the connection's credential its key names.
Protocol definitions have their own sections:

- `http.operations` maps operation IDs to reviewed HTTP operations, including GraphQL matchers. IDs also determine candidate evaluation order; ambiguous matches are rejected.
- An operation's optional `path_patterns` maps capture names to Go regular expressions. Each expression must match the entire captured value and is checked before ambiguity detection. Unknown capture names and invalid expressions fail compilation. For example, `"path_patterns": {"release_id": "[0-9]+"}` keeps GitHub release-by-ID requests distinct from `/releases/latest`. This is a matching constraint, not a scope type conversion; extracted IDs remain strings. Literal routes do not automatically outrank parameter routes. Constraints require a Perimeter version supporting this field.
- `http.slots` requires requests to stay within the connection's configured API addresses.
- `http.sensitive_query` lists high-entropy bearer query values to fingerprint before capture, including unknown or invalid requests. Extracted parameters see the same fingerprints, preserving approval distinctions without retaining the credentials. Literal query-value matchers cannot use these fields.
- `mcp.scope` selects service resource identifiers from MCP tool arguments.
- `grant` on an HTTP operation or `mcp` names the scope fields a saved approval binds. Omitted, it binds every parameter; `[]` binds none.
- `public_scope` names the extracted parameters that identify public or private resources across protocols.

For example:

```json
{
  "title": "Example",
  "catalog": { "actions": { "items.read": { "title": "Read items" } } },
  "http": {
    "operations": {
      "items.get": {
        "action": "items.read",
        "effects": ["read"],
        "method": "GET",
        "origin": "https://api.example.com",
        "path": "/items/{id}",
        "scope": { "id": { "from": "path", "at": "id" } }
      }
    }
  },
  "mcp": {
    "scope": { "id": { "at": "/id", "optional": true } }
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
`facts.Details` has typed fields for each protocol, such as
`f.Details.HTTP.Method` and `f.Details.MCP.Arguments`. Protocol data types live in
`facts`; parsing and description methods stay in their connectors. A new protocol
adds its detail type to `facts`.

A parsed request implements `connector.Request.Describe`. It returns facts,
with non-serialized approval scope and definition dependencies, and any
validation error. It must not mutate its input or perform I/O. The Perimeter
supplies the live connector, typed policy options, and protocol preset on every
evaluation, including after
an owner approves a waiting request.

`policy.go` finalizes every description by resolving catalog effects, connection
labels, and public/private resource settings. Effects and configured labels are
validated when loaded or compiled. Connectors supply request kinds, which default
to `operation`. The Perimeter treats an empty action or one without configured
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
the Perimeter's current identity settings. `input.facts.kind` is `operation`,
`admission`; omitted kinds from connector descriptions default to
`operation`. Admission authorization uses this field. Protocol detail
keys do not select authorization behavior.
Protocol details live at `input.facts.details.http`, `input.facts.details.mcp`,
and the corresponding names for other connectors. For example:

```rego
package sentinel

deny contains "restricted host" if {
    input.facts.connection == "web"
    input.facts.details.http.host == "restricted.example"
}
```

Owner policies remain in `config.policies`. They can deny requests or require
approval using both common and protocol-specific facts. They do not supply
operation descriptions.
Unknown requests have a null operation and require approval; malformed or
ambiguous matches are refused. Approval grants stay
outside the facts snapshot. Decisions contain `facts`, `deny`, `requirements`, `next`,
and `grant`; the app reads operation, title, parameters, principal,
connection, and the current label from `facts`. Audit records add lifecycle fields
without duplicating those facts.

The Rego rules in `../internal/policy/` compute access restrictions, label-flow checks, and
saved approval waivers. Every request evaluates the same prepared query,
`data.perimeter.decision`. Owner policies receive `input.facts` and
`input.authorization`; they can also read `data.perimeter.gaps` to inspect remaining
approval requirements. Lattice settings are available in `data.lattices`, and
label levels in `data.levels`. Description errors are appended to denials in Go.
`data.sentinel.deny` adds owner denial messages. Owner policies cannot define
rules or data under `perimeter`, `lattices`, or `levels`, which the Perimeter reserves.
An undefined deny rule adds no restrictions. A defined rule must return a set or
array of strings; malformed output and evaluation errors refuse the request.

`data.sentinel.approvals` adds approval requirements. For example:

```rego
package sentinel

approvals contains {"id": "owner.payment_limit", "message": "Payments above $500 need approval."} if {
    input.facts.connection == "payments"
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
Saved approvals waive IDs for the same facts version, connection, operation, and scope.
Use a stable ID for each requirement. A new requirement that appears while a
request waits cannot be covered by an approval of the earlier requirements.
Saved approvals survive policy and data edits: a requirement they do not name
still asks. An edit to a connection's setup or preset removes its saved approvals.

Approval rules can inspect `data.perimeter.base_gaps`, the remaining built-in
requirements after saved waivers. Denial rules can inspect `data.perimeter.gaps`,
which also includes custom requirements. An approval rule that depends on the
final gaps or requirements is recursive and is rejected when the policy is compiled.
Custom requirements can pause operations and connection admission.

Configuration publication requires compiled connections, presets, selectors, and
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

Saved approvals name their connection, operation, scope, and the requirement IDs
they waive; a disclosure requirement's ID names its audience. This schema replaces the old top-level
`operations`, `http_slots`, and `mcp_scope` fields without compatibility aliases.
Custom policies must use the facts paths above.

`facts.Version` versions the public snapshot schema and is recorded in every
saved approval. Bump it when parsing, description,
normalization, label, or approval semantics change, even if the facts schema and
Rego sources stay the same. Display-only changes do not require a bump. A version
change invalidates earlier saved approvals.

GitHub's HTTP section covers REST, Git smart HTTP, and GraphQL. The GitHub MCP
preset's section extracts repository identifiers. Both presets' `public_scope`
applies the connection's private repository patterns. Unlisted API requests
remain unknown.

For an API without a preset, choose **Add connection → API → Custom API**. Its API
address limits requests to the configured origin and path. Permissions cover all
requests within that address, including changes and deletions. There is no
read-only access option.

API catalogs use resource parents and capability leaves. The most specific
permission override wins. The connection and agent views display the same hierarchy.
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
credential-free Web connection. Set `MONITOR_CONFIG=/path/to/config.json` to import
an initial config. Later runs keep stored connections, credentials, and permissions.
`monitor.example.json` contains placeholders and is never imported automatically.
