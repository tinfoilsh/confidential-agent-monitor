Each shipped preset has a `<name>.json` record. Accounts select it with
`"preset": "<name>"`. Monitor accepts only these shipped definitions.

## Adding a named protocol connection

A service inventory is not a protocol contract. Start with the workflow you need
(open a session, receive a message, acknowledge it, reconnect), then identify the
vendor documentation and SDK that describe each step. Prefer a supported standard
specification, but do not invent a scraper merely to label handwritten protocol
rules as generated. `dev/presets` imports request descriptions; it does not infer
an entire session protocol from an HTTP operation that returns a URL.

For a protocol-specific connection:

1. Record the vendor references, SDK version, credential type and protocol
   boundaries. Distinguish observed destinations from a documented permanent
   allowlist; a tutorial hostname is not a guarantee about production endpoints.
2. Capture the SDK against an offline transport with synthetic credentials. Keep
   the request method, body encoding, authentication placement and message shapes
   as fixtures. Include error/control deliveries, not only successful events.
3. Add a shipped preset with the existing catalog/setup conventions and shared
   connector where possible. Use a separate preset when credentials, authority or
   lifecycle differ; do not implicitly add a new endpoint to every existing account.
4. Review effects, labels and saved-approval scope separately from parsing. Bind
   every outgoing response field that can contain content. A protocol message
   called an acknowledgement may also send a reply or update a modal.
5. Exercise the real parser and per-message gate, including negative cases:
   wrong origin/path/port, duplicate fields, missing selectors, unsupported frames,
   credential misplacement, unexpected query parameters and overlapping operations.
   Reconnect through a new admitted connection. Follow repository conventions for
   local Go test overlays; do not force-add ignored Go test files.
6. Run bounded online checks with explicit expectations. An unauthenticated error
   proves reachability, not authenticated functionality. Before deployment, test
   an authorized real session and its reconnect without recording live tokens or
   tickets in fixtures. Never widen a host pattern just to make a test pass.
7. On an SDK/vendor change, reproduce the capture, review its diff and rerun the
   workflow/negative tests before updating the pinned fixture. Report unsupported
   capabilities explicitly; endpoint counts do not prove integration coverage.

### Slack Socket Mode

`slack_socket_mode.json` is a deliberately handwritten, separately selectable
**Slack Socket Mode** connection. It uses the existing HTTP/WebSocket connector,
not raw TCP or a new runtime. It does not change the existing Slack Web API account.

References:

- [Slack's connection-opening method](https://docs.slack.dev/reference/methods/apps.connections.open)
- [Slack's Socket Mode protocol](https://docs.slack.dev/apis/events-api/using-socket-mode)
- [App-level connections:write scope](https://docs.slack.dev/reference/scopes/connections.write)
- [Python Slack SDK v3.38.0](https://github.com/slackapi/python-slack-sdk/tree/v3.38.0)

Setup: enable Socket Mode for the Slack app, create an app-level `xapp-` token with
`connections:write`, and set it through the connection's credential settings.
It is not the bot/user token in the separate **Slack** connection. Monitor only
substitutes the app token in the Authorization header at
`https://slack.com/api/apps.connections.open`; it is not sent to WebSocket hosts.
The SDK receives the temporary connection URL and manages the session/reconnects.

The opening POST recognizes no body (Python SDK behavior), JSON and form. Socket
handshakes recognize HTTPS port 443, `/link/`, and only `ticket`, `app_id` and
`debug_reconnects` query parameters. The current bounded destination set is
`wss.slack.com`, `wss-primary.slack.com` and `wss-backup.slack.com` with literal
operation origins. Slack's examples are not an exhaustive hostname contract: a
returned URL outside that set remains unsupported and must be investigated, not
accepted by changing the origin to `*` or permitting all of `*.slack.com`.

Permissions are `connect` (session), `receive` (read) and `respond` (send).
**Every response**, including a bare acknowledgement or JavaScript's empty
`payload: {}`, is conservatively classified as send. The entire JSON response is
bound, not just its envelope ID. This deliberately avoids treating payload-bearing
slash-command, menu or modal responses as harmless reads. A read-only grant does
not permit acknowledgements; grant the needed send permission explicitly. These
are authorization descriptors, not a complete Slack response-schema validator.

Incoming messages are authorized per delivery as opaque data with the account's
contents/trust labels. `hello`, normal events, rate-limit notifications and
`disconnect` do not require the same nested payload shape. **Monitor does not
filter incoming events by channel** or correlate response envelope IDs with
previous deliveries. Configure the app's Slack permissions/subscriptions narrowly;
CCH's own channel filter is not an equivalent Monitor security boundary.

The temporary WebSocket `ticket` is a bearer capability. The current shared HTTP
capture includes query parameters in owner-visible request/audit details. Do not
export real handshake captures or treat these tickets as harmless fixture text.
This is a limitation to review before production use, not a claim that Socket Mode
has the same credential-redaction properties as static placeholder substitution.

Reproduce SDK wire shapes (no Slack account or credentials needed):

```sh
python3 -m venv /tmp/monitor-slack-sdk
/tmp/monitor-slack-sdk/bin/pip install slack_sdk==3.38.0
/tmp/monitor-slack-sdk/bin/python dev/check-slack-socket-mode.py --check dev/fixtures/slack-socket-mode.json
# Optional bounded public endpoint checks: deliberately no credentials or real tickets.
/tmp/monitor-slack-sdk/bin/python dev/check-slack-socket-mode.py --check dev/fixtures/slack-socket-mode.json --online
```

The committed fixture contains synthetic values only. The online check expects
`not_authed` for the opening method and probes one invalid-ticket handshake; this
is **not** a successful end-to-end Slack session. Authenticated event delivery,
app-specific hostname selection and real reconnect behavior still need a live test.
Thread-history/modal Web API variants are a separate integration concern.

For an authenticated local test, use the same venv and a Go installation matching
`go.mod`, from the repository root:

```sh
/tmp/monitor-slack-sdk/bin/python dev/slack-socket-live.py --duration 180 --reconnect-after 60
# Or use an explicitly supplied, ignored file containing literal token assignments:
chmod 600 .env
/tmp/monitor-slack-sdk/bin/python dev/slack-socket-live.py --env-file .env --duration 180 --reconnect-after 60
# Optional deliberate workspace mutation: send one labelled message to this channel.
/tmp/monitor-slack-sdk/bin/python dev/slack-socket-live.py --channel C0123456789 --post-test
```

Use a dedicated test Slack app, not a production bot: multiple Socket Mode clients
can receive different events from the same app. In the optional posting example,
replace `C0123456789` with the intended test channel ID.

The launcher builds the Go helper before reading credentials. Enter the `xoxb-`
bot token and `xapp-` app token at its hidden terminal prompts, or supply a private
`--env-file` containing `SLACK_BOT_TOKEN=...` and `SLACK_APP_TOKEN=...`. The file
must be owned by you, inaccessible to other users, and not a symlink. Values are
literal (optional enclosing quotes); no shell interpolation or execution occurs.
The repository's root `.env` is ignored. Never put values in flags, inherited
environment variables, chat, or tracked files. Remove the file when testing is
over. Tokens pass over stdin to the helper, which creates no additional credential
files. The SDK subprocess receives only public placeholders.
The helper runs two loopback CONNECT proxies with the real shipped JSON, shared
HTTP/WebSocket connector, guarded dialer, credential substitution, and normal
upstream TLS verification. A temporary **public CA certificate** lets that SDK
trust the local test proxy; its signing key stays in memory and nothing is
installed in the system trust store. Source hashes identify the compiled presets.
Only bot `auth.test` is admitted by default on the HTTP connection; one explicitly
requested test post is restricted to the supplied channel. Socket events are
received and acknowledged; their contents and temporary URLs are not printed.
Ctrl-C stops the client/proxies and removes temporary build/certificate files.

This harness is not the full Monitor: it uses a test-operation allowlist instead
of the Monitor policy engine, writes no audit records, and does not exercise
sandbox enrollment or durable secret storage. A successful session validates the
real connector against Slack, not the entire sandbox application. A zero-event timeout
is not evidence that app event subscriptions work. SDK reconnect can request a
new hostname outside the bounded preset; that is a real unsupported case to
review, not a reason to skip TLS checks or silently widen destinations.

## Preset format and authorization

The catalog contains setup fields, connections, defaults, and permission actions.
Protocol definitions have their own sections:

- `http.operations` maps operation IDs to reviewed HTTP operations, including GraphQL matchers. IDs also determine candidate evaluation order; ambiguous matches are rejected.
- `http.slots` requires requests to stay within the connection's configured API addresses.
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
