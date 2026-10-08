Each preset has a `<name>.json` record and may have a shipped `<name>.rego`
module. Accounts select it with `"preset": "<name>"`.

These JSON files are also the baseline for the [API preset generator](../dev/presets/README.md).
Edit accepted definitions here. The generator reads them directly and writes
proposals and reports to ignored directories under `dev/presets/`.
`drafts/` holds presets loaded only when a development monitor uses `-drafts`;
`policy/` holds the shared policy modules used by shipped presets.

The SFTP, MQTT, and NATS protocol presets include setup forms and operation
permissions. See [file and broker protocols](../docs/file-and-broker-protocols.md)
for client commands, supported versions, limits, and scoped owner policies.

For an API without a preset, choose **Add account → API → Custom API**. The form
accepts an HTTPS API URL, bearer token or API key in a header or query parameter,
and optional agent access. A path in the URL limits access to that path and its
children. The account page supplies a placeholder and shows where the agent
should send it through the monitor. The real credential stays in the account's
HTTP values and is redacted from the owner view.

Custom API permissions cover all requests within the configured address. `Ask`
requests approval; `Allow` permits requests subject to the usual data-sharing,
trust, and owner policy checks. The monitor does not infer which endpoints are
read-only, so this preset has no read-only access option. Saved approvals bind
the origin and connection settings. Use a service-specific preset when actions
need separate permissions.

JSON contains `title`, `catalog`, and optional `operations`. The catalog holds
setup fields, connections, defaults, and actions. Action entries may supply
effects for the module, inherited from the nearest action ancestor. Record
operations keep their own effects; the app
shows the union of effects within a permission group. Missing operations mean
an empty list. A present `operations` value must be an array.

The full resolved JSON is available at `data.presets.<name>`. A module uses
`package handlers.<name>` and supplies `operation`, optional `title`, and
optional `deny` rules. The shared policy selects that module for all requests
on the preset, including requests it cannot recognize. Without a module, it
uses `data.monitor.api`. A module can explicitly delegate to that matcher,
carrying its operation, title, and denials together. See `github.rego`.

An owner's `config.presets` entry replaces the entire JSON record of the same
name. The shipped module still applies. Drafts load JSON only. Owner Rego
continues to live in `config.policies`; the `custom` preset recognizes
`data.sentinel.operation`.

GitHub's REST operations now live in `github.json`. They retain the former
`github_api` operation IDs, effects, scopes, and grants, and use GitHub's
permission names: `open.issues`, `comment`, `open.pulls`, `merge`, and `push`.
The module handles Git smart HTTP, GraphQL, and MCP, and applies the account's
public/private repository settings across protocols. Unlisted REST requests
are unknown and require approval. They no longer inherit a blanket read rule.

Stored configs migrate during unlock. Legacy configuration patches also migrate
before validation. Migration replaces `template` and `policy_options.preset`
with `preset`, and maps permissions on shipped `github_api` accounts to the
combined GitHub actions. Owner-defined `github_api` records retain their name
and generic matcher. Connections and credentials stay as configured;
migration does not add an MCP connection.

`dev/setup`, also called by `dev/sandbox`, seeds a fresh store with only the
credential-free Web account. Set `MONITOR_CONFIG=/path/to/config.json` to
import a custom initial config instead. Later runs keep the stored accounts,
credentials, and dev agent permissions. `monitor.example.json` is a reference
with placeholder credentials, and is never imported automatically.

Review custom policies separately. References to `input.account.template` and
`input.account.policy_options.preset` now use `input.account.preset`.
`data.templates.<name>` becomes `data.handlers.<name>`, except for the generic
matcher, which becomes `data.monitor.api`. A check for `template == "api"`
must name the relevant presets instead. Migration does not rewrite Rego.

Moving the policy sources changes the program digest, so existing saved
approvals no longer apply. Later display edits do not change approval
definitions. Changes to operation records, resolved effects, and connection
settings still do.
