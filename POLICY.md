# Policy source

Open **Policy** in the web app to read, edit, or download `policy.toml`.
The saved TOML is authoritative. Monitor derives its runtime configuration from
that source on startup and after every edit. Settings changes, account edits,
pairing, and saved approvals update the same source through go-toml's editing API.
Untouched text and comments stay in place.

Monitor stores the source inside its encrypted state, alongside separately
stored credentials and captured preset definitions. A downloaded file is a copy;
apply it through the web app or CLI to change the running policy. Stored state
requires policy source; legacy JSON configuration is not supported.

## Editing

These are example sections of a policy:

```toml
[monitor]
version = 1

[lattices]
confidentiality = true
integrity = false

[identities.claude.accounts.github]
level = "read"

[identities.claude.accounts.github.actions]
issues = "ask"
```

Account access levels are `off`, `read`, `ask`, and `allow`. Individual action
overrides accept `off`, `ask`, and `allow`. Identity keys, accounts, connection
settings, custom Rego policies, and policy data also live in this file.

Preset overrides merge tables recursively. Scalars and arrays replace inherited
values. A preset override of `{ "$json" = "null" }` deletes the inherited key.
HTTP operations and saved rules use named tables, allowing an edit
to one entry without copying its siblings:

```toml
[presets.custom_api.http.operations.request]
sends = "team"
```

Set `enabled = false` on a named operation or rule to disable it. Remove an
override to inherit its default again. The preset editor saves overrides using
the same rules. Trust requirements come from the effects vocabulary. Both `write`
and `generate` require trust when integrity enforcement is enabled.

Monitor fills in `monitor.presets` with content hashes and retains the referenced
preset definitions in encrypted state. Those pins keep an existing policy's
preset behavior stable across server updates. The effective-policy view expands
these definitions and defaults so you can inspect what the source means.

Credentials live only in encrypted state, keyed by account, connection, and
secret name. Each connector uses a single `secrets` map. Set them through account
settings; policy TOML contains no credential values or markers. Refreshing a
credential leaves policy source unchanged. Source, effective-policy and agent
views contain no credentials.

This format does not load older documents with pointer-keyed credentials or
mailboxes. Migrate those documents before upgrading. Captured presets and owner
overrides must omit operation `id` and `requires_trust` fields. The facts and
approval semantics version is 7; saved approvals need to be granted again.

TOML has no null value. Monitor uses `{ "$json" = "null" }` where an exact JSON
value is needed, including saved approval scopes. The same form preserves numbers
outside TOML's integer range or numbers requiring exact decimal precision. Dates
and times in policy data must be quoted strings.

## Owner CLI

Use the same owner key as the web app, in a private file:

```sh
monitor policy --owner-url https://monitor.example.com --owner-key-file owner.key show > policy.toml
# Edit policy.toml, then validate and review it.
monitor policy --owner-url https://monitor.example.com --owner-key-file owner.key diff policy.toml
monitor policy --owner-url https://monitor.example.com --owner-key-file owner.key apply policy.toml
```

`show --effective` expands presets and defaults. `diff` validates the draft and
shows both source and effective changes. Applying a file replaces the saved
source. Monitor validates and persists the new policy before activating it;
invalid edits or failed saves leave the current policy in force.

## Agent proposals

An agent uses its paired SSH identity:

```sh
monitor policy show
monitor policy propose change.toml --reason 'Allow reading this account for the report'
```

`change.toml` is a TOML fragment merged into the active source. For example:

```toml
[identities.claude.accounts.github]
level = "read"
```

Use `--delete /identities/claude/accounts/github/actions/issues` to remove an
override. Deletion paths are JSON Pointers; repeat the flag for multiple paths.
Pass `-` as the file name to read TOML from stdin.

Agents can inspect and propose changes to their own account permissions and
rules, policy settings on accounts they can reach, and the lattice switches.
They cannot inspect credentials, connection settings, or other identities, and
cannot apply edits. Each proposal waits as an approval card that shows the source
and effective changes. **Allow once** applies the proposal atomically, and **Deny**
rejects it. The agent's command waits for the answer. If the owner does not answer
before the approval wait ends, the proposal expires. If the active source changes
before approval, the proposal fails and the agent must submit a new one.

The owner API exposes `GET /policy`, `GET /policy?effective`,
`POST /policy/preview`, and `POST /policy`. These two POST endpoints take a JSON object
with a `source` string. Proposals appear in `GET /requests`, and the owner answers
them with `POST /requests/{id}` like other approvals. On the agent's SSH transport,
`agent.monitor` provides `GET /policy` and `POST /policy/proposals`. Proposal
submissions take `source`, `reason`, and optional `delete`, an array of arrays of
path components. The response arrives after the owner answers.

Account settings and pairing use `POST /policy/edits`. Each change replaces one
source value or explicitly deletes it. Values can contain JSON null without
turning it into a deletion:

```json
{"changes":[
  {"path":["identities","claude","accounts","github","level"],"value":"read"},
  {"path":["identities","claude","rules","old-approval"],"delete":true}
]}
```

Edits compile once outside the authorization transaction. Publication checks that
policy and credentials have not changed, persists the document, and installs the
prepared state. Concurrent label updates are retained. A credential
replacement persists through its existing handle without recompiling policy.
