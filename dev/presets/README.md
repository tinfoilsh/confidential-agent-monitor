# Preset descriptor generation

This tool inventories API requests and proposes monitor actions, effect sets, resource scopes, and saved-approval grants. It does not generate full request/response schemas. Run `generate` to create a local coverage index at `coverage/README.md` with the current results and remaining gaps.

## Adding protocol presets

Not every shipped preset comes from this generator. Protocols described in prose
can use a reviewed, handwritten definition with SDK fixtures. For example,
`generate slack` covers Web API requests, not the separate
[Slack Socket Mode definition](../../presets/slack_socket_mode.json).

1. Identify the workflow and vendor references, credential types, destinations,
   and SDK version. State which capabilities the sources actually cover.
2. Capture the SDK with synthetic credentials and keep versioned request/message
   fixtures, including control and error messages.
3. Define setup, actions, effects and approval scope using the existing connector
   where possible. Review credential placement and content-bearing responses.
4. Test recognition and refusal cases through the real parser and gate: origins,
   encodings, malformed messages, credential placement, permissions and reconnects.
5. Test an authorized live session. Distinguish endpoint reachability from event
   delivery and record the tested workflow, not a claim of complete API coverage.
   Repeat the checks when SDKs or definitions change.

The [manual test tools](../manual_tests/README.md) share connector setup across
Slack and Grafana. Slack includes a synthetic SDK fixture and capture mode for
inspecting changes. These are not automatic freshness checks.
Keep live tokens and temporary connection tickets out of fixtures and shared logs.

OpenAPI server base paths belong in operation paths, not in a configurable
origin. For example, Grafana's pinned spec declares `servers: [{url: /api}]`, so
its health operation is `/api/health`, not `/health`. Its `sources.json` entry maps
to the shipped `grafana` preset. Check routes against the vendor input as well as
the preserved baseline: a `shipped_override` can preserve an old mistake.

## Generation commands

Run commands from `dev/presets`. This directory is a separate Go module, so use `GOWORK=off`.

`generate` is the single candidate pipeline. The old `draft` command and its
credential catalog inference have been removed; existing static draft presets
remain available to the development monitor.

```sh
# Reproduce candidates from the locked inputs.
GOWORK=off go run . fetch slack anthropic airtable
GOWORK=off go run . generate slack anthropic airtable
GOWORK=off go run . check slack anthropic airtable

# Inventory every source mapped to a shipped API preset.
GOWORK=off go run . generate
GOWORK=off go run . check

# Regroup existing shipped operations without adding endpoints.
GOWORK=off go run . group
# Then refresh candidates and their coverage reports.
GOWORK=off go run . generate
```

`generate` and `check` return a nonzero exit status for missing or failed sources. They continue through the other selected providers, preserving useful results and writing an error report for each failure. The current all-provider commands fail for six configured source gaps: Dropbox, Salesforce, Shopify, Supabase, WooCommerce, and WordPress.

The files have different roles:

| Location | Purpose |
| --- | --- |
| `sources.json` | Provider mappings, source formats, API families, filters, and exclusions |
| `sources.lock.json` | Resolved source URLs, commits, content hashes, and successful refresh timestamps |
| `.cache/` | Downloaded source bytes, verified against the lock before parsing |
| `snapshots/` | Exact normalized bytes for mutable Airtable and Slack documentation sources |
| `../../presets/*.json` | Authoritative shipped definitions, used directly as the generation baseline |
| `candidates/` | Expanded preset proposals, never loaded by the monitor automatically |
| `coverage/` | Source-to-descriptor mappings, provenance, gaps, overlaps, and artifact hashes |

Git ignores `.cache/`, `candidates/`, `coverage/`, `snapshots/`, and temporary `.generate-*` files. Keep the generator code, source definitions and lock, and shipped presets in version control. Run `fetch` and `generate` before checking candidates in a fresh checkout. If an upstream source no longer serves the locked content, restore the matching local cache or snapshot, or run `update` for that provider and review the changed lock before regenerating.

HTTP definitions live under `http.operations`, an object keyed by operation ID;
protocol sections such as `mcp` remain separate.

Regeneration reads the shipped presets on every run and preserves their operation IDs, effects, request constraints, scopes, grants, and destinations. It groups actions by resource and writes candidates and coverage reports. There is no separate baseline folder to keep in sync. Changing a shipped preset invalidates its previous coverage report until regeneration.

Actions use resource paths followed by a capability, such as `repos.hooks.read`,
`orgs.hooks.admin`, or `customers.write`. Catalog entries include every parent,
so the app can collapse groups and set permissions at any level. Effects stay
on each operation and continue to determine its obligations independently of
its display group. Read operations receive resource-specific actions too.

Grouping uses enclosing URL resources, strips transport/version segments and
terminal operation verbs, and handles dotted RPC methods. GraphQL uses schema
return types when available, falling back to field names. Source categories
provide a fallback for paths without literal resources. A source can override
an ambiguous group in `sources.json` with `"groups": {"operationId": "resource.subresource"}`.
These keys name source operation IDs; unknown keys and malformed group paths
are errors. `generate` uses these rules.

`group [preset-or-source...]` writes the grouping into shipped presets, using
only their existing operations. With no arguments it processes all shipped API
presets. It uses cached source metadata where available and otherwise the shipped
routes. Native and MCP presets keep their protocol/tool action catalogs, which
use the same tree UI. Repeated grouping produces the same result. This is a
breaking action-name change: update agent overrides and custom policies to use
the new names. No aliases or permission migration are generated.

Accept additions in the corresponding `../../presets/<name>.json`, preserving its account setup and existing operations. Source names can differ from preset names; use the `preset` mapping in `sources.json`. The Confluence source group includes Jira, so divide its operations between the Confluence and Jira presets instead of copying the combined candidate into either one. Regenerate after accepting changes so the next proposal uses the updated shipped definitions.

Each source variant receives a status:

| Status | Meaning |
| --- | --- |
| `shipped_override` | A shipped definition has the same route and encoding. Its deliberate restrictions still apply. This status records that it is shipped, not an independent semantic review. |
| `needs_review` | The generator proposed a descriptor. Permissions and resource semantics still need review. |
| `unsupported` | No usable descriptor could be produced; `reason` explains the gap. |
| `archived_schema` | A current method is indexed, but its request definition comes from an older source or preserved override. |

`missing_params` identifies documented query parameters rejected by an existing definition. `unmapped_shipped` lists shipped definitions without a source mapping. These may be deliberate extensions, deleted upstream operations, or source omissions; generation does not delete them. Conflicting descriptors remain visible instead of being merged away. Accepting a candidate does not clear these gaps, and requests that match multiple operations remain refused by policy.

An accounted inventory does not prove that all vendor APIs were selected or that the proposed permissions are correct. API families and filters in `sources.json` define the denominator. Matching an existing route also does not prove every documented request passes its reviewed constraints. `check` validates artifact consistency, mappings, and counts. Additional gates are available:

```sh
# Fail while recorded semantic reviews, unsupported requests, archived schemas,
# parameter gaps, overlaps, or source warnings remain.
GOWORK=off go run . check --reviewed slack anthropic airtable

# Also require a successful upstream check within the last 30 days.
GOWORK=off go run . check --max-age=720h slack anthropic airtable

# Refresh named upstream sources, then regenerate and inspect the differences.
GOWORK=off go run . update slack anthropic airtable
GOWORK=off go run . generate slack anthropic airtable
```

An unqualified `update` resolves changed source definitions. `update --all` refreshes every configured source, including unchanged upstream URLs. A failed refresh preserves the prior lock and returns an error. Older lock entries have no `checked_at`; the age gate rejects them until refreshed. External request-schema references must be bundled into the locked specification before import.

Slack's current snapshot contains the 340 method names from the official sitemap, plus the archived Swagger request definitions as a second source. It is explicitly marked `index-only`. Of the current method names, 164 map to archived or preserved definitions and 176 lack schemas. The documentation importer can fetch each current method's Markdown page during `update slack`; this collection still needs to complete. SCIM, Audit Logs, and Legal Holds are separately recorded family exclusions.

Anthropic's pinned SDK mock specification includes beta and administration operations. Public availability, version headers, credential requirements, compound effects, and batch destinations need per-operation review. Airtable now uses the OpenAPI document embedded in its public developer documentation, including Web API and SCIM operations. Extraction persists only the specification and excludes surrounding browser state. Both providers still have unsupported bodies and overlapping routes in their reports.

Before promoting a provider, review every proposed action and effect combination, destinations and account boundaries, selectors, and the authority granted by saved approvals. Resolve overlaps with explicit request conditions. Verify request encodings, optional selectors, batches, version variants, and changes to approval scope through the actual policy matcher. Keep intentional restrictions documented. Generic name-based inference is only a proposal.

OpenRouter's API preset (`open_router`) comes from its official
[`openapi.json`](https://openrouter.ai/openapi.json). Refresh it with
`GOWORK=off go run . update open_router`, then run `generate open_router` and
`check open_router` using the workflow above. The separate `openrouter` preset
is its MCP connection.

OpenRouter normalization records paid inference's generate/pay/send effects,
distinguishes saving presets from running inference, and classifies credential,
access, routing, and budget changes as administration. Intern runs additionally
execute tools; provisioning remains a payment even when paid inference is
allowed. Generated approvals bind the complete request body and query, together
with path selectors. Video model listings and job status share one read
descriptor with the requested path segment bound, avoiding overlapping routes.
The API key slot covers `/api`, including the documented alpha Decisions route;
management and programme-gated endpoints still need the corresponding upstream
access. The current inventory has 152 request variants and 149 descriptors.
Multipart file upload and multipart audio transcription are reported as
unsupported; JSON audio transcription is supported. Consequently,
`check --reviewed open_router` still reports those two encoding gaps.

```sh
# Importer and accounting regressions, from this directory.
GOWORK=off go test ./...

# Policy validation and request-contract tests, from the monitor root.
go test . -run 'Test(Preset|Optional|GeneratedCandidate)' -count=1
```

The policy tests validate all candidate records structurally and exercise selected Slack, Anthropic, and Airtable requests. They do not claim exhaustive semantic tests for every generated operation. No provider accounts are called by these tests.
