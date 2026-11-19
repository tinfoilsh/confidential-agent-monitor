# Preset descriptor generation

This tool inventories API requests and proposes monitor actions, effect sets, resource scopes, and saved-approval grants. It does not generate full request/response schemas. Run `generate` to create a local coverage index at `coverage/README.md` with the current results and remaining gaps.

## Adding protocol presets

Not every shipped preset comes from this generator. Protocols described in prose
can use a reviewed, handwritten definition with SDK fixtures. For example,
`generate slack` covers Web API requests, not the separate
[Slack Socket Mode definition](../../connector/catalog/presets/slack_socket_mode.json).

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
A source's `origin` and `path` replace only the document server's origin and base
path; operation and path servers keep theirs, and a templated server host takes the
preset origin set that covers it.
A source's `pointer` names the JSON pointer of a document, string or object,
embedded in a downloaded JSON page. Postman sources take `variables`, values for
collection variables the export leaves undefined, and `captures`, which turn each
path segment matching a pattern, such as `{"version": "v[0-9]+\\.[0-9]+"}`, into
that capture.

Discovery operation IDs are method IDs without the API name; an ID an earlier
document of the source already uses gains the document's version as a prefix, such
as `v1alpha.properties.runReport`. Postman operation IDs are request names; a
repeated name gains its folder path, `Folder/Name`, and a number, `Folder/Name #2`,
when the folder repeats it.

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

`generate` and `check` return a nonzero exit status for missing or failed sources. They continue through the other selected providers, preserving useful results and writing an error report for each failure. The current all-provider commands fail for five hand-maintained presets without a usable source: Salesforce, Salesmate, Shopify, WooCommerce, and WordPress.

The files have different roles:

| Location | Purpose |
| --- | --- |
| `sources.json` | Provider mappings, source formats, API families, filters, and exclusions |
| `sources.lock.json` | Resolved source URLs, commits, content hashes, and successful refresh timestamps |
| `.cache/` | Downloaded source bytes, verified against the lock before parsing |
| `snapshots/` | Exact normalized bytes for mutable Airtable and Slack documentation sources |
| `../../connector/catalog/presets/*.json` | Authoritative shipped definitions, used directly as the generation baseline |
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

Grouping uses enclosing URL resources, strips the server base path,
transport/version segments and terminal operation verbs, and handles dotted RPC
methods. A segment with child routes keeps its full name. A name loses either its
leading verbs or, after a path parameter or in an RPC method, its trailing ones;
on routes read with GET only read verbs count. GraphQL uses schema return types
when available, falling back to field names and then the path. Source categories
provide a fallback for paths without literal resources. A source can override
an ambiguous group in `sources.json` with `"groups": {"operationId": "resource.subresource"}`.
These keys name source operations as described below, or shipped descriptor IDs such as hand-written ones; unknown keys and malformed group paths
are errors. A specification can nest all of its operations under one parent
with `"group": "graphql"`. `generate` uses these rules.

Reviewed effects live in `sources.json` as `"effects": {"admin,delete": ["operationId"]}`,
keyed by the comma-separated effect list. They replace the inferred effects, and
`generate` sets them and the matching action on the descriptors named after the
operation and its body variants, or else on every descriptor serving it, keeping their
other fields, so changing a review means editing that table and regenerating. Unknown
operations, unknown effects, keys listed twice, reviews that reach no descriptor,
and different reviews for one descriptor are errors.

Reviewed upload endpoints whose bodies cannot be inspected are listed as
`"opaque": ["operationId"]`. `generate` then emits one descriptor accepting any body
for each, or makes the shipped descriptors serving it accept any body, binding path
captures and query but not the body. Unknown, excluded, and repeated operations are errors.

Source operations the preset deliberately omits are listed as
`"exclusions": {"operationId": "reason"}`. No descriptor is generated or mapped for them;
coverage reports those within the filters as `excluded` with the reason, and shipped
descriptors that served only them as `unmapped_shipped`. Unknown operations are errors.

Keys of `groups`, `effects`, `opaque` and `exclusions` are an operation ID, which
names every operation with that ID in the source's specifications, or `METHOD /path`
with the path of the generated descriptor, including the server base path, which names
the operations on that route and takes precedence over an ID. An operation without an
ID is also named by its method and the path its specification writes. A descriptor ID
that is already taken gets a suffix derived from the request it matches.

Source options: `wildcards` lists final path parameters that match several segments,
like `{+name}`; `params` lists query parameters every operation accepts; `encodings`
(`json`, `form`) also offers each OpenAPI request body declared only in the other
encoding. Unknown, empty, and repeated entries, and wildcards matching no final path
parameter, are errors. A specification's `headers` set request headers for `fetch` and
`update`, such as a browser `User-Agent` for hosts that reject the default one.

`group [preset-or-source...]` writes the grouping into shipped presets, using
only their existing operations. With no arguments it processes all shipped API
presets. It uses cached source metadata where available and otherwise the shipped
routes. Native and MCP presets keep their protocol/tool action catalogs, which
use the same tree UI. Repeated grouping produces the same result. This is a
breaking action-name change: update agent overrides and custom policies to use
the new names. No aliases or permission migration are generated.

`accept <source>` runs `check` and then writes the candidate over the shipped preset of a source that maps to exactly one preset. Otherwise accept additions in the corresponding `../../connector/catalog/presets/<name>.json` by hand, preserving its connection setup and existing operations. Source names can differ from preset names; use the `preset` mapping in `sources.json`. The Confluence source group includes Jira, so divide its operations between the Confluence and Jira presets instead of copying the combined candidate into either one. Regenerate after accepting changes so the next proposal uses the updated shipped definitions.

Each source variant receives a status:

| Status | Meaning |
| --- | --- |
| `shipped_override` | A shipped definition has the same route and encoding, or accepts any body on that route, and its path patterns and query, header, and field conditions can match the operation's requests. Its deliberate restrictions still apply. This status records that it is shipped, not an independent semantic review. |
| `needs_review` | The generator proposed a descriptor. Permissions and resource semantics still need review. |
| `unsupported` | No usable descriptor could be produced; `reason` explains the gap. |
| `archived_schema` | A current method is indexed, but its request definition comes from an older source or preserved override. |
| `excluded` | The source's `exclusions` list the operation; `reason` explains why. |

`missing_params` identifies documented query parameters rejected by every matched definition. `generate` adds optional ones to the `params` of matched shipped definitions that can serve the operation, binding the query in their scope; it leaves their query conditions unchanged. `unmapped_shipped` lists shipped definitions without a source mapping. These may be deliberate extensions, deleted upstream operations, or source omissions; generation does not delete them. Generation adds `path_patterns` so a capture does not also match another descriptor's more specific segment, such as `/v1/charges/{charge}` and `/v1/charges/search`. It uses the source's integer, enum, anchored pattern, or merged multi-parameter segment when that separates them, and otherwise excludes the literal or literal prefix when the other descriptor accepts the rest of the route, or its shallowest literal when it is otherwise narrower only by literals. A bare capture beside a `{name}:verb` sibling excludes `:`. Conflicting descriptors remain visible instead of being merged away. Accepting a candidate does not clear these gaps, and requests that match multiple operations remain refused by policy.

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

An unqualified `update` resolves changed source definitions. `update --all` refreshes every configured source, including unchanged upstream URLs. A failed refresh, including a document that does not parse in its declared format, preserves the prior lock and returns an error. Older lock entries have no `checked_at`; the age gate rejects them until refreshed. `update` also locks the files that relative references outside examples and extensions name, and generation bundles them; other external references must be vendored into the locked specification.

Slack's current snapshot contains the 340 method names from the official sitemap, plus the archived Swagger request definitions as a second source. `update slack` fetches each current method's Markdown page, and every resulting request variant maps to a shipped definition. SCIM, Audit Logs, and Legal Holds are separate API families recorded in its note.

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
access. The current inventory has 175 request variants and 192 descriptors.
File upload is reviewed as an uninspectable body. Multipart audio transcription
is reported as unsupported; JSON audio transcription is supported. Consequently,
`check --reviewed open_router` still reports that encoding gap.
