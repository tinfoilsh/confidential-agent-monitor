# Monitor UI ↔ policy document ↔ API — a map, and where to squish

Companion to `daniel_thoughts.md`. Read from code at `main` 2026-10-21
evening (`6201b25`; `ui/src/App.tsx`, `Settings.tsx`, `Agents.tsx`,
`Connections.tsx`, `Activity.tsx`, `config.go`, `owner.go`, `policy.go`).

## What changed upstream since the first draft (7 commits, 21 Oct)

- **"Agents" is now "Actors"** in the UI (`aef8ae1`; the document key is
  still `identities`, the route still `#agents`). Device controls
  simplified; device sign-in got a proper dialog. Half of squish item 2
  is done.
- **Theme moved into Settings** (`556f7de`, `645bea6`) — one more row on
  the grab-bag page.
- **Private `.monitor` routes + attested websearch** (`6201b25`), the one
  that matters for sandboxes. Inside a sandbox, every Tinfoil connection
  now answers on a PRIVATE hostname with NO client credential:
  `http://<connection>.monitor/v1` for inference (`http://tinfoil.monitor/v1`
  for the default), `http://<connection>.monitor/mcp` for websearch (a
  second `tinfoil-mcp` connection on the same account, pinned to
  `websearch.tinfoil.sh`, tool definitions owner-reviewed). The
  Connection page shows these as "Connection setup" with copy buttons:
  "set your client's base URL to this; if it needs an API key, enter
  `monitor`". The placeholder-in-Authorization dance (`tfm_tinfoil_<id>`)
  still works but is no longer the intended path.

  For cthulhu (`docs/current/sandbox.md`) that collapses the recipe:
  `--tinfoil-proxy http://tinfoil.monitor/v1 monitor` with no key flag,
  `--tinfoil-websearch-url http://tinfoil-websearch.monitor` brings
  websearch back, and the Monitor CA no longer matters for inference
  (plain http on a private name). One cthulhu follow-up needed:
  wire-home refuses plain `http://` to anything but loopback — allow
  `*.monitor`.

## The mental model in one paragraph

The Monitor is ONE document (a TOML policy, ~6 top-level keys) plus a
request log. Everything in the UI is a view onto that document or that
log. Three nouns matter: **accounts** ("Connections" in the UI — a
service plus its credential, built from a preset), **identities**
("Agents" — an SSH key: a sandbox, your laptop, or a paired client), and
the **grid between them** (`identities.<agent>.accounts.<account>.level`
= off / read / ask / allow). Everything else is a modifier on that grid:
effects (what KIND of action — read, write, delete, send, publish, pay),
data-flow labels (what the agent has SEEN, so sends get a second look),
saved rules (an approved request remembered), and the Rego `policies`
escape hatch. Requests flow in over SSH, get described by a preset
(`GitHub: POST /repos/x/issues` → action `issues.write`, effects
`[write]`), get decided by the grid + modifiers, and land in Activity as
allowed / denied / pending.

## The document

```toml
allow_paid_inference = false          # Settings → Default permissions
allow_networks = []                   # Settings → Advanced (raw CIDR list)
[lattices]  confidentiality = true    # Settings → Guardrails (two toggles)
            integrity = false
[effects]   publish = "ask"           # Settings → Guardrails → effect defaults (global)
[default_access.<account>] level=...  # NOT in the UI as such — onboarding writes it
[accounts.<name>]                     # Connections
  preset = "github"
  contents = "anyone" | "me"          # data-flow: how private is what this account returns
  sends    = "anyone" | "me"          # data-flow: who can see what you send it
  strangers = true|false              # integrity: does it return untrusted input
  effects.<effect> = off|ask|allow    # per-account effect override
  policy_options = {}                 # preset-specific knobs
  connections.<key>.<connector> = {…} # the actual endpoint(s) (hosts, enclave, repo…)
[identities.<name>]                   # Agents
  key = "ssh-ed25519 …"
  routes = true|false                 # may this key reach sandboxes (devices)
  reviewer = "<account>"              # optional AI reviewer connection
  effects.<effect> = …                # per-agent effect override
  accounts.<account>.level = off|read|ask|allow
  accounts.<account>.actions.<action> = off|ask|allow   # per-action override
  accounts.<account>.effects.<effect> = …               # per-agent-per-account effect
  rules.<id> = {account, action, operation, scope, requirements}   # Saved rules
[policies] <name> = "package sentinel … deny contains …"   # Rego, Settings → Policy editor
[presets] <name> = {…}                 # overrides of the shipped service presets
[data] onboarding.completed = true
```

Precedence for one request: explicit deny anywhere wins → per-action
override → account level → effect modes (most specific scope wins:
agent+account > agent > account > global > built-in defaults, where
publish/pay default to ask) → data-flow requirements (confidentiality:
"this agent has seen private data and this request discloses to anyone";
integrity: "this request acts on untrusted input") → Rego `policies` →
saved rules waive named requirements for a matching scope.

## The UI, page by page, and what it edits

| Nav item | Route | Edits / reads | Verdict |
| --- | --- | --- | --- |
| **Activity** | `#activity`, `#request/<id>` | `GET /requests`, `POST /requests/{id}` with `once` / `save` / `deny`. `save` also writes `identities.<agent>.rules.<id>` | Core. Keep. |
| **Actors** (was Agents) | `#agents`, `#agent/<name>`, `#agent-settings/<name>` | `identities.*` — grouped into Sandboxes / Devices / Other actors purely by NAME PREFIX (`sandbox-`, `device-<16hex>`) | Core, but the three groups are a naming accident, not a concept. |
| **Connections** | `#accounts`, `#account/<name>`, `#catalog` (add from preset) | `accounts.*` + OAuth sign-in (`POST /accounts/{a}/sign-in`); the Browser connector gets a live screenshot panel; Tinfoil connections show a "Connection setup" block with their private `http://<connection>.monitor/{v1,mcp}` URLs | Core. Keep. "Catalog" = the 300 presets. |
| **Saved rules** | `#rules` | `identities.*.rules.*` (flattened across agents) | Not a top-level concept — it is a per-agent list. |
| **Settings** | `#settings` | `allow_paid_inference`, `lattices.*`, global `effects.*`, `allow_networks`, theme; links to Policy editor and Preset editor | Grab-bag. |
| Settings → **Policy editor** | `#policy` | the WHOLE document as TOML: `GET /policy`, `POST /policy/preview` (diff), `POST /policy` (replace) | Power-user escape hatch. Same data as every other page. |
| Settings → **Preset editor** | `#presets`, `#preset/<name>` | `presets.*` — override a shipped service definition (hosts, operations, actions) | Rare. Developer tool. |
| **Integrations** | `#integrations/<page>` | nothing — static guides: "Start here", "Wrap commands", "Monitor shell", "MCP connections" (text with copy buttons) | Docs, not settings. |
| Onboarding | first load, `data.onboarding.completed` absent | writes `allow_networks`, `lattices.confidentiality`, `accounts.network` (tcp `*`), `default_access.network`, and the `network-default` Rego rule | The one place `default_access` and `policies` get written for you. |

## The API (owner panel, `/api/*`, header `X-Tinfoil-Session`)

| Endpoint | Used by |
| --- | --- |
| `GET /` | everything: `{generation, config, presets, labels, status, ca, host_key…}` — the snapshot every page renders from |
| `GET /policy[?effective]` | Policy editor (TOML source; `effective` = with presets resolved) |
| `POST /policy/preview` `{source}` → diff | Policy editor "Validate" |
| `POST /policy` `{source}` | Policy editor "Apply" (whole-document replace) |
| `POST /policy/edits` `{generation, changes:[{path:[…], value}|{path, delete}]}` | EVERY toggle/dropdown in Agents, Connections, Settings — path-addressed patches into the same document |
| `GET /requests`, `GET /requests/{id}`, `POST /requests/{id}` `{decision: once\|save\|deny}` | Activity |
| `GET /presets/{name}` | Catalog / Preset editor |
| `POST /accounts/{account}/sign-in`, `POST /sign-in/{state}` | OAuth connections |
| `POST /labels/{identity}` | rename an agent (display label, not the identity name) |
| `POST /enroll` | sandbox/device enrollment (the CLI, not the UI) |
| `POST /unlock` | CLI only, over the owner SSH channel (the browser cannot unlock) |

So: **the UI and the API are grouped the same way, because both are
views of the same document** — `/policy/edits` with a `path` IS the
dropdown; the Policy editor IS `GET/POST /policy`. The split that is
NOT visible from the API: "Saved rules" (a UI flattening of
`identities.*.rules`) and the Sandboxes/Devices/Other grouping (a UI
regex over identity names). There is no "settings" object — the
Settings page is four unrelated top-level keys.

## Where it is confusing, mapped to the cause

| Your note | Cause in the model |
| --- | --- |
| "What is an agent?" | `identities` are SSH keys. Sandboxes, your laptop (`device-…`), and `monitor` CLI clients are all the same row type. The word is overloaded with "AI agent". |
| "Why don't sandboxes show up in my Monitor?" | A sandbox only becomes an identity on first `attest-ssh` (`POST /enroll`), not on creation. Until then the Monitor has never heard of it. |
| "TCP? Paid inference? Can I change it later?" | Onboarding exposes three internals (a raw-TCP catch-all account, an effect default, a lattice toggle) with no mapping back to where they live. Yes, all changeable later — in three different places. |
| "Settings → Policy looks different" | It is the raw document. Every other page is a form over a slice of the same document. |
| "Known Only prompted on every host" | Raw TCP is an opaque pipe: the `tcp` connector labels every connect as observes-private + sends-anyone, so with confidentiality on, every new host is a potential disclosure. The mode only becomes quiet once real HTTP presets (GitHub, Tinfoil…) do the work and the catch-all is off. |
| "The Monitor only looks at network" | Correct, by construction: it is a credential-substituting egress proxy. "Loan a credential to a process" IS a network request from that process. Harness-level hooks would be a different product surface. |

## Squish proposals (UI only, no model change)

1. **Three nav items, not seven: Activity · Agents · Connections.**
   - Saved rules → a tab inside each agent (it already is per-agent in the document) plus a "rules" badge on the agent row.
   - Settings → a gear in the header opening ONE sheet with the four
     keys as plain-English toggles (below). Policy editor and Preset
     editor move under "Advanced" at the bottom of that sheet.
   - Integrations → "How to connect" link on the empty state of Agents
     and in the agent row's menu; it is help text, not a destination.
2. ~~Rename "Agents"~~ — done upstream as "Actors". Still: drop the
   Sandboxes / Devices / Other split in favour of an icon + one-word
   kind per row. Your laptop is "This device"; a sandbox is "Sandbox
   danielbox1"; a paired CLI is "Paired key".
3. **Onboarding = pick a starting posture, one sentence each, defaults
   to Offline**, exactly as you wrote: Offline → Known services only →
   Open. Each posture is a *named bundle* of the same five document edits
   onboarding already makes; show the bundle name in the Settings sheet
   with "change" — so the user always knows which one they're in and can
   move up or down. Hide "paid inference" and "TCP" from this screen
   entirely (paid inference defaults on for the Tinfoil connection, off
   elsewhere; the TCP catch-all is what "Open" means).
4. **Settings sheet, four rows:**
   - Network posture: Offline / Known services / Open  (`allow_networks`, `default_access.network`, `policies.network-default`, `accounts.network`)
   - Track what agents have seen and ask before they share it  (`lattices.confidentiality`)
   - Treat content from the internet as untrusted  (`lattices.integrity`)
   - Always ask before: ☑ paying ☑ publishing ☐ deleting …  (global `effects.*`)
   - Advanced ▸ Policy editor · Preset editor · Allowed networks (CIDR)
5. **The grid as the centrepiece of an agent page.** One row per
   connection with a four-state control (off / read / ask / allow) and a
   disclosure for per-action overrides. That is `identities.<a>.accounts`
   verbatim. Effects overrides go under "more".
6. **Pre-seed a `tinfoil` connection at onboarding** with the owner's
   key (your note) so a fresh Monitor + sandbox can think immediately.
   Document-wise it is one `accounts.tinfoil` entry (with both the
   inference and the `websearch` connection, as the preset now defines)
   + a grant on `default_access`. With `.monitor` routes the sandbox then
   needs NOTHING else — no key, no placeholder — which is the "Monitor
   Proxy" line in your thoughts, delivered.
7. **Requests → the request page is already good**; the "save" decision
   should say what it will remember ("GitHub · read issues in tinfoilsh/* —
   for sandbox danielbox1") rather than "save rule".

None of these change `config.go`, the API, or the CLI. Items 1, 2, 4 are
`App.tsx` + `Settings.tsx` restructuring; 3 is `owner.js`
`onboardingChanges` + the onboarding form; 6 is an extra change in that
same function when a key is supplied.
