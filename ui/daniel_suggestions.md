# Suggestions (not for merge)

Things found while simplifying the UI that need a backend change, a
decision, or a conversation. Move each into the PR description or a
message to Mia before the branch lands; delete this file before merge.

1. **Expose the Monitor's name in the snapshot.** `GET /` has no `name`;
   the UI wants "Welcome to daniel1". The name lives in the CLI / control
   plane today.
2. **"Turn off all networking" should not cut the owner's SSH path to
   sandboxes.** Today the offline preset sets `routes = false` on every
   identity (`routes.go:152`, `tunnel.go:257`), so `ssh <sandbox>` fails
   with "device has no sandbox route access". The UI is being built on
   the assumption that it means *sandboxes cannot reach out; the owner can
   still reach in* — i.e. only egress is off. Needs the preset (or the
   backend) to match.
3. **Raw TCP connections should always mean "every host".** The `tcp`
   preset's editable host-patterns field is the only per-connection
   setting on the catch-all `network` connection and the only place a
   user meets "host patterns". The UI now hides it (and the whole
   Connection setup panel for tcp); the document keeps `*`. The preset
   could drop the field.
4. ~~Request log is memory-only~~ — wrong: settled requests go to an
   immutable audit log in storage (`audit.go`); only the live ring is
   capped at 1000.
5. **Seed a `tinfoil` connection at onboarding** when the owner supplies
   a key (both the inference and `websearch` connections the preset now
   defines). Today onboarding writes only the raw-TCP catch-all; the
   Catalog pins Tinfoil as "Recommended" as a stopgap.

## Still to do (UI)

- Identities: drop the Sandboxes / Devices / Other grouping.
- Settings: untangle the grab-bag (paid inference — Daniel has thoughts; lattices; effect defaults; theme).
- Integrations nav item → help links where they're needed.
- Connections: remove the per-connection Advanced section.
- Rules: make "View request" find old requests in the audit log, not just the live ring.

## Done so far (one line each)

- Welcome page: three explainers, Start, small "turn off networking" link; no Open, no paid-inference toggle.
- Sidebar: Identities · NETWORKING (toggle) ▸ Activity · Connections · Rules · Settings; muted when off.
- Activity: stat cards gone; counts in dropdowns; "n of total"; pending first then newest; off-banner with turn-on button.
- Badges: Allowed / Blocked (automatic) vs Approved / Denied by you.
- Request page: JSON + data-flow sentence under "Advanced details"; 3-column context; Change access → identity.
- Identity×connection cell: Connection access → Actions → Rules, labelled and indented; rule rows link to Rules page.
- Identity page: read-only Connections list, click → connection.
- Connections: explainer first, Identity access, Advanced; API section and Add-identity button gone; raw TCP shown as "General network access", no host patterns.
- Rules page: back, grouped by connection, View request + Remove.
- Settings: Dangerous section with "Allow absolutely everything"; New custom preset under Advanced.
- Catalog: Mine | Catalog tabs on Connections; collapsed groups; Tinfoil pinned Recommended; Add + Edit preset per row; popup retired.
- Onboarding seeds a keyless Tinfoil connection next to the catch-all.
- Dev only: passphrase prefilled, rollback floor off, welcome-page pin flag.
- "Actors" → "Identities".
