# Suggestions, round 2 (not for merge)

On top of main `a882ca7` (Mia's rework). Same deal as `daniel_suggestions.md`:
move these into the PR or a message; delete before merge.

1. **Setup page: no "Open".** Known Only is the default and the only
   normal path; the one alternative offered is turning all networking
   off. Open means "skip connections entirely" — that belongs behind
   Settings → Dangerous, not on the first screen.
2. **Setup page: drop "Allow AI inference".** On by default, not shown.
   (Daniel has more thoughts on paid inference; later.)
3. **Dashboard: create a Monitor with a Tinfoil key already in it.** The
   "Connect Tinfoil" step after setup is great — but it shouldn't need to
   exist. When you create a Monitor in the dashboard, let me pick one of
   my keys or (better) just create a new key for that Monitor by default.
   Then the Monitor comes up already connected.
4. **Preset versioning instead of overriding.** Today editing a built-in
   preset silently replaces it (same name, built-in hidden, "Remove custom
   preset" to get it back). What I want: the built-in is the _default_
   and stays untouched; editing makes a new version next to it
   (`tinfoil-1`, or any title you give it), tied to the built-in it came
   from, and when you add a connection you pick which version. The UI
   now does this with a `catalog.derived_from` field on the saved
   preset — the backend should own that concept.
   1. This is built but hidden fro now - instead there are no presets. `SHOW_CATALOG_CONFIGURATION`
5. **Effects are too much.** Access level (off / read / ask / allow) is the
   thing people understand. The per-effect rows (payments, generate, read,
   send, …) are a second axis on top of it, and "Allow AI inference" is a
   carve-out of one of those rows sitting next to it as if it were a
   sibling. Most people will never tune these. Put effects under
   Advanced; surface one plain switch for money ("ask before paying,
   except AI inference").
6. **"Auto review requests with Tinfoil" needs a name and a home.** It's
   the AI reviewer (a Tinfoil model decides "ask" requests by a standing
   instruction, escalates the rest). Nothing about the label says that,
   and it sits per-agent among SSH plumbing. Say what it does, and make it
   a Monitor-wide switch in Settings with per-agent override only if
   someone asks.
7. **Name vs title.** A preset has a fixed `name` (id) and an editable
   `title`; a connection has an editable `name`. Pick one word for "the
   thing the customer types" across both.
8. **"Account" leaks.** The UI says Connections but routes, tooltips and
   the document say accounts. Routes are now `#connections`; the document
   key (`accounts`) and API path (`/accounts/{name}/sign-in`) still say
   account.
9. **Consolidate access, actions and rules in one place.** Three things
   decide what an agent may do on a connection — the access level, the
   per-action settings ("overrides"), and saved rules — and the UI
   scatters them: level and overrides in the grid, rules under Activity.
   They belong together, on the connection: Connection access → Actions
   (each settable) → Rules (a rule is just an action scoped to specific
   parameters, saved from a request). The UI now does this in the
   identity×connection cell; the model and the Activity/Rules tab should
   agree with it.
10. **No "agents" — sandboxes and trusted devices.** An identity is any
    SSH key the Monitor knows, but the two kinds it actually holds are
    not alike. A sandbox is the thing being contained; its grid is the
    whole product. A device is my own laptop key, enrolled by
    `attest-ssh` so I can SSH _through_ the Monitor into a sandbox. Its
    grid only matters if the laptop itself runs tools through the
    Monitor client, which we are not shipping. Showing both as "agents"
    with the same page made me think I had to configure my laptop.
    Now: a Sandboxes list and a Trusted devices list; a device row has one
    switch (can reach sandboxes). No search — nobody has enough of
    either. "Add sandbox" goes to the dashboard, because that is where
    sandboxes are made; "Add trusted device" is just a key paste.
11. **Networking off means one thing: sandboxes can't send anything out.**
    The Offline preset also wrote `routes = false` on every
    identity and turned every grant off, so "networking off" locked me
    out of my own sandboxes and threw away my configuration. That's
    three features in one switch. It is now the deny rule only; trusted
    devices stay trusted unless I turn them off on their own row, and
    grants survive so turning networking back on restores everything.
    Same switch in the sidebar, on the setup page, and on the Activity
    banner so it's never a hunt.
12. **A request page is: who, where, when; what you did; why it's odd.**
    The old page had "Review", "Policy review", "Approval needed" and
    "Why it was blocked" — same list under four names — plus a JSON dump.
    Now one Review line (you approved it once / saved a rule / denied it;
    or "blocked by policy", "waiting for you") and a Details list that
    only appears when there's something non-obvious: an effect forcing
    ask or deny, a hard block, an unrecognised operation. Dropped from
    Details: "needs your approval" (that's what pending means) and the
    audience/trust data-flow lines, which nobody set up on purpose and
    which read as alarming. The JSON facts are gone from the page.
13. **General network access is blind, say s** A raw TCP request
    is host and port; the Monitor cannot see what goes over it.
    This is a warning inside the general network so people don't add lots of these (it can't be sniffed)
