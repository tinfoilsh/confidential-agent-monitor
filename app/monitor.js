import * as owner from "./owner.js";
import * as dashboard from "./dashboard.js";
const isDashboard = document.documentElement?.dataset.ui === "dashboard";
const { LEVELS, MODES, AUDIENCES: WHO, edits, sourceChanges, reasons, ruleSentence } = owner;
let ownerSession = sessionStorage.getItem("monitor-local-session");
let ownerMode = null;
const KEY = "monitor-owner-key", GENERATION = "monitor-generation", DISMISSED = "monitor-dismissed", RETURN = "monitor-sign-in-return";
const REQUEST_POLL_MS = 5000, TOAST_MS = 5000, LIVE_POLL_MS = 1000, WHEEL_LINE_PX = 40;
// Tab is left out so keyboard focus can leave the page view; the Tab button sends it.
const LIVE_KEYS = ["Enter", "Backspace", "Delete", "Escape", "ArrowUp", "ArrowDown", "ArrowLeft", "ArrowRight", "Home", "End", "PageUp", "PageDown"];
const SEES = { me: "only you", team: "your team", anyone: "anyone" };
const STATE_CLASS = { allowed: "", approved: "", refused: "bad", denied: "bad", expired: "muted", pending: "warn" };

// Keep the activity filter and return route while a request is open.
let view = null, records = [], locked = false, scope = null, requestSource = "activity";
let onboardingPreset = "known_only", onboardingPaidInference = true, onboardingSaving = false;
let serverState = { view: null, records: [] }, sending = false, editVersion = 0, refreshing = null;
const pendingEdits = [];
let connectorIcons = {};
const iconsReady = fetch("icons/manifest.json").then((res) => res.ok ? res.json() : {}).then((icons) => { connectorIcons = icons; }).catch(() => {});
const expanded = new Set(["agents", "accounts"]);
const $ = (id) => document.getElementById(id);
const esc = (s) => String(s ?? "").replace(/[&<>"']/g, (c) => `&#${c.charCodeAt(0)};`);
const q = (v) => esc(JSON.stringify(v));
const opt = (value, text, selected) => `<option value="${esc(value)}" ${value === selected ? "selected" : ""}>${esc(text)}</option>`;
const ids = () => view.config.identities ?? {};
const accounts = () => view.config.accounts ?? {};
const lattices = () => owner.lattices(view);
const connectorIcon = (type) => {
  const icon = owner.connectorIcon(connectorIcons, type);
  const dark = isDashboard ? (document.documentElement.dataset.theme === "dark" ? "all" : "not all") : "(prefers-color-scheme: dark)";
  return `<picture class="connector-icon" aria-hidden="true">${icon.dark ? `<source media="${dark}" srcset="${esc(icon.dark)}">` : ""}<img src="${esc(icon.src)}" width="14" height="14" alt=""></picture>`;
};
const accountIcon = (a) => connectorIcon(accounts()[a]?.preset ?? "custom");
const entry = (account) => owner.presetOf(view, account);
const route = () => location.hash.slice(1).split("/").map(decodeURIComponent);
const pendingSoonest = () => owner.pendingSoonest(records);
const left = (r) => owner.timeLeft(r);

function toast(text) {
  $("toast").textContent = text;
  $("toast").hidden = false;
  clearTimeout(toast.timer);
  toast.timer = setTimeout(() => ($("toast").hidden = true), TOAST_MS);
}

// run surfaces a failed action as a toast.
const run = (fn) => async (...args) => {
  try { return await fn(...args); } catch (err) { render(); toast(err.message); }
};

// Every response tells whether the monitor is locked; a rejected key is forgotten.
async function observe(...args) {
  const res = await fetch(...args);
  if (res.status === 401) {
    ownerSession = null;
    sessionStorage.removeItem("monitor-local-session");
    sessionStorage.removeItem(KEY);
  }
  locked = res.status === 423;
  return res;
}
const authenticated = () => ownerMode === "bearer" ? !!sessionStorage.getItem(KEY) : !!ownerSession;
let activeClient, clientMode, clientCredential;
const client = () => {
  const credential = ownerMode === "bearer" ? sessionStorage.getItem(KEY) : ownerSession;
  if (!activeClient || clientMode !== ownerMode || clientCredential !== credential) {
    activeClient = ownerMode === "bearer"
      ? owner.ownerClient({ key: credential, fetch: observe })
      : owner.localOwnerClient({ token: credential, fetch: observe });
    clientMode = ownerMode;
    clientCredential = credential;
  }
  return activeClient;
};

async function loadOwnerMode() {
  const res = await fetch("auth.json", { cache: "no-store", credentials: "omit", redirect: "error" });
  if (!res.ok) throw new Error("Could not load Monitor sign-in options. Reload the page to retry.");
  const { mode } = await res.json();
  if (!["bearer", "ssh"].includes(mode)) throw new Error("Unknown Monitor sign-in method.");
  ownerMode = mode;
  if (mode === "ssh") sessionStorage.removeItem(KEY);
  else {
    ownerSession = null;
    sessionStorage.removeItem("monitor-local-session");
  }
}

function remember(v) {
  serverState.view = v;
  localStorage.setItem(GENERATION, Math.max(v.generation, +localStorage.getItem(GENERATION) || 0));
  project();
}

// Reapply pending edits over the last confirmed snapshot, including after a failed save.
function project() {
  const next = pendingEdits.length ? structuredClone(serverState) : serverState;
  for (const edit of pendingEdits) edit.update(next);
  view = next.view;
  records = next.records;
  $("saving").hidden = pendingEdits.length === 0;
  const count = pendingSoonest().length;
  document.title = count ? `(${count}) Monitor` : "Monitor";
}

function refresh() {
  if (pendingEdits.length || sending) return Promise.resolve();
  // Timer ticks and manual refreshes share one read, even when it takes longer
  // than the polling interval. Starting another poll must not discard its result.
  if (!refreshing) refreshing = (async () => {
    while (!pendingEdits.length && !sending) {
      const version = editVersion, source = client();
      const { view: next, requests: log } = await source.read(undefined, { summary: true });
      // A click or a changed credential invalidates this snapshot. Read again
      // after completed edits so their callers also wait for current state.
      if (version !== editVersion || source !== client()) continue;
      if (serverState.view === next && serverState.records === log) return false;
      serverState.records = log;
      remember(next);
      return true;
    }
  })().finally(() => { refreshing = null; });
  return refreshing;
}

function edit(update, send, { then, message = "Saved" } = {}) {
  return new Promise((resolve, reject) => {
    const item = { update, send, message, resolve, reject, from: location.hash, to: then && "#" + then };
    pendingEdits.push(item);
    editVersion++;
    try {
      project();
      if (item.to) location.hash = item.to;
      render();
    } catch (err) {
      pendingEdits.pop();
      project();
      if (item.to && location.hash === item.to) location.hash = item.from;
      render();
      reject(err);
      return;
    }
    if (!sending) flushEdits();
  });
}

async function flushEdits() {
  sending = true;
  let failed = false, needsRefresh = false, message;
  while (pendingEdits.length) {
    const item = pendingEdits[0];
    let result, error;
    try { result = await item.send(); } catch (err) { error = err; }
    pendingEdits.shift();
    editVersion++;
    if (!error) {
      if (result) remember(result);
      else { item.update(serverState); needsRefresh = true; project(); }
      message = item.message;
      render();
      item.resolve();
    } else {
      failed = true;
      needsRefresh = true;
      project();
      if (item.to && location.hash === item.to) location.hash = item.from;
      render();
      item.reject(error);
    }
  }
  sending = false;
  if (!failed && message) toast(message);
  // Decisions return no snapshot; also reconcile uncertain network failures.
  if (needsRefresh) {
    try { await refresh(); render(); } catch (err) { toast(err.message); }
  }
}

const changeSettings = (changes, options, update = () => {}) => edit(
  (state) => { owner.previewChanges(state.view, changes, shippedFiles); update(state); },
  () => client().edit(changes), options);

const commit = run((changes, then, update) => changeSettings(changes, { then }, update));
const patch = (body, then, update) => commit(sourceChanges(JSON.parse(JSON.stringify(body))), then, update);

// sync redraws only the keyed parts whose markup changed, so open details, focus and typed input elsewhere survive.
const drawn = new WeakMap();
function sync(el, parts) {
  const old = new Map([...el.children].map((c) => [c.dataset.key, c]));
  let at = el.firstElementChild;
  for (const [key, html] of parts) {
    let node = old.get(key);
    old.delete(key);
    if (!node || drawn.get(node) !== html) {
      const t = document.createElement("template");
      t.innerHTML = html;
      const fresh = t.content.firstElementChild;
      fresh.dataset.key = key;
      const disclosures = new Map([...(node?.querySelectorAll("details[data-disclosure]") ?? [])].map((d) => [d.dataset.disclosure, d.open]));
      fresh.querySelectorAll("details[data-disclosure]").forEach((d) => { d.open = disclosures.get(d.dataset.disclosure) ?? false; });
      drawn.set(fresh, html);
      node?.replaceWith(fresh);
      if (node === at) at = fresh;
      node = fresh;
    }
    if (node === at) at = at.nextElementSibling;
    else el.insertBefore(node, at);
  }
  old.forEach((c) => c.remove());
}

function render() {
  const gate = !ownerMode ? `<p class="empty">Loading…</p>`
    : !authenticated() ? keyPage()
    : locked ? lockedPage()
    : !view ? `<p class="empty">Loading…</p>`
    : !owner.onboarded(view) ? onboardingPage() : "";
  $("gate").hidden = !gate;
  $("app").hidden = !!gate;
  sync($("gate"), gate ? [["gate", gate]] : []);
  if (gate) return;
  // Keep old approval bookmarks pointing at the shared activity view.
  if (route()[0] === "needs") history.replaceState(null, "", "#activity");
  if (isDashboard && route()[0] === "agent") history.replaceState(null, "", "#agents/" + encodeURIComponent(route()[1] ?? ""));
  const [path, ...args] = route(), kind = path || "activity";
  if (kind === "agent" || kind === "account") scope = [kind, args[0]];
  if (kind === "agent-settings") scope = ["agent", args[0]];
  if (kind === "activity") {
    scope = ["agent", "account"].includes(args[0]) && args[1] ? args.slice(0, 2) : null;
  }
  if (kind !== "request") requestSource = location.hash.slice(1) || "activity";
  const panes = { request: requestPane, agent, "agent-settings": agentSettings, pair, account, add, preset: presetPage, rules, settings, integrations, policy: policyPage };
  const parts = (html) => html.map((content, i) => [`${location.hash}/${i}`, content]).filter(([, content]) => content);
  if (isDashboard) {
    renderDashboard(kind, args, panes, parts);
  } else {
    $("app").classList.toggle("with-pane", !!panes[kind]);
    $("list").setAttribute("role", panes[kind] ? "complementary" : "main");
    $("pane").hidden = !panes[kind];
    sync($("tree"), sidebar(kind, args[0]));
    sync($("list"), list(kind === "request" && args[0]));
    sync($("pane"), panes[kind] ? parts(panes[kind](...args)) : []);
  }
  // Effects save immediately; update them without replacing unsaved account fields.
  if (kind === "account" && $("account-effects")) sync($("account-effects"), [["effects", `<div><h3>Effects</h3>${effectControls({ account: args[0] })}</div>`]]);
  // Restore a draft when returning to the page without replacing the textarea on each keystroke.
  if (kind === "policy" && policyEditor && $("policy-source")?.value !== policyEditor.draft) $("policy-source").value = policyEditor.draft;
  liveSync();
}

function onboardingPage() {
  return `<form class="onboarding" onsubmit="event.preventDefault(); finishOnboarding()" aria-labelledby="onboarding-title">
    <h1 id="onboarding-title">Set up your monitor</h1>
    <p class="muted">Choose how agents can connect to the outside world.</p>
    <fieldset ${onboardingSaving ? "disabled" : ""}><legend>Network policy</legend>
      ${Object.entries(owner.POLICY_PRESETS).map(([value, { title, description }]) => `<label class="policy-choice">
        <input type="radio" name="network-policy" value="${value}" ${value === onboardingPreset ? "checked" : ""} onchange="chooseOnboardingPreset(this.value)">
        <span><strong>${title}</strong><small>${description}</small></span></label>`).join("")}
    </fieldset>
    <fieldset ${onboardingSaving ? "disabled" : ""}><legend>AI inference</legend>
      <label class="policy-choice">
        <input type="checkbox" name="paid-inference" ${onboardingPaidInference ? "checked" : ""} onchange="chooseOnboardingPaidInference(this.checked)">
        <span><strong>Allow paid AI inference</strong><small>Let agents use models from Anthropic, OpenAI, and other providers without payment approval. Provider charges apply. Other payments still require approval.</small></span>
      </label>
    </fieldset>
    <p class="muted">Saved for this monitor across browsers. You can change it later in Settings.</p>
    <button class="primary" type="submit" ${onboardingSaving ? "disabled" : ""}>${onboardingSaving ? "Saving…" : "Use this policy"}</button>
  </form>`;
}

const applyPolicyPreset = run(() => commit(edits.applyPolicyPreset(view, $("policy-preset").value)));
const chooseOnboardingPreset = (preset) => { onboardingPreset = preset; };
const chooseOnboardingPaidInference = (allow) => { onboardingPaidInference = allow; };
const finishOnboarding = run(async () => {
  if (onboardingSaving) return;
  onboardingSaving = true;
  try {
    await edit(() => {}, () => client().onboard(serverState.view, onboardingPreset, undefined, { allowPaidInference: onboardingPaidInference }), { message: "Policy saved" });
  } finally {
    onboardingSaving = false;
    render();
  }
});

const head = (title, sub = "", back = "activity") => isDashboard
  ? `<div class="detail-bar"><a href="#${esc(dashboardBack(back))}">${dashboard.icon("arrow")}Back to ${esc(dashboardBackLabel(back))}</a>${sub ? `<span class="muted">${sub}</span>` : ""}</div>`
  : `<header><b>${title}</b><span class="muted">${sub}</span><a class="x" href="#${esc(back)}" aria-label="Close">✕</a></header>`;
const disclosure = (key, title, content, cls = "") => `<details data-disclosure="${esc(key)}" class="${cls}"><summary>${title}</summary>${content}</details>`;
const node = (key, attrs, label, depth, { open, count = "", on } = {}) => [key,
  `<a class="node ${on ? "on" : ""}" ${attrs} style="--depth: ${depth}"><i>${open == null ? "" : open ? "▾" : "▸"}</i><span>${label}</span><small>${count}</small></a>`];
const folder = (key, label, count, depth = 0) => node(key,
  `role="button" tabindex="0" aria-expanded="${expanded.has(key)}" onclick="toggle(${q(key)})" onkeydown="if (event.key === 'Enter' || event.key === ' ') { event.preventDefault(); toggle(${q(key)}); }"`,
  label, depth, { open: expanded.has(key), count });
const link = (path, label, depth, on, count) => node(path.join("/"), `href="#${path.map(encodeURIComponent).join("/")}"`, label, depth, { on, count });

function toggle(key) {
  expanded.has(key) ? expanded.delete(key) : expanded.add(key);
  render();
}

function sidebar(kind, arg) {
  const pending = pendingSoonest(), at = (k, a) => kind === k && arg === a, groups = owner.catalog(view);
  const saved = Object.values(ids()).reduce((n, id) => n + Object.keys(id.rules ?? {}).length, 0);
  return [
    link(["activity"], `${pending.length ? `<span class="bang">!</span> ` : ""}Activity`, 0,
      kind === "activity" || kind === "request" && requestSource.startsWith("activity"), pending.length ? `${pending.length} pending` : ""),
    folder("agents", "Agents", Object.keys(ids()).length),
    ...(expanded.has("agents") ? [...Object.keys(ids()).map((n) => link(["agent", n], `${pending.some((r) => r.facts.principal.name === n) ? `<span class="bang">!</span> ` : ""}${esc(n)}`, 1,
      at("agent", n) || at("agent-settings", n))), link(["pair"], `<span class="new">Pair agent…</span>`, 1, kind === "pair")] : []),
    folder("accounts", "Accounts", Object.keys(accounts()).length),
    ...(expanded.has("accounts") ? Object.keys(accounts()).map((a) => link(["account", a], accountIcon(a) + esc(a), 1, at("account", a), accountStatus(a))) : []),
    folder("add", "Add account", groups.reduce((n, g) => n + g.presets.length, 0)),
    ...(expanded.has("add") ? [...groups.flatMap(({ group, title, presets }) => [
      folder("add-group/" + group, esc(title), presets.length, 1),
      ...(expanded.has("add-group/" + group) ? presets.map((p) => link(["add", p.name], connectorIcon(p.name) + esc(p.title), 2, at("add", p.name), p.accounts || "")) : []),
    ]), link(["preset"], `<span class="new">New preset…</span>`, 1, kind === "preset" && !arg)] : []),
    link(["rules"], "Rules", 0, kind === "rules", saved || ""),
    link(["policy"], "Policy", 0, kind === "policy"),
    link(["integrations"], "Integrations", 0, kind === "integrations"),
    link(["settings"], "Settings", 0, kind === "settings"),
  ];
}

function keyPage() {
  if (ownerMode === "bearer") return `<section><h2>Open Monitor</h2><form onsubmit="event.preventDefault(); setKey()">
    <label for="key">Owner key or passphrase</label><input id="key" type="password" autocomplete="current-password" required onpaste="pasteOwnerKey(event)">
    <div class="row"><span></span><button class="primary" type="submit">Continue</button></div></form></section>`;
  return `<section><h2>Open Monitor from your CLI</h2><p>Run <code>tinfoil monitor open NAME</code> to open a local panel with an attested connection. Keep private credentials in the CLI.</p></section>`;
}

function lockedPage() {
  return ownerMode === "bearer"
    ? `<section><p>Your monitor restarted.</p><button class="primary" onclick="unlock()">Unlock</button></section>`
    : `<section><p>Your monitor restarted. Run <code>tinfoil monitor open NAME</code> again to unlock it and reopen the SSH connection.</p></section>`;
}

function pasteOwnerKey(event) {
  const text = event.clipboardData?.getData("text") ?? "";
  if (!/[\r\n]/.test(text) || /^[A-Za-z0-9+/]{43}=\s*$/.test(text)) return;
  event.preventDefault();
  toast("This field cannot accept line breaks. Use a single-line passphrase.");
}

const setKey = run(async () => {
  if (ownerMode !== "bearer") return;
  sessionStorage.setItem(KEY, owner.encodeOwnerKey($("key").value));
  $("key").value = "";
  await refresh();
  render();
});

const unlock = run(async () => {
  if (ownerMode !== "bearer") return;
  remember(await client().unlock(+localStorage.getItem(GENERATION) || 0));
  await refresh();
  render();
});

const summary = owner.summary, saveText = owner.saveText;
function decide(r) {
  const d = owner.decisions(r);
  return `${d.once ? `<button onclick="answer('${r.id}', 'once')">Allow once</button>` : ""}`
    + `${d.save ? `<button title="${esc(saveText(r))}" onclick="answer('${r.id}', 'save')">Save rule and retry</button>` : ""}`
    + `${d.deny ? `<button class="danger" onclick="answer('${r.id}', 'deny')">Deny</button>` : ""}${d.dismiss ? `<button onclick="dismiss('${r.id}')">Dismiss</button>` : ""}`;
}

function list(selected) {
  const dismissed = JSON.parse(localStorage.getItem(DISMISSED) ?? "[]");
  const shown = owner.ordered(records.filter((r) => !scope || (scope[0] === "agent" ? r.facts.principal.name : r.facts.account) === scope[1]), dismissed);
  const pending = shown.filter((r) => r.state === "pending").length;
  return [
    ["activity", `<div class="group"><b>Activity</b>${pending ? `<span class="warn">${pending} pending</span>` : ""}${scope ? `<span class="muted">${esc(scope[1])} · <a href="#activity">All</a></span>` : ""}</div>`],
    ["columns", `<div class="ev hd"><span>Time</span><span>Agent</span><span>Account</span><span>Operation</span><span>Result</span></div>`],
    ...shown.map((r) => ["e/" + r.id, `<a class="ev ${r.state === "pending" ? "pending" : ""} ${r.id === selected ? "on" : ""}" href="#request/${r.id}"><span class="mono muted">${new Date(r.time).toLocaleTimeString()}</span>
      <span>${esc(r.facts.principal.name)}</span><span>${accountIcon(r.facts.account)}${esc(r.facts.account)}</span><span class="mono">${esc(r.facts?.title || summary(r.facts?.details))}</span><span class="${STATE_CLASS[r.state]}"${r.state === "pending" ? ` title="Needs approval · ${left(r)} left"` : ""}>${r.state}</span></a>`]),
    ...(shown.length ? [] : [["quiet", `<p class="empty">Nothing yet.</p>`]]),
  ];
}

// Keep only the selected request's full payload. Activity polls contain summaries.
let selectedRequest = null;
const requestRecord = (id) => {
  const record = records.find((r) => r.id === id);
  return record?.summary && selectedRequest?.id === id && selectedRequest.source === client() && selectedRequest.record
    ? { ...selectedRequest.record, state: record.state, savingDecision: record.savingDecision } : record;
};
function loadRequest(id, retry = false) {
  if (pendingEdits.length || sending) return;
  const source = client(), state = records.find((r) => r.id === id)?.state;
  if (!retry && selectedRequest?.id === id && selectedRequest.source === source && selectedRequest.state === state) return;
  const load = selectedRequest = { id, source, state, loading: true };
  source.request(id).then((record) => { load.record = record; }).catch((err) => { load.error = err.message; }).finally(() => {
    load.loading = false;
    if (selectedRequest === load && source === client()) render();
  });
}
function requestPane(id) {
  const listed = records.find((r) => r.id === id);
  if (listed?.summary) {
    loadRequest(id);
    if (selectedRequest?.id !== id || selectedRequest.loading || !selectedRequest.record) {
      const error = selectedRequest?.id === id && selectedRequest.error;
      return [head("Request", "", requestSource), error
        ? `<section><p class="bad">${esc(error)}</p><button onclick="loadRequest(${q(id)}, true)">Retry</button></section>`
        : `<p class="empty">Loading request…</p>`];
    }
  }
  const r = requestRecord(id);
  if (!r) return [head("Request", "", requestSource), `<p class="empty">No request ${esc(id)}.</p>`];
  const buttons = decide(r);
  return [head(esc(r.facts?.title || summary(r.facts?.details) || r.facts.account), `${esc(r.facts.principal.name)} · ${accountIcon(r.facts.account)}${esc(r.facts.account)}${r.state === "pending" ? ` · ${left(r)} left` : ""}`, requestSource),
    `<section><div class="row"><span class="${STATE_CLASS[r.state]}">${r.state}</span><span class="muted">${new Date(r.time).toLocaleTimeString()}</span></div>
      <ul>${[...(r.deny ?? []), ...reasons(r)].map((x) => `<li>${esc(x)}</li>`).join("")}</ul>
      <div class="mono">${esc(summary(r.facts?.details))}</div>
      ${r.facts?.details?.policy ? `<h2>Source changes</h2><pre>${esc(r.facts.details.policy.source_diff)}</pre><h2>Effective changes</h2><pre>${esc(r.facts.details.policy.effective_diff || "No effective changes.")}</pre>` : ""}
      ${r.facts?.operation?.id ? disclosure("grant", `<span class="muted">${esc(r.facts?.operation?.id)} grant</span>`, `<pre>${esc(JSON.stringify(r.grant))}</pre>`) : ""}
      ${disclosure("request", "Policy facts", `<pre>${esc(JSON.stringify(r.facts, null, 2))}</pre>`)}
      ${requestLinks(r)}${buttons ? `<div class="decisions">${buttons}</div>` : ""}</section>`];
}

const answer = run((id, decision) => {
  const request = requestRecord(id);
  if (!request || request.savingDecision) return;
  return edit((state) => {
    state.records = state.records.map((r) => r.id === id ? { ...r, savingDecision: true,
      state: decision === "save" ? "refused" : decision === "deny" ? "denied" : "approved",
      ...(decision === "save" ? { deny: ["Approval rule saved; retry the request."] } : {}) } : r);
    const identity = state.view.config.identities?.[request.facts.principal.name];
    if (decision === "save" && identity) identity.rules = { ...(identity.rules ?? {}), [request.id]: {
      account: request.facts.account, action: request.facts.operation.action, operation: request.facts.operation.id,
      definition: request.definition,
      scope: request.grant ?? {}, requirements: request.requirements ?? [],
    }};
  }, () => client().decide(id, decision), { message: decision === "save" ? "Rule saved. Retry the request from your agent." : decision === "deny" ? "Denied" : "Approved" });
});

function dismiss(id) {
  localStorage.setItem(DISMISSED, JSON.stringify([...JSON.parse(localStorage.getItem(DISMISSED) ?? "[]"), id]));
  render();
}

const pair = () => [head("Pair an agent"), `<section><label for="name">Name</label><input id="name"><label for="pubkey">Public key</label><textarea id="pubkey" rows="3"></textarea>
  <div class="row"><span></span><button class="primary" onclick="pairAgent()">Pair</button></div></section>`];

const pairAgent = () => commit(edits.pairAgent($("name").value, $("pubkey").value), (isDashboard ? "agents/" : "agent/") + encodeURIComponent($("name").value.trim()));

function permissionButtons(label, own, inherited, change) {
  return `<span class="seg" role="group" aria-label="${esc(label)} permission">${Object.entries(MODES).map(([m, t]) =>
    `<button class="${m === own ? "primary" : !own && m === inherited ? "inherited" : ""}" aria-label="${esc(t + " " + label)}" aria-pressed="${m === own}" title="${esc(m === own ? "Click to unset" : !own && m === inherited ? "Inherited setting" : t)}" onclick="event.preventDefault(); event.stopPropagation(); ${change(m === own ? null : m)}">${t}</button>`).join("")}</span>`;
}

function accessActions(name, a, nodes) {
  const renderAction = (node) => {
    const { key: k, effects, children, inherited, own, overrides } = node;
    const label = `${esc(node.title)}${overrides ? ` <small class="muted" title="${overrides} overrides">${overrides}</small>` : ""}`;
    const buttons = permissionButtons(k, own, inherited, (m) => `patchAccess(${q(name)}, ${q(a)}, { actions: { [${q(k)}]: ${q(m)} } })`);
    const title = `title="${esc(effects.join(", "))}"`;
    return children.length
      ? `<details class="access-action-group" data-disclosure="${esc(name + "/" + a + "/" + k)}"><summary class="access-action" role="button" aria-label="${esc(node.title)}"><span class="access-group-title" ${title}>${label}</span>${buttons}</summary><div class="access-children">${children.map(renderAction).join("")}</div></details>`
      : `<div class="access-action"><span ${title}>${label}</span>${buttons}</div>`;
  };
  return nodes.map(renderAction);
}

function effectControls(scope = {}) {
  const relevant = scope.account ? [scope.account] : Object.keys(accounts()).filter((a) => {
    if (!scope.agent) return true;
    const access = ids()[scope.agent]?.accounts?.[a] ?? view.config.default_access?.[a];
    return access?.level && access.level !== "off";
  });
  const used = new Set(relevant.flatMap((a) => Object.keys(owner.actionsOf(view, a)).flatMap((action) => owner.effectsOf(view, a, action))));
  const settings = owner.effectSettings(view, scope).filter(({ effect }) => used.has(effect));
  if (!settings.length) return `<p class="muted">No effects used by these actions.</p>`;
  const prominent = ({ effect, own, inherited }) => ["pay", "publish"].includes(effect) || own !== null || inherited !== "allow";
  const row = ({ effect, own, inherited, source }) => {
    const title = ({ pay: "Payments", publish: "Publishing" })[effect] ?? effect.charAt(0).toUpperCase() + effect.slice(1);
    const hint = `${MODES[own ?? inherited]} · ${source}${effect === "pay" ? ". Explicit payment settings also apply to paid AI inference." : ""}`;
    return `<div class="access-action"><span title="${esc(hint)}">${esc(title)}</span>${permissionButtons(title, own, inherited,
      (m) => `commit(edits.setEffect(${q(scope)}, ${q(effect)}, ${q(m)}))`)}</div>`;
  };
  const others = settings.filter((setting) => !prominent(setting));
  return `<p class="muted">Changes save immediately. Click a selected permission to unset it.</p><div class="access-actions effect-permissions">
    ${settings.filter(prominent).map(row).join("")}
    ${others.length ? `<details class="access-action-group" data-disclosure="${esc(["effects", scope.agent ?? "", scope.account ?? "", "other"].join("/"))}"><summary><span class="access-group-title">Other effects</span></summary><div class="access-children">${others.map(row).join("")}</div></details>` : ""}
  </div>`;
}

function agent(name, inline = false) {
  const id = ids()[name];
  if (!id) return [head(esc(name)), `<p class="empty">No agent ${esc(name)}.</p>`];
  const levels = owner.agentAccess(view, name).map(({ account: a, level, levels, overrides, actions: nodes }) => {
    const key = `access/${encodeURIComponent(name)}/${encodeURIComponent(a)}`, open = level !== "off" && expanded.has(key);
    const actions = open ? accessActions(name, a, nodes) : [];
    return `<div class="acct"><div class="row"><button class="access-toggle" aria-label="Actions for ${esc(a)}" aria-expanded="${open}" aria-controls="${esc(key)}" ${level !== "off" ? "" : "disabled"} onclick="toggle(${q(key)})">
      <i>${level !== "off" ? open ? "▾" : "▸" : ""}</i>${accountIcon(a)}<b>${esc(a)}</b>${overrides && level !== "off" ? `<small class="muted" title="${overrides} action overrides" aria-label="${overrides} action overrides">${overrides}</small>` : ""}</button>
      <span class="seg" role="group" aria-label="Default access for ${esc(a)}">${levels.map(([l, t]) =>
        `<button class="${l === level ? "primary" : ""}" aria-pressed="${l === level}" onclick="patchAccess(${q(name)}, ${q(a)}, { level: ${q(l)} })">${t}</button>`).join("")}</span></div>
      <div class="access-actions" id="${esc(key)}" ${open ? "" : "hidden"}>${actions.join("")}${open ? `<details data-disclosure="${esc(key + "/effects")}"><summary>Effect overrides</summary>${effectControls({ agent: name, account: a })}</details>` : ""}</div></div>`;
  });
  const hint = owner.browsingHint(view, name) ? `<p class="muted">Browsing needs approval after reading private data.</p>` : "";
  const l = view.labels[name] ?? {};
  const point = (axis, values) => {
    const lattice = axis === "trust" ? "integrity" : "confidentiality";
    if (!lattices()[lattice]) return `<a class="muted" href="#settings">${axis === "trust" ? "Integrity" : "Confidentiality"} off</a>`;
    return `<select aria-label="${axis === "trust" ? "Trust" : "Audience"}" onchange="setLabel(${q(name)}, { ...${q({ trust: l.trust, audience: l.audience })}, [${q(axis)}]: this.value })">
      ${Object.entries(values).map(([v, title]) => opt(v, title, l[axis])).join("")}</select>`;
  };
  const labels = `<span class="labels" title="${esc(owner.labelStatus(view, l))}">${point("trust", owner.TRUSTS)}${point("audience", WHO)}</span>`;
  if (inline) return [
    `<div class="agent-controls">${labels}<a href="#agent-settings/${encodeURIComponent(name)}">Settings</a></div>`,
    id.profile ? `<p class="warn">Profiling is on. Requests run without checks.</p>` : "", hint,
    levels.join("") || `<p class="muted">No connections yet.</p>`];
  return [head(esc(name), labels),
    id.profile || hint ? `<section>${id.profile ? `<p class="warn">Profiling is on. Requests run without checks.</p>` : ""}${hint}</section>` : "",
    `<section><h2>Access</h2>${levels.join("") || `<p class="empty">No accounts yet.</p>`}</section>`,
    `<section><a href="#agent-settings/${encodeURIComponent(name)}">Settings</a></section>`];
}

function inlineAgent(name) {
  const open = expanded.has("agent/" + encodeURIComponent(name));
  return { open, html: open ? agent(name, true).join("") : "" };
}

function agentSettings(name) {
  if (!ids()[name]) return [head(esc(name)), `<p class="empty">No agent ${esc(name)}.</p>`];
  const others = Object.keys(ids()).filter((n) => n !== name);
  return [head(esc(name), "Settings", (isDashboard ? "agents/" : "agent/") + encodeURIComponent(name)),
    `<section><h2>Effects</h2>${effectControls({ agent: name })}</section>`,
    `<section><a href="#integrations">Connect your tools</a><p class="muted">Setup guides for wrapped commands, Monitor shell, and MCP connections.</p></section>`,
    `<section>${disclosure("setup", "Setup", `<label>Host key</label><pre>${esc(view.host_key)}</pre><label>CA</label><pre>${esc(view.ca)}</pre>`)}</section>`,
    `<section>${disclosure("replace-key", "Replace key", `<p class="muted">Use this after recreating the sandbox. The agent starts clean.</p><textarea id="pubkey" aria-label="Replacement public key" rows="2"></textarea>
      <div class="row"><span></span><button onclick="commit(edits.replaceKey(${q(name)}, $('pubkey').value))">Replace key</button></div>`)}</section>`,
    `<section><label><input type="checkbox" ${ids()[name].routes ? "checked" : ""} onchange="commit(edits.setRoutes(${q(name)}, this.checked))"> Open sandbox routes</label><p class="muted">Allows sandbox connections. Turning this off closes existing sessions.</p></section>`,
    others.length ? `<section>${disclosure("copy-settings", "Copy settings", `<div class="row"><select id="from">${others.map((n) => opt(n, n)).join("")}</select><button onclick="copySettings(${q(name)})">Copy</button></div>`)}</section>` : "",
    `<section><button class="danger" onclick="removeAgent(${q(name)})">Remove agent</button></section>`];
}

function rulesSection(name) {
  const list = Object.entries(ids()[name].rules ?? {}).map(([id, r]) => `<div class="row"><span>${esc(ruleSentence(r))}${r.operation
    ? `<details><summary class="muted">grant</summary><pre>${esc(JSON.stringify(r.scope))}</pre></details>` : ""}</span><button onclick="removeRule(${q(name)}, ${q(id)})">Remove</button></div>`);
  return `<section><h2>${esc(name)}</h2>${list.join("")}</section>`;
}

const rules = () => [head("Rules"), ...Object.keys(ids()).filter((n) => Object.keys(ids()[n].rules ?? {}).length).map(rulesSection)];

const removeAgent = (name) => commit(edits.removeAgent(name), "activity");

const patchAccess = (name, account, access) => commit(edits.setAccess(name, account, access));

const setLabel = run((name, label) => edit((state) => {
  state.view.labels[name] = { ...label, because: {
    ...(label.trust !== "trusted" && { trust: "the owner" }),
    ...(label.audience !== "anyone" && { audience: "the owner" }),
  } };
}, () => client().label(name, label)));

const removeRule = (name, id) => commit(edits.removeRule(name, id));

const copySettings = run((name) => changeSettings(edits.copySettings(view, $("from").value, name)));

function accountStatus(a) {
  const { state, blocked } = owner.accountStatus(view, a);
  if (state === "error") return `<span class="bad">Can't connect</span>`;
  if (state === "connecting") return `<span class="muted">Connecting…</span>`;
  return blocked ? `<span class="warn">${blocked} tools await review</span>` : "";
}

// The full active definition includes pinned defaults and any TOML overrides.
const shippedFiles = {}, presetGenerations = {}, presetLoads = new Set();
const loadShipped = run(async (name) => {
  if (presetLoads.has(name)) return;
  presetLoads.add(name);
  const generation = view.generation;
  try {
    shippedFiles[name] = await client().preset(name);
    presetGenerations[name] = generation;
  } finally { presetLoads.delete(name); }
  render();
});
const presetFile = (name) => presetGenerations[name] === view.generation && shippedFiles[name] ? shippedFiles[name]
  : view.presets[name] ? undefined : owner.newPreset(name);

// Downloads the saved version, which the monitor has checked, as presets/<name>.json.
function downloadPreset(name) {
  const blob = new Blob([owner.presetText(presetFile(name)) + "\n"], { type: "application/json" });
  Object.assign(document.createElement("a"), { href: URL.createObjectURL(blob), download: name + ".json" }).click();
}

function requestLinks(r) {
  const account = accounts()[r.facts.account];
  if (!account) return "";
  return `<div class="row"><a href="#account/${encodeURIComponent(r.facts.account)}">Account settings</a>
    <a href="#preset/${encodeURIComponent(account.preset)}/${encodeURIComponent(r.id)}">${owner.draftable(view, r) ? "Add operation" : "Edit preset"}</a></div>`;
}

function presetPage(name, from) {
  if (!name) return [head("New preset"), `<section><label for="preset-name">Name</label><div class="row"><input id="preset-name"><button onclick="location.hash = 'preset/' + encodeURIComponent($('preset-name').value.trim())">Create</button></div></section>`];
  if (!presetFile(name)) {
    loadShipped(name);
    return [head("Preset " + esc(name)), `<p class="empty">Loading…</p>`];
  }
  if (records.find((r) => r.id === from)?.summary && requestRecord(from)?.summary) return requestPane(from);
  const request = requestRecord(from), file = owner.withDraft(presetFile(name), request);
  const users = Object.entries(accounts()).filter(([, acc]) => acc.preset === name).map(([a]) => a);
  return [head("Preset " + esc(name)), `<section><p class="muted">Changes apply to every account using it: ${esc(users.join(", ") || "none yet")}.</p>
    ${request ? `<h2>${esc(owner.requestTitle(request))}</h2><ul>${(request.deny ?? []).map((reason) => `<li>${esc(reason)}</li>`).join("")}</ul>
      <p>Review the request and its settings using the reason above. After making any corrections, retry from your agent.</p>
      <p><a href="#request/${encodeURIComponent(request.id)}">Back to request</a> · <a href="#account/${encodeURIComponent(request.facts.account)}">Account settings</a></p>` : ""}
    <textarea id="preset" aria-label="Preset definition" rows="40">${esc(owner.presetText(file))}</textarea>
    <div class="row">${view.config.presets?.[name] ? `<button class="danger" onclick="commit(edits.removePreset(${q(name)}))">Remove your version</button>` : "<span></span>"}
      <span><button onclick="downloadPreset(${q(name)})">Download file</button> <button class="primary" onclick="savePreset(${q(name)})">Save</button></span></div></section>`];
}

const savePreset = run(async (name) => {
  const changes = edits.savePreset(name, $("preset").value, presetFile(name));
  await edit(() => {}, () => client().edit(changes), { then: "preset/" + encodeURIComponent(name) });
});

function questions(a) {
  const pick = (id, value) => `<select id="${id}">${Object.entries(WHO).map(([x, title]) => opt(x, title, value)).join("")}</select>`;
  return `<label for="contents">Who should see what's in here?</label>${pick("contents", a.contents)}
    <label><input type="checkbox" id="strangers" ${a.strangers ? "checked" : ""}> Strangers can put content here</label>
    <label for="sends">Who sees what the agent sends here?</label>${pick("sends", a.sends)}`;
}

const answers = () => ({ contents: $("contents").value, strangers: $("strangers").checked, sends: $("sends").value });

function input(f, value, disabled = false) {
  const state = disabled ? "disabled" : "";
  value = owner.fieldText(f, value);
  if (f.json || f.multiline) return `<textarea id="f-${esc(f.key)}" ${state} rows="6">${esc(value)}</textarea>`;
  if (f.secret) return `<div class="secret-input"><input id="f-${esc(f.key)}" ${state} type="password" autocomplete="new-password" spellcheck="false" placeholder="${esc(f.hint || "Paste your secret here")}" value="${esc(value)}">
    <button type="button" aria-controls="f-${esc(f.key)}" aria-pressed="false" aria-label="Show ${esc(f.label)}" onclick="toggleSecret(${q(f.key)}, this)">Show</button></div>`;
  return `<input id="f-${esc(f.key)}" ${state} type="text" placeholder="${esc(f.hint)}" value="${esc(value)}">`;
}

function toggleSecret(key, button) {
  const field = $("f-" + key), show = field.type === "password";
  field.type = show ? "text" : "password";
  button.textContent = show ? "Hide" : "Show";
  button.setAttribute("aria-pressed", String(show));
  button.setAttribute("aria-label", button.getAttribute("aria-label").replace(/^(Show|Hide)/, button.textContent));
}

const read = (f) => owner.readField(f, $("f-" + f.key).value);

function setupField(f, preset) {
  const field = `<label for="f-${esc(f.key)}">${esc(f.oauth ? "Access token" : f.label)}</label>${input(f.oauth ? { ...f, label: "Access token", hint: "Paste your access token here" } : f, f.default)}
    ${f.secret ? `<p class="muted field-help">Leave blank to configure later.</p>` : ""}`;
  if (!f.oauth) return field;
  return `<div class="credential"><div id="token-field-${esc(f.key)}" hidden>${field}</div>
    <button type="button" class="link" id="token-toggle-${esc(f.key)}" aria-controls="token-field-${esc(f.key)}" aria-expanded="false" onclick="setupToken(${q(preset)}, ${q(f.key)})">Use an access token instead</button></div>`;
}

function setupToken(preset, key) {
  const field = $("token-field-" + key), button = $("token-toggle-" + key);
  field.hidden = !field.hidden;
  button.textContent = field.hidden ? "Use an access token instead" : "Use sign-in instead";
  button.setAttribute("aria-expanded", String(!field.hidden));
  $("signin-" + key).hidden = !field.hidden;
  const oauth = owner.setupFields(view, preset).some((f) => f.oauth && $("token-field-" + f.key).hidden);
  $("account-add").textContent = oauth ? "Add without signing in" : "Add";
  $("account-add").classList.toggle("primary", !oauth);
  if (!field.hidden) $("f-" + key).focus();
}

const signInLabel = (preset) => owner.signInLabel(view, preset);

function add(preset) {
  const c = view.presets[preset];
  if (!c) return [head("Add account"), `<p class="empty">No preset ${esc(preset)}.</p>`];
  if (preset === "custom_api") return customAPIPage(c);
  const fields = owner.setupFields(view, preset), oauth = fields.filter((f) => f.oauth);
  return [head(connectorIcon(preset) + "Add " + esc(c.title)), `<section><label for="account-name">Name</label><input id="account-name" value="${esc(preset)}">
    ${fields.map((f) => setupField(f, preset)).join("")}
    ${questions(c.defaults)}<div class="row"><span></span><div class="credential-actions">
      <button id="account-add" class="${oauth.length ? "" : "primary"}" onclick="addAccount(${q(preset)})">${oauth.length ? "Add without signing in" : "Add"}</button>
      ${oauth.map((f) => `<button id="signin-${esc(f.key)}" class="primary" onclick="addAccount(${q(preset)}, ${q(f.key)})">${esc(signInLabel(preset))}</button>`).join("")}</div></div></section>`,
    `<section><a href="#preset/${encodeURIComponent(preset)}">Edit preset</a></section>`];
}

const addAccount = run(async (preset, signInKey) => {
  if ($("account-add").disabled) return;
  const fields = owner.setupFields(view, preset), name = $("account-name").value.trim();
  const changes = edits.addAccount(view, preset, { name, values: Object.fromEntries(fields.map((f) => [f.key, read(f)])), answers: answers(),
    oauth: fields.filter((f) => f.oauth && $("token-field-" + f.key).hidden).map((f) => f.key) });
  const from = location.hash;
  const buttons = [$("account-add"), ...fields.filter((f) => f.oauth).map((f) => $("signin-" + f.key))];
  buttons.forEach((button) => { button.disabled = true; });
  try {
    await changeSettings(changes, { message: "Account added" });
    if (location.hash !== from) return;
    location.hash = "account/" + encodeURIComponent(name);
    if (signInKey !== undefined) {
      const f = fields.find((f) => f.key === signInKey);
      await signIn(name, owner.fieldPaths(f)[0].map(encodeURIComponent).join("/"));
    }
  } finally { buttons.forEach((button) => { button.disabled = false; }); }
});

function apiConnectionFields(a) {
  const { url, auth, header, prefix, query } = owner.apiSettings(view, a);
  return `<label for="api-url">API URL</label><input id="api-url" type="url" required placeholder="https://api.example.com" value="${esc(url)}" autocomplete="off">
    <p class="muted">The credential is used only at this address and its paths.</p>
    <label for="api-auth">Authentication</label><select id="api-auth" onchange="apiAuthChanged()">${opt("bearer", "Bearer token", auth)}${opt("header", "API key in a header", auth)}${opt("query", "API key in a query parameter", auth)}</select>
    <div id="api-header-fields" ${auth === "header" ? "" : "hidden"}><label for="api-header">Header name</label><input id="api-header" value="${esc(header)}">
      <label for="api-prefix">Prefix, if required</label><input id="api-prefix" value="${esc(prefix)}" placeholder="Leave empty for a plain API key"></div>
    <div id="api-query-fields" ${auth === "query" ? "" : "hidden"}><label for="api-query">Parameter name</label><input id="api-query" value="${esc(query)}"></div>`;
}

function apiAuthChanged() {
  $("api-header-fields").hidden = $("api-auth").value !== "header";
  $("api-query-fields").hidden = $("api-auth").value !== "query";
}

const apiForm = () => ({ url: $("api-url").value, auth: $("api-auth").value, header: $("api-header").value, prefix: $("api-prefix").value, query: $("api-query").value });

function customAPIPage(c) {
  const agents = Object.keys(ids()), selected = agents.length === 1 ? agents[0] : "";
  return [head(connectorIcon("api") + "Add Custom API"), `<section><form onsubmit="event.preventDefault(); addCustomAPI()">
    <p>Connect an app using its API key. The agent gets a placeholder; Monitor keeps the real key.</p>
    <label for="account-name">Name</label><input id="account-name" required pattern="[a-zA-Z0-9][a-zA-Z0-9\\-]*" placeholder="my-app" title="Use letters, numbers, and hyphens.">
    ${apiConnectionFields()}
    <label for="api-token">API key or token</label><input id="api-token" type="password" required autocomplete="new-password">
    ${agents.length ? `<label for="api-agent">Agent</label><select id="api-agent">${opt("", "Set up access later", selected)}${agents.map((name) => opt(name, name, selected)).join("")}</select>
      <label for="api-access">Access</label><select id="api-access">${opt("ask", "Ask before each request", "ask")}${opt("allow", "Allow all API requests", "ask")}</select>` : `<p class="muted">After adding this account, pair an agent to give it access.</p>`}
    <p class="muted">Access covers all operations at this address, including changes and deletions.</p>
    <details data-disclosure="api-sharing"><summary>Data sharing</summary>${questions(c.defaults)}</details>
    <div class="row"><span></span><button id="api-add" class="primary" type="submit">Add</button></div>
  </form></section>`];
}

const addCustomAPI = run(async () => {
  if ($("api-add").disabled) return;
  const name = $("account-name").value.trim();
  const changes = edits.addCustomApi(view, { name, api: apiForm(), token: $("api-token").value, agent: $("api-agent")?.value, level: $("api-access")?.value, answers: answers() });
  const from = location.hash;
  $("api-add").disabled = true;
  try {
    await changeSettings(changes, { message: "Account added" });
    if (location.hash === from) location.hash = "account/" + encodeURIComponent(name);
  } finally { if ($("api-add")) $("api-add").disabled = false; }
});

function apiAgentSetup(a) {
  const setups = Object.entries(accounts()[a].connections ?? {}).flatMap(([key, kinds]) =>
    (Object.values(kinds)[0]?.slots ?? []).map((_, index) => owner.apiSetup(view, a, key, index)).filter(Boolean));
  if (!setups.length) return "";
  const codex = owner.codexSetup(view, a);
  return `<section class="account-card agent-setup"><div class="section-heading"><h2>Connect your agent</h2></div>
    <div class="agent-setup-body"><p class="muted">Use these placeholders in your agent and send requests through Monitor. Monitor substitutes your saved credentials at the locations below.</p>
    ${codex ? `<p>Save this in <code>~/.codex/config.toml</code>, then run Codex in your Monitor-connected sandbox or with <code>monitor run -- codex</code>. Choose a model available to your ChatGPT account. Grant your agent access to this account and review any pending requests in Activity.</p>
      <div class="integration-code"><div class="row"><span>Codex configuration</span><button data-copy="codex-config">Copy</button></div><pre id="codex-config">${esc(codex)}</pre></div>
      <p><a href="https://chatgpt.com/#settings/Usage" target="_blank" rel="noopener noreferrer">Manage ChatGPT usage</a></p>` : ""}
    ${setups.map((setup, index) => {
      const id = `api-placeholder-${index}`;
      const [location, placement] = setup.header ? ["Header", `${setup.header}: ${setup.value}`]
        : setup.query ? ["Query parameter", `${setup.query}=${setup.value}`] : ["Authentication", setup.placement];
      return `<div class="agent-setup-item">${setups.length > 1 ? `<h3>${esc(setup.connection)} · ${esc(setup.credential)}</h3>` : ""}
        <label for="${id}">Agent placeholder</label><div class="secret-input"><input id="${id}" class="mono" readonly value="${esc(setup.placeholder)}" onclick="this.select()"><button onclick="copyAPIPlaceholder(${q(id)})" aria-label="Copy placeholder for ${esc(setup.connection)} ${esc(setup.credential)}">Copy</button></div>
        <dl class="agent-setup-details"><dt>Address</dt><dd><code>${esc(setup.address)}</code></dd>
        <dt>${location}</dt><dd><code>${esc(placement)}</code></dd></dl></div>`;
    }).join("")}</div></section>`;
}

const copyAPIPlaceholder = run(async (id) => {
  $(id).select();
  if (!navigator.clipboard) { toast("Copy the selected placeholder."); return; }
  try {
    await navigator.clipboard.writeText($(id).value);
    toast("Placeholder copied");
  } catch {
    toast("Copy the selected placeholder.");
  }
});

const credentialFields = (a) => owner.credentialFields(view, a);

function credentialEditor(a, f) {
  return `<div class="credential"><label for="f-${esc(f.key)}">${esc(f.label)}</label>
    <input type="hidden" id="mode-${esc(f.key)}" value="keep">
    <div id="credential-actions-${esc(f.key)}" class="credential-actions">
      <span class="credential-status muted">${esc(f.status)}${f.account ? ` · ${esc(f.account)}` : ""}</span>
      ${f.signIn ? `<button class="primary" onclick="signIn(${q(a)}, ${q(f.key)})">${esc(signInLabel(accounts()[a].preset))}</button>` : ""}
      <button id="replace-${esc(f.key)}" onclick="credentialMode(${q(a)}, ${q(f.key)}, 'replace')">${f.kind === "unset" ? "Set value" : "Replace"}</button>
      ${f.kind !== "unset" ? `<button class="danger" onclick="credentialMode(${q(a)}, ${q(f.key)}, 'clear')">Remove</button>` : ""}</div>
    <div id="credential-edit-${esc(f.key)}" hidden></div>
    <div id="credential-remove-${esc(f.key)}" hidden><p class="muted field-help" role="status">Will be removed when you save.</p></div>
    <button id="credential-cancel-${esc(f.key)}" hidden onclick="credentialMode(${q(a)}, ${q(f.key)}, 'keep')">Cancel</button></div>`;
}

function credentialMode(a, key, mode) {
  $("mode-" + key).value = mode;
  $("credential-actions-" + key).hidden = mode !== "keep";
  const editor = $("credential-edit-" + key);
  editor.hidden = mode !== "replace";
  const f = credentialFields(a).find((f) => f.key === key);
  editor.innerHTML = mode === "replace" ? `${input(f)}
    <p class="muted field-help">${f.kind === "unset" ? "Enter a value, then save." : "Your current credential stays in use until you save."}</p>` : "";
  $("credential-remove-" + key).hidden = mode !== "clear";
  $("credential-cancel-" + key).hidden = mode === "keep";
  if (mode === "replace") $("f-" + key).focus();
  else $(mode === "keep" ? "replace-" + key : "credential-cancel-" + key).focus();
}

function accountActions(a) {
  const renderAction = (node) => {
    const { effects, children, total } = node;
    const badges = effects.map((effect) => `<span class="badge ${["read", "write", "send", "delete", "admin"].includes(effect) ? "effect-" + effect : ""}">${esc(effect.charAt(0).toUpperCase() + effect.slice(1))}</span>`).join("");
    const row = `<span class="capability-name">${esc(node.title)}${children.length ? ` <small title="${total} subaction${total === 1 ? "" : "s"}" aria-label="${total} subaction${total === 1 ? "" : "s"}">${total}</small>` : ""}</span><span class="effects" aria-label="Effects">${badges || `<span class="muted">No effects</span>`}</span>`;
    return children.length
      ? `<details class="action-group" data-disclosure="${esc(a + "/" + node.key)}"><summary class="capability">${row}</summary><div class="action-children">${children.map(renderAction).join("")}</div></details>`
      : `<div class="capability">${row}</div>`;
  };
  return owner.actionTree(view, a).map(renderAction).join("") || `<p class="empty">This preset doesn't define any actions yet.</p>`;
}

function accountUsers(a) {
  const users = owner.accountUsers(view, a);
  return `<section class="account-card"><div class="section-heading"><h2>Used by <span class="count">${users.length}</span></h2></div>
    ${users.length ? `<div class="usage-columns"><span>Agent</span><span>Default access</span></div><ul class="agent-list">${users.map(({ name, level, profile, overrides }) =>
      `<li><a class="agent-link" href="#agent/${encodeURIComponent(name)}"><span class="agent-info"><strong>${esc(name)}</strong>${profile ? ` <small>Profiling on</small>` : ""} <small>${overrides ? `${overrides} action override${overrides === 1 ? "" : "s"}` : "No action overrides"}</small></span>
        <span class="badge ${["read", "ask", "allow"].includes(level) ? "level-" + level : ""}">${esc(LEVELS[level] ?? level)}</span></a></li>`).join("")}</ul>` : `<p class="empty">No agents have access to this account.</p>`}</section>`;
}

function account(a) {
  const acc = accounts()[a];
  if (!acc) return [head(esc(a)), `<p class="empty">No account ${esc(a)}.</p>`];
  const c = entry(a);
  const fields = owner.plainFields(view, a), credentials = credentialFields(a);
  return [isDashboard ? head(esc(a), accountStatus(a), "accounts") : `<header class="account-header">${accountIcon(a)}<h1>${esc(a)}</h1><span class="muted">${esc(c.title)} ${accountStatus(a)}</span><a class="x" href="#activity" aria-label="Close account">✕</a></header>`,
    liveCard(a),
    apiAgentSetup(a),
    `<div class="account-overview"><section class="account-card"><div class="section-heading"><h2>Actions <span class="count">${Object.keys(owner.actionsOf(view, a)).length}</span></h2><a href="#preset/${encodeURIComponent(acc.preset)}">Edit preset</a></div>
      <div class="action-list">${accountActions(a)}</div></section>${accountUsers(a)}</div>`,
    `<section class="account-card account-settings"><div class="section-heading"><h2>Account settings</h2></div><div class="settings-fields"><div>${questions(acc)}</div>
      ${fields.length || credentials.length || acc.preset === "custom_api" ? `<div>${acc.preset === "custom_api" ? apiConnectionFields(a) : ""}${fields.map((f) => `<label for="f-${esc(f.key)}">${esc(f.label)}</label>${input(f, f.value)}`).join("")}${credentials.map((f) => credentialEditor(a, f)).join("")}</div>` : ""}</div>
      <div id="account-effects" class="account-effects"></div>
      <div class="card-footer"><button class="primary" onclick="saveAccount(${q(a)})">Save</button></div></section>`,
    ...owner.reviews(view, a).map((s) => review(a, s, c)),
    `<section><details data-disclosure="custom-rules"><summary class="hd">Custom rules</summary><textarea id="policy" aria-label="Custom rules" rows="12">${esc(view.config.policies?.[a])}</textarea>
      <div class="row"><span></span><button onclick="commit(edits.setAccountPolicy(${q(a)}, $('policy').value))">Save rules</button></div></details></section>`,
    `<section><button class="danger" onclick="removeAccount(${q(a)})">Remove account</button></section>`];
}

function review(a, s, c) {
  if (s.state === "connecting") return `<section><h2>${esc(s.name)}</h2><p class="muted">Connecting…</p></section>`;
  if (s.error) return `<section><h2>${esc(s.name)}</h2><p class="bad">Can't connect: ${esc(s.error)}</p></section>`;
  if (!s.blocked) return "";
  return `<section><h2>${esc(s.name)}</h2><p>${c.title} changed its tools: ${s.added} new, ${s.changed} changed, ${s.removed} removed.</p>
    <details><summary class="muted">${s.blocked} tools await review</summary><pre>${esc(s.changes.join("\n\n"))}</pre></details>
    <div class="row"><span></span><button class="primary" onclick="approve(${q(a)}, ${q(s.key)})">Approve</button></div></section>`;
}

const approve = (a, key, name = owner.connectionName(a, key)) => commit(edits.approveTools(view, a, key), undefined,
  (state) => { state.view.status[name] = { ...state.view.status[name], details: { blocked: 0, changes: [] } }; });

const saveAccount = run(async (a) => {
  const credentials = credentialFields(a), modes = credentials.map((f) => $("mode-" + f.key));
  await changeSettings(edits.saveAccount(view, a, { answers: answers(), api: accounts()[a].preset === "custom_api" ? apiForm() : undefined,
    values: Object.fromEntries(owner.plainFields(view, a).map((f) => [f.key, read(f)])),
    credentials: Object.fromEntries(credentials.map((f, i) => [f.key, { mode: modes[i].value, value: modes[i].value === "replace" ? read(f) : undefined }])) }));
  credentials.forEach((f, i) => {
    if ($("mode-" + f.key) === modes[i] && modes[i].value !== "keep") credentialMode(a, f.key, "keep");
  });
});

// Sign-in leaves the current credential usable until the exchange succeeds.
const signIn = run(async (a, key) => {
  const f = credentialFields(a).find((f) => f.key === key);
  const { url } = await client().signIn(a, f.path, location.origin + location.pathname, f.credential);
  sessionStorage.setItem(RETURN, location.hash);
  location.href = url;
});

const removeAccount = (a) => commit(edits.removeAccount(view, a), "activity");

// The live browser view keeps its markup fixed so polling never replaces the image, focus or typed text; liveSync owns its lifetime.
let live = {};
const liveConnection = (a) => owner.liveConnection(view, a);
const liveCard = (a) => liveConnection(a) == null ? "" : `<section class="account-card live" aria-label="Browser"><div class="section-heading"><h2>Browser</h2>
  <span id="live-owner" class="live-owner" role="status"></span><button id="live-take" class="primary" onclick="liveOwn()"></button></div>
  <fieldset id="live-input" class="live-body" disabled>
    <div class="live-bar"><button onclick="liveAct({ action: 'back' })">Back</button><input id="live-url" aria-label="Address" onkeydown="if (event.key === 'Enter') liveNavigate()"><button onclick="liveNavigate()">Go</button></div>
    <div id="live-tabs" class="live-tabs" role="group" aria-label="Tabs"></div>
    <div id="live-screen" class="live-screen" tabindex="0" aria-label="Page. While you have control, click, scroll and type here." onkeydown="liveKey(event)" onwheel="liveWheel(event)"><img id="live-shot" alt="" hidden onclick="liveClick(event)"></div>
    <div class="live-bar"><input id="live-text" aria-label="Text to type" placeholder="Text to type" onkeydown="if (event.key === 'Enter') liveType()"><button onclick="liveType()">Type</button>
      <span class="seg" role="group" aria-label="Keys">${["Enter", "Tab", "Backspace", "Escape"].map((k) => `<button onclick="liveAct({ action: 'key', key: '${k}' })">${k === "Escape" ? "Esc" : k}</button>`).join("")}</span></div>
  </fieldset>
  <p id="live-error" class="bad live-error" role="alert" hidden></p>
  <div class="card-footer"><span class="muted">Page dialog</span><fieldset id="live-dialog" class="seg" aria-label="Page dialog" disabled>
    <button onclick="liveAct({ action: 'dialog', accept: true })">Accept</button><button onclick="liveAct({ action: 'dialog', accept: false })">Dismiss</button></fieldset></div></section>`;
const liveActive = () => live.name != null && !document.hidden && !locked && authenticated();
const liveReady = () => !!(live.frame?.owner && live.frame.frame) && !live.owning;

function liveSync() {
  const [kind, a] = route(), name = kind === "account" && view ? liveConnection(a) : null;
  if (name !== live.name) {
    clearTimeout(live.timer);
    live = { name, seq: 0, after: 0, queue: [] };
  }
  paintLive();
  if (!live.timer) livePoll();
}

function paintLive() {
  const f = live.frame, shot = $("live-shot");
  if (!shot) return;
  $("live-owner").textContent = !f ? "Connecting…" : f.owner ? "You have control. The agent is paused." : "The agent has control.";
  $("live-take").textContent = { pause: "Pausing…", resume: "Returning…" }[live.owning] ?? (f?.owner ? "Return to agent" : "Pause and take control");
  $("live-take").disabled = !!live.owning;
  $("live-input").disabled = !liveReady();
  $("live-dialog").disabled = !f?.owner || !!live.owning;
  shot.hidden = !f?.screenshot;
  if (f?.screenshot) Object.assign(shot, { src: "data:image/jpeg;base64," + f.screenshot, alt: f.tabs?.find((t) => t.active)?.title || f.url });
  if (f?.url && document.activeElement !== $("live-url")) $("live-url").value = f.url;
  const tabs = (f?.tabs ?? []).map((t) => `<button aria-pressed="${t.active}" title="${esc(t.url)}" onclick="liveAct({ action: 'tab', tab: ${q(t.id)} })">${esc(t.title || t.url)}</button>`).join("");
  if (drawn.get($("live-tabs")) !== tabs) { $("live-tabs").innerHTML = tabs; drawn.set($("live-tabs"), tabs); }
  const error = live.error || (f?.error ? "Couldn't show the page. If it opened a dialog, accept or dismiss it." : "");
  Object.assign($("live-error"), { textContent: error, hidden: !error, title: live.error ? "" : f?.error ?? "" });
}

// Every response is the whole state, so one sent before the newest shown frame or action is out of date and dropped.
async function liveRequest(l, body) {
  const seq = ++l.seq;
  if (body) l.after = seq;
  const f = await client().browser(l.name, body);
  if (seq < l.after) return;
  Object.assign(l, { after: seq, frame: f, error: "" });
  paintLive();
}

async function livePoll() {
  const l = live;
  l.timer = clearTimeout(l.timer);
  if (!liveActive() || l.polling || l.queue.length || l.owning) return;
  const after = l.after;
  l.polling = true;
  try { await liveRequest(l); } catch (err) { if (l.after === after) { l.error = err.message; paintLive(); } }
  l.polling = false;
  liveSchedule(l);
}

function liveSchedule(l) {
  if (l === live && liveActive() && !l.timer) l.timer = setTimeout(livePoll, LIVE_POLL_MS);
}

async function liveOwn() {
  const l = live, action = l.frame?.owner ? "resume" : "pause";
  if (l.owning) return;
  l.owning = action;
  l.queue.splice(1);
  paintLive();
  let failed = false;
  try { await liveRequest(l, { action }); } catch (err) { failed = true; toast(err.message); }
  l.owning = null;
  if (l !== live) return;
  paintLive();
  // A failed request may still have changed control, so look again rather than trust the last frame.
  failed ? livePoll() : liveSchedule(l);
}

// Input runs in order, each aimed at the frame on screen when the owner gave it.
function liveAct(body) {
  const l = live, frame = l.frame?.frame, last = l.queue.at(-1);
  if (body.action === "dialog" ? !l.frame?.owner || l.owning : !liveReady()) return;
  if (l.queue.length > 1 && last.action === body.action && last.frame === frame && ["type", "scroll"].includes(body.action)) {
    if (body.action === "type") last.text += body.text; else last.dy += body.dy;
    return;
  }
  l.queue.push({ ...body, frame });
  if (l.queue.length === 1) liveDrain(l);
}

async function liveDrain(l) {
  while (l.queue.length && l === live) {
    try { await liveRequest(l, l.queue[0]); } catch (err) { l.queue.splice(1); toast(err.message); }
    l.queue.shift();
  }
  liveSchedule(l);
}

// Screenshot pixels are the page's viewport pixels, whatever size the image is drawn at.
function livePoint(e) {
  const img = $("live-shot"), r = img.getBoundingClientRect(), scale = img.naturalWidth / r.width;
  return { x: (e.clientX - r.left) * scale, y: (e.clientY - r.top) * scale };
}
const liveClick = (e) => liveAct({ action: "click", ...livePoint(e) });

function liveWheel(e) {
  if (!liveReady()) return;
  e.preventDefault();
  liveAct({ action: "scroll", ...livePoint(e), dy: e.deltaY * (e.deltaMode ? WHEEL_LINE_PX : 1) });
}

function liveKey(e) {
  if (e.ctrlKey || e.metaKey || e.altKey || !liveReady()) return;
  const body = e.key.length === 1 ? { action: "type", text: e.key } : LIVE_KEYS.includes(e.key) ? { action: "key", key: e.key } : null;
  if (!body) return;
  e.preventDefault();
  liveAct(body);
}

function liveType() {
  if ($("live-text").value) liveAct({ action: "type", text: $("live-text").value });
  $("live-text").value = "";
}

function liveNavigate() {
  const url = $("live-url").value.trim();
  if (url) liveAct({ action: "navigate", url: url.includes("://") ? url : "https://" + url });
  $("live-screen").focus();
}


const copyIntegration = run(async (id) => {
  const block = $(id);
  try {
    await navigator.clipboard.writeText(block.textContent);
    toast("Copied");
  } catch {
    const selection = window.getSelection();
    if (selection) {
      const range = document.createRange();
      range.selectNodeContents(block);
      selection.removeAllRanges();
      selection.addRange(range);
    }
    toast(selection ? "Text selected. Press Cmd-C or Ctrl-C to copy." : "Select the command text and copy it.");
  }
});

function integrations(page = "start") {
  const pages = owner.INTEGRATION_PAGES;
  if (!Object.hasOwn(pages, page)) page = "start";
  const html = owner.integrationGuide(view, page, (route) => "#" + route.map(encodeURIComponent).join("/"));
  return [head("Integrations"), `<nav class="integration-nav" aria-label="Integration guides">${Object.entries(pages).map(([key, title]) => `<a href="#integrations/${key}" ${page === key ? 'aria-current="page"' : ""}>${title}</a>`).join("")}</nav>`, `<article class="integration-guide">${html}</article>`];
}

// Polling leaves the draft alone. A preview is valid only for the draft that produced it.
let policyEditor = null, policyLoading = false, policyLoadError = "";
const loadPolicy = run(async () => {
  if (policyLoading) return;
  policyLoading = true;
  policyLoadError = "";
  try {
    const saved = await client().policy(true);
    policyEditor = { ...saved, draft: saved.source, preview: null };
  } catch (err) {
    policyLoadError = err.message;
    throw err;
  } finally { policyLoading = false; }
  render();
});
function changePolicy(text) {
  policyEditor.draft = text;
  policyEditor.preview = null;
  render();
}
const previewPolicy = run(async () => {
  const editor = policyEditor, draft = editor.draft;
  const result = await client().previewPolicy(draft);
  if (policyEditor === editor && editor.draft === draft) editor.preview = result;
  render();
});
const applyPolicySource = run(async () => {
  const editor = policyEditor, preview = editor?.preview;
  if (!preview) throw new Error("Review the policy diff before applying.");
  await edit(() => {}, () => client().applyPolicy(editor.draft), { message: "Policy applied" });
  if (policyEditor === editor) await loadPolicy();
});
function downloadPolicyText(source, filename) {
  const url = URL.createObjectURL(new Blob([source], { type: "application/toml" }));
  Object.assign(document.createElement("a"), { href: url, download: filename }).click();
  setTimeout(() => URL.revokeObjectURL(url), 1000);
}
const downloadActivePolicy = run(async () => {
  const saved = await client().policy();
  downloadPolicyText(saved.source, "policy.toml");
});
function policyPage() {
  if (!policyEditor) {
    if (policyLoadError) return [head("Policy"), `<section><p class="bad">${esc(policyLoadError)}</p><button onclick="loadPolicy()">Retry</button></section>`];
    if (!policyLoading) loadPolicy();
    return [head("Policy"), `<p class="empty">Loading policy…</p>`];
  }
  const p = policyEditor;
  return [head("Policy"),
    `<section><p>This file is the source of truth for saved permissions. Changes made elsewhere in Monitor update it too.</p>
      <p class="muted">Credentials are stored separately.</p>
      <div class="row"><button onclick="loadPolicy()">Reload active file</button><button onclick="downloadActivePolicy()">Download active policy.toml</button></div></section>`,
    `<section><label for="policy-source">policy.toml</label><textarea id="policy-source" rows="30" spellcheck="false" oninput="changePolicy(this.value)">${esc(p.source)}</textarea></section>`,
    `<section><div class="row"><button onclick="previewPolicy()">Validate and review diff</button><button class="primary" ${!p.preview ? "disabled" : ""} onclick="applyPolicySource()">Apply reviewed change</button></div></section>`,
    p.preview ? `<section><h2>Source changes</h2><pre>${esc(p.preview.source_diff || "No source changes.")}</pre><h2>Effective changes</h2><pre>${esc(p.preview.effective_diff || "No effective changes.")}</pre></section>` : "",
    `<section><details><summary>Effective policy, including preset definitions</summary><pre>${esc(p.effective)}</pre></details></section>`];
}
const settings = () => [head("Settings"), `<section><h2>Policy preset</h2>
  <label for="policy-preset">Choose a starting policy for this monitor</label>
  <select id="policy-preset">${Object.entries(owner.POLICY_PRESETS).map(([value, policy]) => opt(value, policy.title, view.config.data?.onboarding?.preset ?? "known_only")).join("")}</select>
  <p class="muted">You can edit individual permissions after applying a preset.</p>
  <div class="row"><span></span><button onclick="applyPolicyPreset()">Apply preset</button></div>
  </section>`, `<section><h2>Effects</h2>
  <label><input type="checkbox" ${view.config.allow_paid_inference ? "checked" : ""} onchange="commit(edits.setPaidInference(this.checked))"> Allow paid AI inference</label>
  <p class="muted">Allow model generation without payment approval by default. Provider charges apply. Explicit payment settings and other restrictions still apply.</p>
  ${effectControls()}</section>`, `<section><h2>Lattices</h2>
  <p class="muted">Applies to all agents and connector requests.</p>
  <label><input type="checkbox" ${lattices().confidentiality ? "checked" : ""} onchange="commit(edits.setLattice('confidentiality', this.checked))"> Confidentiality lattice</label>
  <p class="muted">Restrict where agents can send private data. On by default.</p>
  <label><input type="checkbox" ${lattices().integrity ? "checked" : ""} onchange="commit(edits.setLattice('integrity', this.checked))"> Integrity lattice</label>
  <p class="muted">Restrict sensitive actions after agents read untrusted content. Off by default.</p>
  <p class="muted">Labels keep their history while enforcement is off. Access permissions, explicit approvals and custom rules still apply.</p>
  </section>`, `<section><h2>Networks</h2><label for="networks">Private networks the monitor may reach, one per line</label>
  <textarea id="networks" rows="4">${esc((view.config.allow_networks ?? []).join("\n"))}</textarea>
  <div class="row"><span></span><button onclick="commit(edits.setNetworks($('networks').value))">Save</button></div></section>`];

// Both entry points use this runtime and the same owner session. The dashboard
// supplies list/navigation markup; detailed controls call the same owner actions.
let dashboardRoute = null, dashboardFilters = { query: "", state: "", agent: "", account: "", page: 0 };
const dashboardFilterCache = new Map();
function dashboardBack(back) {
  if (back !== "activity") return back;
  return ({ agent: "agents", "agent-settings": "agents", pair: "agents", account: "accounts", add: "catalog", preset: "presets" })[route()[0]] ?? back;
}
function dashboardBackLabel(back) {
  const path = dashboardBack(back).split("/")[0];
  return dashboard.sections[path]?.[0].toLowerCase() ?? (path === "agent" ? "agent" : "activity");
}
const collapsedCatalogGroups = new Set();
function toggleCatalogGroup(element) {
  if (!element.isConnected || dashboardFilters.query) return;
  const key = element.dataset.group;
  if (element.open) collapsedCatalogGroups.delete(key);
  else collapsedCatalogGroups.add(key);
}

function renderDashboard(kind, args, panes, parts) {
  const routeKey = location.hash || "#activity";
  if (dashboardRoute !== routeKey) {
    if (dashboardRoute !== null) dashboardFilterCache.set(dashboardRoute, dashboardFilters);
    dashboardRoute = routeKey;
    dashboardFilters = dashboardFilterCache.get(routeKey) ?? { query: "", state: "", agent: "", account: "", page: 0 };
    if (kind === "agents" && args[0]) expanded.add("agent/" + encodeURIComponent(args[0]));
    if (!dashboardFilterCache.has(routeKey) && kind === "activity" && ["agent", "account"].includes(args[0])) dashboardFilters[args[0]] = args[1] ?? "";
    sync($("toolbar"), []);
    $("workspace").scrollTop = 0;
  }
  const collection = ["agents", "accounts", "catalog", "presets"].includes(kind);
  const activity = kind === "activity";
  $("pane").hidden = activity;
  $("list").hidden = !activity;
  sync($("tree"), dashboard.navigation(kind, view, records));
  sync($("page-header"), dashboard.pageHeader(kind, args, view, records));
  sync($("overview"), activity ? dashboard.stats(view, records) : []);
  sync($("toolbar"), dashboard.toolbar(kind, view, records));
  for (const field of ["state", "agent", "account"]) if ($("filter-" + field)) $("filter-" + field).value = dashboardFilters[field];
  if ($("dashboard-search")) $("dashboard-search").value = dashboardFilters.query;
  sync($("list"), activity ? dashboard.activity(view, records, dashboardFilters, JSON.parse(localStorage.getItem(DISMISSED) ?? "[]"), accountIcon) : []);
  let content = collection ? dashboard.collection(kind, view, dashboardFilters.query, connectorIcon, collapsedCatalogGroups, inlineAgent) : panes[kind]?.(...args) ?? [];
  if (kind === "rules" && content.length === 1) content.push(dashboard.empty("No saved rules", "Save an approval rule from a request to allow matching requests in the future.", '<a class="button" href="#activity">View activity</a>', "rules"));
  if (!activity && !content.length) content = [dashboard.empty("Page not found", "Choose a section from the sidebar.", '<a class="button" href="#activity">View activity</a>')];
  sync($("pane"), parts(content));
  $("fun-ui-link").href = "fun_ui.html" + (collection ? "#activity" : location.hash);
}
function filterDashboard(field, value) {
  if (field === "clear" || field === "pending") dashboardFilters = { query: "", state: field === "pending" ? "pending" : "", agent: "", account: "", page: 0 };
  else { dashboardFilters[field] = value; if (field !== "page") dashboardFilters.page = 0; }
  render();
}
const refreshDashboard = run(async () => { await refresh(); render(); toast("Monitor refreshed"); });
function toggleNavigation(button) {
  const open = $("navigation").classList.toggle("open");
  button.setAttribute("aria-expanded", String(open));
}
function applyTheme() {
  const preference = localStorage.getItem("monitor-theme") ?? "system";
  document.documentElement.dataset.theme = preference === "system" ? (matchMedia("(prefers-color-scheme: dark)").matches ? "dark" : "light") : preference;
  $("theme-toggle").title = `Theme: ${preference}. Click to change.`;
  $("theme-toggle").setAttribute("aria-label", `Theme: ${preference}. Change color theme`);
  $("theme-toggle").innerHTML = dashboard.icon(document.documentElement.dataset.theme === "dark" ? "sun" : "moon");
  document.querySelectorAll('.connector-icon source').forEach(source => {
    source.media = document.documentElement.dataset.theme === "dark" ? "all" : "not all";
  });
}
function cycleTheme() {
  const modes = ["system", "light", "dark"];
  localStorage.setItem("monitor-theme", modes[(modes.indexOf(localStorage.getItem("monitor-theme") ?? "system") + 1) % modes.length]);
  applyTheme();
}

const sessionFragment = new URLSearchParams(location.hash.slice(1));
if (sessionFragment.has("session")) {
  ownerSession = sessionFragment.get("session");
  sessionStorage.setItem("monitor-local-session", ownerSession);
  history.replaceState(null, "", location.pathname);
}

function hashChanged() {
  // A restarted local SSH tunnel may reuse this origin. Reload to consume its new
  // capability and discard pending requests from the previous session.
  if (new URLSearchParams(location.hash.slice(1)).has("session")) location.reload();
  else {
    if (isDashboard) {
      $("navigation").classList.remove("open");
      document.querySelector(".mobile-toggle").setAttribute("aria-expanded", "false");
    }
    render();
  }
}
window.addEventListener("hashchange", hashChanged);
if (isDashboard) {
  $("fun-ui-link").innerHTML = 'Fun UI ' + dashboard.icon("external");
  applyTheme();
  matchMedia("(prefers-color-scheme: dark)").addEventListener("change", applyTheme);
  $("workspace").addEventListener("scroll", () => $("page-header").classList.toggle("pinned", $("workspace").scrollTop > 0), { passive: true });
} else {
  const switcher = document.createElement("a");
  switcher.href = "./" + location.hash;
  switcher.textContent = "Management UI";
  switcher.style.cssText = "position:fixed;bottom:8px;left:8px;font-size:11px;z-index:10";
  switcher.addEventListener("click", () => { switcher.href = "./" + location.hash; });
  document.body.append(switcher);
}
document.addEventListener("visibilitychange", liveSync);
document.addEventListener("click", (e) => { const id = e.target.closest?.("[data-copy]")?.dataset.copy; if (id) copyIntegration(id); });
// Inline handlers in the rendered markup run in global scope.
Object.assign(globalThis, { $, addAccount, addCustomAPI, answer, apiAuthChanged, applyPolicySource, approve, changePolicy, commit, copyAPIPlaceholder, copySettings,
  cycleTheme, filterDashboard, refreshDashboard, toggleCatalogGroup, toggleNavigation,
  credentialMode, dismiss, downloadActivePolicy, downloadPreset, edits, liveAct, liveClick, liveKey, liveNavigate, liveOwn, liveType, liveWheel, loadPolicy, loadRequest,
  applyPolicyPreset, chooseOnboardingPreset, chooseOnboardingPaidInference, finishOnboarding, pairAgent, pasteOwnerKey, patchAccess, previewPolicy, removeAccount, removeAgent, removeRule, saveAccount, savePreset, setKey, setLabel, setupToken, signIn, toggle, toggleSecret, unlock });
setInterval(run(async () => {
  if (!ownerMode || !authenticated() || locked) return;
  const changed = await refresh();
  if (changed || pendingSoonest().length) render();
}), REQUEST_POLL_MS);
// Every provider returns here; the authenticated owner API exchanges the code.
const back = new URLSearchParams(location.search);
if (back.has("state") || back.has("code") || back.has("error")) {
  history.replaceState(null, "", location.pathname + (sessionStorage.getItem(RETURN) ?? ""));
  sessionStorage.removeItem(RETURN);
}
run(async () => {
  await loadOwnerMode();
  await iconsReady;
  if (!authenticated()) return;
  await refresh();
  if (!back.has("code") && !back.has("error")) return;
  if (!back.get("state") || ["state", "code", "client_id", "error"].some((key) => back.getAll(key).length > 1)) throw new Error("Invalid sign-in callback. Start sign-in again.");
  render();
  toast("Finishing sign-in…");
  const result = Object.fromEntries(["code", "client_id", "error"].filter((key) => back.has(key)).map((key) => [key, back.get(key)]));
  remember(await client().finishSignIn(back.get("state"), result));
  toast("Signed in");
})().then(render);
