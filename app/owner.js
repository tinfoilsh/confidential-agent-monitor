// The owner API client and the request, permission and account semantics shared by
// Monitor's own app and embedding dashboards. The server remains the authority: these
// functions shape edits and describe its answers.

export const LEVELS = { off: "No access", read: "Read only", ask: "Ask", allow: "Allow" };
export const MODES = { allow: "Allow", ask: "Ask", off: "Deny" };
export const AUDIENCES = { me: "Only me", team: "My team", anyone: "Anyone" };
export const TRUSTS = { trusted: "Trusted", untrusted: "Untrusted" };
export const CATALOG_GROUPS = { api: "API", mcp: "MCP", protocol: "Protocol" };
export const CREDENTIAL_STATUS = { "oauth-required": "Sign-in required", unset: "Not configured" };
export const POLICY_PRESETS = {
  open: { title: "Open", description: "Allow unrestricted TCP network access." },
  known_only: { title: "Known only", description: "Allow only connections and operations covered by your policy. Block everything else." },
  offline: { title: "Offline", description: "Block agent connections to all services and sandbox routes." },
};
// A new preset starts as one bearer-token API; the owner sets its origin, slots and operations.
export const NEW_PRESET = { catalog: { group: "api", fields: [{ key: "token", label: "API token", secret: true, path: ["connections", "", "http", "secrets", "token"] }],
  connections: { "": { http: { slots: [{ value: "token", origin: "https://api.example.com", path: "/", header: "Authorization", prefix: "Bearer " }] } } },
  defaults: { contents: "me", strangers: true, sends: "me" } }, http: { operations: {} } };
const LOOPBACK = ["localhost", "127.0.0.1", "[::1]"];

// Human input preserves UTF-8 bytes, including whitespace. Old canonical
// base64 32-byte keys keep their original meaning; base64 is only the wire format.
export function encodeOwnerKey(input) {
  if (typeof input === "string" && input.trim().startsWith("{")) throw new Error("Use tinfoil monitor open. Do not load private credential files into a remote web page.");
  if (typeof input !== "string") throw new Error("Enter your owner key or passphrase.");
  const legacy = input.trim();
  try {
    const decoded = atob(legacy);
    if (decoded.length === 32 && btoa(decoded) === legacy) return legacy;
  } catch {}
  const bytes = new TextEncoder().encode(input);
  if (bytes.length < 16 || bytes.length > 4096) throw new Error("Use an owner key or passphrase between 16 and 4096 UTF-8 bytes.");
  return btoa(String.fromCharCode(...bytes));
}

export class OwnerError extends Error {
  constructor(message, status) {
    super(message);
    this.status = status;
  }
}

// Keep validators and parsed responses in this authenticated client's memory,
// never in browser storage. Bound the cache when navigating through audit details.
function ownerJSON(fetch) {
  const cache = new Map();
  return async (url, options) => {
    const read = options.method === "GET", known = read && cache.get(url);
    if (!read) cache.clear();
    const res = await fetch(url, { ...options, headers: { ...options.headers,
      ...(known && { "If-None-Match": known.tag }) } });
    if (res.status === 304 && known) {
      cache.delete(url);
      cache.set(url, known);
      return known.value;
    }
    const text = await res.text();
    if (!res.ok) throw new OwnerError(text.trim() || `Request failed (${res.status})`, res.status);
    const value = text ? JSON.parse(text) : null, tag = res.headers.get("ETag");
    cache.delete(url);
    if (read && tag) {
      cache.set(url, { tag, value });
      if (cache.size > 4) cache.delete(cache.keys().next().value);
    }
    return value;
  };
}

// Without an endpoint, requests go to the page's own origin; any given endpoint, even an empty one, must be a valid URL.
// A remote owner API needs HTTPS. The key is never sent on a redirect.
export function ownerClient({ endpoint, key, generation, fetch = (...args) => globalThis.fetch(...args) }) {
  if (typeof key === "string" && key.trim().startsWith("{")) throw new Error("Signing credentials require tinfoil monitor open and its attested connection.");
  let base = "";
  if (endpoint !== undefined) {
    let url;
    try { url = new URL(endpoint); } catch { throw new Error("Invalid monitor endpoint."); }
    if (url.protocol !== "https:" && !(url.protocol === "http:" && LOOPBACK.includes(url.hostname))) throw new Error("The monitor endpoint must use HTTPS.");
    if (url.username || url.password || url.search || url.hash) throw new Error("Invalid monitor endpoint.");
    base = url.href.replace(/\/$/, "");
  }
  const json = ownerJSON(fetch);
  return ownerApi((method, path, body, signal) => {
    return json(base + path, { method, signal, cache: "no-store", credentials: "omit", redirect: "error",
      headers: { Authorization: "Bearer " + key, ...(body !== undefined && { "Content-Type": "application/json" }) },
      body: body === undefined ? undefined : JSON.stringify(body) });
  }, generation, base);
}

// With a known generation, an older view is a rollback, and a locked monitor unlocks at that minimum.
export function ownerApi(request, generation, base = "") {
  let minimum = generation;
  let catalog;
  const checked = (view) => {
    if (minimum !== undefined && view) {
      if (view.generation < minimum) throw new OwnerError("The monitor state is older than the last state you saw. Restore the latest monitor state before continuing.", 409);
      minimum = view.generation;
    }
    return view;
  };
  const get = (path, signal) => request("GET", path, undefined, signal);
  const post = (path, body, signal) => request("POST", path, body, signal);
  const snapshot = async (method, path, body, signal) => {
    const known = catalog;
    const view = await request(method, known ? `${path}?catalog=${encodeURIComponent(known.id)}` : path, body, signal);
    if (view?.catalog_id) {
      if (view.presets) catalog = { id: view.catalog_id, presets: view.presets };
      else if (known?.id === view.catalog_id) view.presets = known.presets;
      else throw new OwnerError("Monitor returned an unknown preset catalog. Reload the page.", 409);
    }
    return checked(view);
  };
  const unlock = (at = minimum ?? 0, signal) => snapshot("POST", "/unlock", { generation: at }, signal);
  return {
    async read(signal, { summary = false } = {}) {
      const path = summary ? "/requests?summary" : "/requests";
      const [view, requests] = await Promise.all([snapshot("GET", "/", undefined, signal), get(path, signal)]).catch(async (err) => {
        if (err.status !== 423 || minimum === undefined) throw err;
        return [await unlock(minimum, signal), await get(path, signal)];
      });
      return { view: checked(view), requests: requests ?? [] };
    },
    request: (id, signal) => get(`/requests/${encodeURIComponent(id)}`, signal),
    unlock,
    onboard: (view, preset, signal, { allowPaidInference = true } = {}) => onboarded(view) ? Promise.resolve(view)
      : snapshot("POST", "/policy/edits", { changes: [...edits.applyPolicyPreset(view, preset), ...edits.setPaidInference(allowPaidInference)], generation: view.generation }, signal),
    edit: (changes, signal) => snapshot("POST", "/policy/edits", { changes }, signal),
    decide: (id, decision, signal) => post(`/requests/${encodeURIComponent(id)}`, { decision }, signal),
    label: (name, label, signal) => snapshot("POST", `/labels/${encodeURIComponent(name)}`, label, signal),
    preset: (name, signal) => get(`/presets/${encodeURIComponent(name)}`, signal),
    policy: (effective, signal) => get(effective ? "/policy?effective" : "/policy", signal),
    previewPolicy: (source, signal) => post("/policy/preview", { source }, signal),
    applyPolicy: (source, signal) => snapshot("POST", "/policy", { source }, signal),
    signIn: (account, path, redirect, credential, signal) => post(`/accounts/${encodeURIComponent(account)}/sign-in`, { path, redirect, credential }, signal),
    finishSignIn: (state, result, signal) => snapshot("POST", `/sign-in/${encodeURIComponent(state)}`, typeof result === "string" ? { code: result } : result, signal),
    browser: (name, body, signal) => request(body ? "POST" : "GET", `/connections/${encodeURIComponent(name)}/browser`, body, signal),
    icons: async (signal) => {
      const manifest = await get(ICON_MANIFEST, signal);
      return (preset) => connectorIcon(manifest, preset, base);
    },
  };
}

// Monitor serves connector icons with its app. The manifest names each preset's file and optional dark variant;
// a preset without one shows the custom icon.
const ICON_MANIFEST = "/app/icons/manifest.json";
export function connectorIcon(manifest, preset, base = "") {
  if (preset === "codex") preset = "openai";
  if (preset === "openrouter") preset = "open_router";
  const icon = manifest?.[preset]?.src ? manifest[preset] : manifest?.custom ?? { src: "custom.svg" };
  const url = (file) => `${base}/app/icons/${encodeURIComponent(file)}`;
  return { src: url(icon.src), ...(icon.dark && { dark: url(icon.dark) }) };
}

// Controls address source values; named rules and operations stay named.
export function sourceChanges(body, path = []) {
  return Object.entries(body).flatMap(([key, value]) => {
    const at = [...path, key];
    if (value === null) return [{ path: at, delete: true }];
    const atomic = key === "scope" || key === "fields" || key === "query" || key === "headers" ||
      at[0] === "identities" && at[2] === "rules" && at.length === 4 || value?.oauth || value?.$json;
    if (!atomic && value && typeof value === "object" && !Array.isArray(value) && Object.keys(value).length)
      return sourceChanges(value, at);
    return [{ path: at, value }];
  });
}

export function applyChanges(target, changes) {
  for (const change of changes) {
    let parent = target;
    for (const key of change.path.slice(0, -1)) {
      if (!Object.hasOwn(parent, key) || !parent[key] || typeof parent[key] !== "object")
        Object.defineProperty(parent, key, { value: {}, enumerable: true, configurable: true, writable: true });
      parent = parent[key];
    }
    const key = change.path.at(-1);
    if (change.delete) delete parent[key];
    else Object.defineProperty(parent, key, { value: structuredClone(change.value), enumerable: true, configurable: true, writable: true });
  }
  return target;
}

// previewChanges shows edits before the server confirms them, including edited presets' catalogs.
export function previewChanges(view, changes, shipped = {}) {
  view.config = applyChanges(view.config, changes);
  for (const name of new Set(changes.filter((c) => c.path[0] === "presets" && c.path.length > 1).map((c) => c.path[1]))) {
    const file = view.config.presets?.[name] ?? shipped[name];
    if (!file) continue; // A shipped preset not fetched yet needs the server's resolved catalog.
    const previous = view.presets[name] ?? view.presets.custom, catalog = file.catalog ?? {};
    view.presets[name] = { ...previous, ...catalog, title: typeof file.title === "string" ? file.title : name,
      fields: Array.isArray(catalog.fields) ? catalog.fields : previous?.fields ?? [],
      actions: catalog.actions ?? {}, operations: file.http?.operations ?? {} };
  }
  return view;
}

const identities = (view) => view.config.identities ?? {};
export const onboarded = (view) => view.config.data?.onboarding?.completed === true;
const accounts = (view) => view.config.accounts ?? {};
export const lattices = (view) => ({ confidentiality: view.config.lattices?.confidentiality ?? true, integrity: view.config.lattices?.integrity ?? false });
export const presetOf = (view, account) => view.presets[accounts(view)[account]?.preset] ?? view.presets.custom;
export const connectionName = (account, key) => (key ? `${account}-${key}` : account);
const fill = (text, scope) => text.replace(/\{(\w+)\}/g, (m, k) => scope?.[k] ?? m);
const filled = (c, values) => JSON.parse(JSON.stringify(c), (_, v) => typeof v === "string" ? fill(v, values) : v);
const atPath = (object, path) => path.reduce((value, key) => value?.[key], object);
// JSON values are equal regardless of key order, which differs between server responses and edited copies.
const same = (a, b) => a === b || !!a && !!b && typeof a === "object" && typeof b === "object" && Array.isArray(a) === Array.isArray(b)
  && Object.keys(a).length === Object.keys(b).length && Object.keys(a).every((k) => Object.hasOwn(b, k) && same(a[k], b[k]));
function putPath(object, path, value) {
  for (const key of path.slice(0, -1)) {
    if (!Object.hasOwn(object, key)) Object.defineProperty(object, key, { value: {}, enumerable: true });
    object = object[key];
  }
  Object.defineProperty(object, path.at(-1), { value, enumerable: true, configurable: true, writable: true });
}
const esc = (s) => String(s ?? "").replace(/[&<>"']/g, (c) => `&#${c.charCodeAt(0)};`);

export function summary(e) {
  if (e?.http) return `${e.http.method} ${e.http.host}${e.http.path}`;
  if (e?.smtp) return `To ${e.smtp.to.join(", ")}${e.mail?.subject ? `: ${e.mail.subject}` : ""}`;
  if (e?.imap) return `${e.imap.command} ${e.imap.args}`;
  if (e?.mcp) return e.mcp.tool;
  return "";
}
export const requestTitle = (r) => r.facts?.title || summary(r.facts?.details) || r.facts?.operation?.id || r.facts?.account;
export const reasons = (r) => (r.requirements ?? []).map((requirement) => requirement.message);
// A pending request past its deadline is expired, even before the next poll says so.
export const stateAt = (r, now) => r.state === "pending" && r.expires && Date.parse(r.expires) <= now ? "expired" : r.state;
export const pendingSoonest = (records) => records.filter((r) => r.state === "pending").sort((a, b) => new Date(a.expires) - new Date(b.expires));
export function ordered(records, dismissed = []) {
  const priority = (r) => r.state === "pending" ? 0 : r.state === "expired" && !dismissed.includes(r.id) ? 1 : 2;
  return [...records].sort((a, b) => priority(a) - priority(b) || (a.state === "pending" && b.state === "pending" ? new Date(a.expires) - new Date(b.expires) : 0));
}
export function timeLeft(r, now = Date.now()) {
  const s = Math.max(0, Math.round((new Date(r.expires) - now) / 1000));
  return `${Math.floor(s / 60)}:${String(s % 60).padStart(2, "0")}`;
}

// A saved approval binds one operation and its grant. The text names fields, not values, which can be whole messages;
// fields left out of the grant are named as broad.
export function grantText(operation, grant, scope) {
  const fields = Object.keys(grant ?? {}), broad = Object.keys(scope ?? {}).filter((k) => !fields.includes(k));
  return `Allow ${operation} ${fields.length ? "for the same " + fields.join(", ") : "for any request"}`
    + (fields.length && broad.length ? `, with any ${broad.join(", ")}` : "");
}
export const saveText = (r) => `${grantText(r.facts?.operation?.id, r.grant, r.facts?.parameters)} on future attempts. Retry this request after saving.`;
// Saving a rule never resumes the original call; it also works after a timeout.
export function decisions(r, now) {
  const state = now === undefined ? r.state : stateAt(r, now);
  const save = r.facts?.operation?.action != null && !!r.facts?.operation?.id;
  return r.savingDecision ? {} : state === "pending" ? { once: true, save, deny: true } : state === "expired" ? { save, dismiss: true } : {};
}
export function ruleSentence(r) {
  if (!r.operation) return `Inactive: ${r.action} on ${r.account} was saved before approvals named an operation`;
  return `${grantText(r.operation, r.scope, r.scope)} on ${r.account}. Approval covers: ${reasons(r).join(" ")}`;
}

// Each pinned MCP tool is an action under read or use, by the hint the owner approved with the pin.
export const actionsOf = (view, account) => ({ ...groupsOf(view, account), ...presetOf(view, account).actions, ...Object.fromEntries(Object.values(accounts(view)[account]?.connections ?? {})
  .flatMap((c) => c.mcp?.pin?.tools ?? []).map((t) => [`${t.annotations?.readOnlyHint ? "read" : "use"}.${t.name}`, { title: t.title || t.name }])) });
// Record operations also contribute permission groups to their preset.
const operationsOf = (view, account) => Object.values(presetOf(view, account).operations ?? {});
const groupsOf = (view, account) => Object.fromEntries(operationsOf(view, account).map((o) => [o.action, { title: o.action }]));
// effectsOf unions the effects of every operation under an action, so a group shows its strictest obligations.
const effectGroups = new WeakMap();
const effectGroupsOf = (view, account) => {
  const preset = presetOf(view, account), actions = preset.actions ?? {};
  let groups = effectGroups.get(preset);
  if (!groups) {
    groups = new Map();
    const add = (action, effects) => action.split(".").forEach((_, i, parts) => {
      const key = parts.slice(0, i + 1).join(".");
      if (!groups.has(key)) groups.set(key, { effects: new Set(), otherPayments: false });
      const group = groups.get(key);
      for (const effect of effects) group.effects.add(effect);
      if (effects.includes("pay") && !effects.includes("generate")) group.otherPayments = true;
    });
    for (const [action, meta] of Object.entries(actions)) add(action, meta.effects ?? []);
    for (const op of Object.values(preset.operations ?? {})) add(op.action, op.effects ?? []);
    effectGroups.set(preset, groups);
  }
  return groups;
};
export const effectsOf = (view, account, k) => {
  const actions = presetOf(view, account).actions ?? {}, groups = effectGroupsOf(view, account);
  const lineage = k.split(".").map((_, i, parts) => parts.slice(0, i + 1).join(".")).reverse();
  const inherited = lineage.find((a) => actions[a]?.effects);
  return [...new Set([...(actions[inherited]?.effects ?? []), ...(groups.get(k)?.effects ?? [])])];
};

// Effect settings use the same precedence as config.effectModes. Keeping the
// inherited value lets editors remove an override without copying a default.
export function effectSettings(view, { agent, account } = {}, effects = []) {
  const id = identities(view)[agent] ?? {};
  const pair = id.accounts?.[account] ?? view.config.default_access?.[account];
  const layers = [["Global settings", view.config.effects]];
  if (account) layers.push([`Account ${account}`, accounts(view)[account]?.effects]);
  if (agent) layers.push([`Agent ${agent}`, id.effects]);
  if (agent && account) layers.push([`Agent ${agent} on ${account}`, pair?.effects]);
  return Object.entries(view.vocabulary).sort(([a], [b]) => a.localeCompare(b)).map(([effect, metadata]) => {
    let mode = metadata.ask ? "ask" : "allow", source = "Monitor defaults";
    if (effect === "pay" && view.config.allow_paid_inference && effects.includes("generate") && effects.includes("pay")) {
      mode = "allow";
      source = "Paid AI inference";
    }
    for (const [name, values] of layers.slice(0, -1)) {
      if (values?.[effect]) { mode = values[effect]; source = name; }
    }
    const own = layers.at(-1)[1]?.[effect] ?? null;
    return { effect, own, inherited: mode, mode: own ?? mode, source: own ? layers.at(-1)[0] : source };
  });
}

// Action access and effect settings are independent restrictions; the strictest wins.
export function mode(access, vocabulary, effects, k, settings = {}) {
  if (!access.level || access.level === "off") return "off";
  const lineage = k.split(".").map((_, i, p) => p.slice(0, p.length - i).join("."));
  const has = (name) => effects.some((e) => vocabulary[e]?.[name]);
  const action = lineage.map((a) => access.actions?.[a]).find(Boolean)
    ?? (has("change") ? (access.level === "read" ? "off" : access.level) : "allow");
  const modes = [action, ...effects.map((e) => settings[e] ?? (vocabulary[e]?.ask ? "ask" : "allow"))];
  return modes.includes("off") ? "off" : modes.includes("ask") ? "ask" : "allow";
}

// actionTree nests dotted actions under titled groups, each with its effects and number of descendant actions.
export function actionTree(view, account) {
  const roots = [];
  for (const [key, action] of Object.entries(actionsOf(view, account)).sort(([a], [b]) => a.localeCompare(b))) {
    let children = roots;
    key.split(".").forEach((part, i, parts) => {
      const path = parts.slice(0, i + 1).join(".");
      let node = children.find((n) => n.key === path);
      if (!node) children.push(node = { key: path, title: part.charAt(0).toUpperCase() + part.slice(1).replace(/[_-]/g, " "), action: false, children: [] });
      if (path === key) Object.assign(node, { title: action.title || key, action: true });
      children = node.children;
    });
  }
  const finish = (node) => {
    node.children.forEach(finish);
    return Object.assign(node, { effects: effectsOf(view, account, node.key), total: node.children.reduce((n, c) => n + Number(c.action) + c.total, 0) });
  };
  return roots.map(finish);
}

export const levelsOf = (account) => Object.entries(LEVELS).filter(([l]) => account?.preset !== "custom_api" || l !== "read");

// agentAccess describes an agent's level for every account and, below it, each action's own and inherited mode.
export function agentAccess(view, name) {
  const id = identities(view)[name] ?? {};
  return Object.entries(accounts(view)).map(([account, acc]) => {
    const access = id.accounts?.[account] ?? view.config.default_access?.[account] ?? { level: "off" };
    const describe = (node) => {
      // A group containing other payments must still show their approval requirement.
      const effects = effectGroupsOf(view, account).get(node.key)?.otherPayments ? node.effects.filter(e => e !== "generate") : node.effects;
      const settings = Object.fromEntries(effectSettings(view, { agent: name, account }, effects).map(({ effect, mode }) => [effect, mode]));
      return { ...node, own: access.actions?.[node.key] ?? null,
        inherited: mode({ ...access, actions: { ...access.actions, [node.key]: null } }, view.vocabulary, node.effects, node.key, settings),
        overrides: Object.keys(access.actions ?? {}).filter((action) => action.startsWith(node.key + ".") && access.actions[action]).length,
        children: node.children.map(describe) };
    };
    return { account, preset: acc.preset, level: access.level, levels: levelsOf(acc), overrides: Object.values(access.actions ?? {}).filter(Boolean).length,
      actions: access.level === "off" ? [] : actionTree(view, account).map(describe) };
  });
}

export function browsingHint(view, name) {
  const id = identities(view)[name] ?? {};
  const reaches = (pred) => Object.entries(accounts(view)).some(([a, acc]) => (id.accounts?.[a]?.level ?? "off") !== "off" && pred(acc));
  return lattices(view).confidentiality && reaches((acc) => acc.preset === "web") && reaches((acc) => acc.contents !== "anyone");
}

export function labelStatus(view, l) {
  const on = lattices(view);
  const lines = [on.confidentiality && l?.audience && l.audience !== "anyone" && `Has seen private data${l.because?.audience ? ` from ${l.because.audience}` : ""}`, on.integrity && l?.trust === "untrusted" && "Has read content from strangers"];
  return lines.filter(Boolean).join(" · ") || "Clean";
}

export const accountUsers = (view, account) => Object.entries(identities(view)).filter(([, id]) => (id.accounts?.[account]?.level ?? "off") !== "off")
  .map(([name, id]) => ({ name, level: id.accounts[account].level, profile: !!id.profile, overrides: Object.values(id.accounts[account].actions ?? {}).filter(Boolean).length }));

// Report every connection's progress and errors, plus MCP tool changes awaiting the owner.
export const reviews = (view, account) => Object.keys(accounts(view)[account]?.connections ?? {}).map((key) => {
  const name = connectionName(account, key), status = view.status[name] ?? {}, s = status.details ?? {};
  const count = (sign) => (s.changes ?? []).filter((x) => x.startsWith(sign)).length;
  return { key, name, state: status.state, error: status.error, blocked: s.blocked ?? 0, added: count("+"), changed: count("~"), removed: count("-"), changes: s.changes ?? [] };
});

export function accountStatus(view, account) {
  const states = reviews(view, account);
  if (states.some((s) => s.error)) return { state: "error", blocked: 0 };
  if (states.some((s) => s.state === "connecting")) return { state: "connecting", blocked: 0 };
  const blocked = states.reduce((n, s) => n + s.blocked, 0);
  return { state: blocked ? "review" : null, blocked };
}

export const liveConnection = (view, account) => {
  const key = Object.entries(accounts(view)[account]?.connections ?? {}).find(([, c]) => c.browser)?.[0];
  return key == null ? null : connectionName(account, key);
};

export const fieldPaths = (f) => f.paths ?? [f.path];
const paths = fieldPaths;
const fieldsOf = (c) => c?.fields ?? [];
// A field with no paths, such as an OAuth client ID, only fills the account's templates when it is created.
const plain = (c) => fieldsOf(c).filter((f) => !f.secret && paths(f).length);
const fieldValue = (acc, f) => atPath(acc, f.path ?? paths(f)[0]) ?? (f.list ? [] : f.json ? {} : "");
export const setupFields = (view, preset) => fieldsOf(view.presets[preset]).filter((f) => !f.edit_only);
export const plainFields = (view, account) => plain(presetOf(view, account)).map((f) => ({ ...f, value: fieldValue(accounts(view)[account], f) }));
export const fieldText = (f, value) => f.json ? (value === undefined ? "" : JSON.stringify(value, null, 2)) : f.list ? (value ?? []).join(", ") : value ?? "";
export function readField(f, raw) {
  const v = f.secret ? raw : raw.trim();
  if (f.json) return v ? JSON.parse(v) : {};
  return f.list ? v.split(/[\s,]+/).filter(Boolean) : v;
}

// A grant template fills from the account's plain settings; one that needs a setup-only value, such as an OAuth client, cannot.
export function grantTemplate(view, account, f) {
  const values = Object.fromEntries(plainFields(view, account).map((p) => [p.key, p.value]));
  const grant = f?.oauth && filled(f.oauth, { ...values, monitor_host_id: view.host_id });
  return grant && !/\{\w+\}/.test(JSON.stringify(grant)) ? grant : undefined;
}

// Each stored credential with its status. A stored grant keeps its client and endpoints for sign-in;
// only an unset or static value starts from the preset's template.
export function credentialFields(view, account) {
  return (view.fields?.[account] ?? []).map((meta) => {
    const f = fieldsOf(presetOf(view, account)).find((f) => paths(f).some((path) => JSON.stringify(path) === JSON.stringify(meta.path)));
    const field = { ...f, ...meta, key: meta.path.map(encodeURIComponent).join("/"), label: `${meta.path[1] ? meta.path[1] + ": " : ""}${f?.label ?? meta.path.at(-1)}`, secret: true, multiline: f ? !!f.multiline : true };
    const grant = meta.kind.startsWith("oauth") ? undefined : grantTemplate(view, account, field);
    return { ...field, status: CREDENTIAL_STATUS[meta.kind] ?? "Configured", signIn: meta.kind.startsWith("oauth") || !!grant, credential: grant && { oauth: grant } };
  }).sort((a, b) => a.key.localeCompare(b.key));
}

export const signInLabel = (view, preset) => preset === "codex" ? "Continue with ChatGPT"
  : preset === "mcp" || !view.presets[preset] ? "Sign in" : "Sign in with " + view.presets[preset].title;

export function catalog(view) {
  const custom = ["custom_api", "mcp"].filter((name) => view.presets[name]);
  const groups = new Map(Object.keys(CATALOG_GROUPS).map((g) => [g, []]));
  for (const [name, preset] of Object.entries(view.presets).sort(([, a], [, b]) => a.title.localeCompare(b.title))) {
    const group = preset.group ?? "api";
    if (!groups.has(group)) groups.set(group, []);
    groups.get(group).push({ name, title: preset.title, accounts: Object.values(accounts(view)).filter((acc) => acc.preset === name).length });
  }
  for (const entries of groups.values()) entries.sort((a, b) => Number(custom.includes(b.name)) - Number(custom.includes(a.name)));
  return [...groups].filter(([, entries]) => entries.length).map(([group, presets]) => ({ group, title: CATALOG_GROUPS[group] ?? group, presets }));
}

// apiSettings describes a custom API account's slot as form settings; without an account, the defaults for a new one.
export function apiSettings(view, account) {
  const slot = account === undefined ? {} : accounts(view)[account]?.connections?.[""]?.http?.slots?.[0] ?? {};
  const auth = slot.query ? "query" : slot.header && !(slot.header.toLowerCase() === "authorization" && slot.prefix === "Bearer ") ? "header" : "bearer";
  return { url: slot.origin ? slot.origin + (slot.path === "/" ? "" : slot.path ?? "") : "", auth,
    header: auth === "header" ? slot.header : "X-API-Key", prefix: auth === "header" ? slot.prefix ?? "" : "", query: slot.query ?? "api_key" };
}

export function apiSlot({ url: raw = "", auth, header = "", prefix = "", query = "" }, value = "token") {
  let url;
  try { url = new URL(raw.trim()); } catch { throw new Error("Enter the API's HTTPS URL, such as https://api.example.com."); }
  if (url.protocol !== "https:" || url.port === "80" || url.username || url.password || url.search || url.hash) {
    throw new Error("Use an HTTPS URL without credentials, query parameters, or a fragment.");
  }
  const slot = { value, origin: url.origin, path: url.pathname.replace(/\/+$/, "") || "/" };
  switch (auth) {
    case "bearer": return { ...slot, header: "Authorization", prefix: "Bearer " };
    case "header": {
      header = header.trim();
      if (!/^[!#$%&'*+.^_`|~0-9a-z-]+$/i.test(header)) throw new Error("Enter a valid header name, such as X-API-Key.");
      if (/[\r\n]/.test(prefix)) throw new Error("The header prefix must be on one line.");
      return { ...slot, header, ...(prefix ? { prefix } : {}) };
    }
    case "query": {
      query = query.trim();
      if (!query || /[\s&=#?]/.test(query)) throw new Error("Enter a query parameter name, such as api_key.");
      return { ...slot, query };
    }
    default: throw new Error("Choose an authentication method.");
  }
}

// The agent sends this placeholder; Monitor substitutes the real key at the slot's address.
export function apiSetup(view, account, key = "", index = 0) {
  const [kind, config] = Object.entries(accounts(view)[account]?.connections?.[key] ?? {})[0] ?? [];
  const slot = config?.slots?.[index];
  if (!slot) return null;
  const path = ["connections", key, kind, "secrets", slot.value];
  const placeholder = view.fields?.[account]?.find(f => same(f.path, path))?.placeholder;
  if (!placeholder) return null;
  const value = (slot.prefix ?? "") + placeholder;
  const placement = slot.header ? `Header: ${slot.header}: ${value}`
    : slot.query ? `Query parameter: ${slot.query}=${value}`
    : slot.basic ? `HTTP Basic ${slot.basic === "user" ? "username" : "password"}: ${value}`
    : slot.segment ? `Path segment ${slot.segment}: ${value}`
    : slot.form ? `${slot.form === "otp" ? "One-time code" : slot.form === "password" ? "Password" : "Username"} field: ${value}`
    : slot.sigv4 ? `AWS SigV4 access key: ${value}` : "";
  return { connection: connectionName(account, key), credential: slot.value, placeholder,
    address: slot.origin + (slot.path === "/" ? "" : slot.path ?? ""), header: slot.header, query: slot.query, value, placement };
}

export function codexSetup(view, account) {
  if (accounts(view)[account]?.preset !== "codex") return null;
  const setup = apiSetup(view, account);
  if (!setup) return null;
  return `model = "gpt-6.1-sol"
model_provider = "monitor_chatgpt"

[model_providers.monitor_chatgpt]
name = "ChatGPT through Monitor"
base_url = "https://api.openai.com/v1"
experimental_bearer_token = ${JSON.stringify(setup.placeholder)}
wire_api = "responses"
requires_openai_auth = false
supports_websockets = false`;
}

// Only valid, unmatched HTTP input can become a new operation, including policy refusals.
const unmatchedHTTP = (r) => r?.facts?.details?.http && !r.invalid && r.facts.operation == null;
export const draftable = (view, r) => unmatchedHTTP(r) && accounts(view)[r.facts.account] && presetOf(view, r.facts.account).operations
  ? accounts(view)[r.facts.account].preset : null;

// The draft matches only this exact path; the owner turns segments into {parameters} and sets its effects and scope.
export function draftOperation(e) {
  const h = e.http, read = ["GET", "HEAD"].includes(h.method), params = Object.keys(h.query ?? {});
  return { id: `${h.method} ${h.path}`, action: read ? "read" : "write", effects: [read ? "read" : "write"], method: h.method, origin: h.origin, path: h.path,
    ...(params.length && { params }), ...(h.body_kind !== "none" && { body: ["json", "form"].includes(h.body_kind) ? h.body_kind : "any" }),
    ...(e.graphql?.fields?.length === 1 && { body: "graphql", graphql: { operation: e.graphql.kind, field: e.graphql.fields[0].name } }), scope: {} };
}

export function withDraft(file, r) {
  file = structuredClone(file);
  if (unmatchedHTTP(r)) {
    const { id, ...operation } = draftOperation(r.facts.details);
    file.http = { ...file.http, operations: { ...(file.http?.operations ?? {}), [id]: operation } };
  }
  return file;
}

export const newPreset = (name) => ({ title: name, ...structuredClone(NEW_PRESET) });

// Preset files keep one field, action and operation per line, as the shipped files do.
const EXPANDED = ["", "catalog", "catalog.fields", "catalog.actions", "http", "http.operations"];
const compact = (v) => Array.isArray(v) ? `[${v.map(compact).join(", ")}]`
  : v && typeof v === "object" ? `{${Object.entries(v).map(([k, x]) => `${JSON.stringify(k)}: ${compact(x)}`).join(", ")}}` : JSON.stringify(v);
export function presetText(v, path = "", indent = "") {
  if (!EXPANDED.includes(path) || v === null || typeof v !== "object") return compact(v);
  const [open, close, items] = Array.isArray(v) ? ["[", "]", v.map((x) => presetText(x, path + ".*", indent + "  "))]
    : ["{", "}", Object.entries(v).map(([k, x]) => `${JSON.stringify(k)}: ${presetText(x, path ? `${path}.${k}` : k, indent + "  ")}`)];
  return items.length ? `${open}\n${indent}  ${items.join(`,\n${indent}  `)}\n${indent}${close}` : open + close;
}

// Each edit returns the source changes for POST /policy/edits.
export const edits = {
  pairAgent: (name, key) => sourceChanges({ identities: { [name.trim()]: { key: key.trim(), accounts: {} } } }),
  removeAgent: (name) => [{ path: ["identities", name], delete: true }],
  replaceKey: (name, key) => [{ path: ["identities", name, "key"], value: key.trim() }],
  setRoutes: (name, routes) => [{ path: ["identities", name, "routes"], value: routes }],
  // An action set to null inherits again.
  setAccess: (name, account, access) => sourceChanges({ identities: { [name]: { accounts: { [account]: access } } } }),
  setEffect: ({ agent, account } = {}, effect, mode) => [{
    path: [...(agent ? ["identities", agent, ...(account ? ["accounts", account] : [])] : account ? ["accounts", account] : []), "effects", effect],
    ...(mode ? { value: mode } : { delete: true }),
  }],
  copySettings: (view, from, name) => ["accounts", "rules", "effects"].map((key) => ({ path: ["identities", name, key], value: structuredClone(identities(view)[from]?.[key] ?? {}) })),
  removeRule: (name, id) => [{ path: ["identities", name, "rules", id], delete: true }],
  setLattice: (lattice, on) => [{ path: ["lattices", lattice], value: on }],
  setNetworks: (text) => [{ path: ["allow_networks"], value: text.split(/\s+/).filter(Boolean) }],
  setPaidInference: (allow) => [{ path: ["allow_paid_inference"], value: allow }],
  applyPolicyPreset(view, preset) {
    if (!Object.hasOwn(POLICY_PRESETS, preset)) throw new Error("Choose a policy preset.");
    const previous = view.config.data?.onboarding?.account;
    let policy = view.config.data?.onboarding?.policy;
    if (!policy) {
      policy = "network-default";
      for (let i = 2; Object.hasOwn(view.config.policies ?? {}, policy); i++) policy = `network-default-${i}`;
    }
    let account = previous && accounts(view)[previous]?.preset === "tcp" ? previous : null;
    if (!account) {
      const connections = new Set(Object.entries(accounts(view)).flatMap(([name, acc]) => Object.keys(acc.connections ?? {}).map(key => connectionName(name, key))));
      account = "network";
      for (let i = 2; Object.hasOwn(accounts(view), account) || connections.has(account); i++) account = `network-${i}`;
    }
    const changes = sourceChanges({
      data: { onboarding: { completed: true, preset, policy, account } },
      lattices: { confidentiality: preset !== "open", integrity: false },
      allow_networks: preset === "open" ? ["0.0.0.0/0", "::/0"] : [],
      policies: { [policy]: preset === "open" ? null : preset === "offline"
        ? 'package sentinel\n\ndeny contains "Network access is disabled."\n'
        : 'package sentinel\n\ndeny contains "This request has no recognized policy operation." if input.facts.operation == null\n' },
    });
    changes.push(...sourceChanges({ accounts: { [account]: { preset: "tcp", contents: "anyone", strangers: true, sends: "anyone",
      connections: { "": { tcp: { hosts: ["*"] } } } } } }));
    const access = { level: preset === "open" ? "allow" : "off" };
    changes.push(preset === "offline" ? { path: ["default_access"], value: { [account]: access } }
      : { path: ["default_access", account], value: access });
    for (const [name, id] of Object.entries(identities(view))) {
      changes.push({ path: ["identities", name, "profile"], value: false });
      // Reapplying the network preset resets this connection for existing
      // agents too; new agents inherit the same default automatically.
      changes.push({ path: ["identities", name, "accounts", account], delete: true });
      if (preset === "offline") changes.push(...sourceChanges({ identities: { [name]: { routes: false,
        accounts: Object.fromEntries(Object.keys(id.accounts ?? {}).filter(a => a !== account).map(a => [a, { level: "off" }])) } } }));
    }
    return changes;
  },
  setAccountPolicy: (account, source) => sourceChanges({ policies: { [account]: source.trim() || null } }),
  approveTools: (view, account, key) => sourceChanges({ accounts: { [account]: { connections: { [key]: { mcp: { pin: view.status[connectionName(account, key)].details.pin } } } } } }),
  // Identities may not name a missing account, so removing one also clears it from every agent.
  removeAccount: (view, account) => sourceChanges({
    accounts: { [account]: null },
    policies: { [account]: null },
    default_access: { [account]: null },
    ...(view.config.data?.onboarding?.account === account && { data: { onboarding: { account: null } } }),
    identities: Object.fromEntries(Object.keys(identities(view)).map((n) => [n, { accounts: { [account]: null } }])),
  }),
  // values holds every setup field read with readField; oauth names the fields that sign in instead of taking a token.
  addAccount(view, preset, { name, values, answers, oauth = [] }) {
    const c = view.presets[preset];
    name = name.trim();
    if (!name) throw new Error("Name this account.");
    if (Object.hasOwn(accounts(view), name)) throw new Error("An account with that name already exists. Choose another name.");
    const fields = setupFields(view, preset);
    // Only the non-secret values fill a preset's connections; secrets go to their fields' paths.
    const plainValues = Object.fromEntries(fields.filter((f) => !f.secret).map((f) => [f.key, values[f.key]]));
    const connections = c.connections ? filled(c.connections, plainValues) : values.connections;
    const acc = { preset, ...answers, ...JSON.stringify(connections) !== JSON.stringify(c.connections) && { connections } };
    for (const f of fields) {
      const value = f.oauth && oauth.includes(f.key) ? { oauth: filled(f.oauth, { ...values, monitor_host_id: view.host_id }) }
        : f.secret && values[f.key] === "" ? null : values[f.key];
      for (const path of paths(f)) putPath(acc, path, value);
    }
    return sourceChanges({ accounts: { [name]: acc } });
  },
  addCustomApi(view, { name, api, token, agent, level, answers }) {
    name = name.trim();
    if (!/^[a-zA-Z0-9][a-zA-Z0-9-]*$/.test(name)) throw new Error("Name this account using letters, numbers, and hyphens.");
    if (Object.hasOwn(accounts(view), name)) throw new Error("An account with that name already exists. Choose another name.");
    if (!token.trim()) throw new Error("Enter the API key or token.");
    const body = { accounts: { [name]: { preset: "custom_api", ...answers, connections: { "": { http: { slots: [apiSlot(api)], secrets: { token } } } } } } };
    if (agent) body.identities = { [agent]: { accounts: { [name]: { level } } } };
    return sourceChanges(body);
  },
  // credentials maps a credential field key to keep, replace with a value, or clear; unchanged settings send nothing.
  saveAccount(view, account, { answers, api, values = {}, credentials = {} }) {
    const acc = accounts(view)[account], updated = structuredClone(acc), changed = new Set(), removals = [];
    const set = (path, value) => {
      if (same(atPath(acc, path), value)) return;
      putPath(updated, path, value);
      // Several controls can edit the same array; submit its final value once.
      const n = path.findIndex((_, i) => i > 0 && Array.isArray(atPath(updated, path.slice(0, i))));
      changed.add(JSON.stringify(n < 0 ? path : path.slice(0, n)));
    };
    for (const [key, value] of Object.entries(answers)) set([key], value);
    if (acc.preset === "custom_api") set(["connections", "", "http", "slots"], [apiSlot(api, acc.connections?.[""]?.http?.slots?.[0]?.value)]);
    for (const f of plainFields(view, account)) if (Object.hasOwn(values, f.key)) for (const path of paths(f)) set(path, values[f.key]);
    for (const f of credentialFields(view, account)) {
      const { mode, value } = credentials[f.key] ?? {};
      if (mode === "replace") {
        if (value === "") throw new Error(`Enter a value for ${f.label}, or cancel the replacement.`);
        set(f.path, value);
      }
      if (mode === "clear") removals.push({ path: ["accounts", account, ...f.path], delete: true });
    }
    return [...[...changed].map((key) => {
      const path = JSON.parse(key);
      return { path: ["accounts", account, ...path], value: atPath(updated, path) };
    }), ...removals];
  },
  // Operations missing from an edited preset are disabled rather than left to the shipped definition.
  savePreset(name, text, previous) {
    const value = JSON.parse(text);
    for (const id of Object.keys(previous?.http?.operations ?? {})) {
      if (value.http?.operations && !Object.hasOwn(value.http.operations, id)) value.http.operations[id] = { enabled: false };
    }
    return [{ path: ["presets", name], value }];
  },
  removePreset: (name) => [{ path: ["presets", name], delete: true }],
};

// Setup guides for connecting tools. href maps a route such as ["pair"] or ["agent-settings", name] to a link, which
// also carries the route as data-route; code blocks carry data-copy with the id of the text to copy.
export const INTEGRATION_PAGES = { start: "Start here", wrapped: "Wrap commands", shell: "Monitor shell", mcp: "MCP connections" };
export function integrationGuide(view, page, href) {
  const link = (route, text) => `<a href="${esc(href(route))}" data-route="${esc(route.join("/"))}">${text}</a>`;
  const code = (id, title, text) => `<div class="integration-code"><div class="row"><span>${esc(title)}</span><button type="button" data-copy="${esc(id)}" aria-label="Copy ${esc(title)}">Copy</button></div><pre id="${esc(id)}">${esc(text)}</pre></div>`;
  const setupLinks = Object.keys(identities(view)).map((name) => `<li>${link(["agent-settings", name], `${esc(name)} setup`)}</li>`).join("");
  return {
    start: `<h1>Use Monitor from your tools</h1><p>Keep API keys and service sign-ins in Monitor, such as a GitHub token or an Anthropic API key. Connect a command, a terminal session, or an agent through an identity with the access you choose.</p>
      <h2>Set up an identity first</h2><ol>
        <li>Choose a service in <b>Add account</b>, then paste its API key or sign in when prompted.</li>
        <li>Create a dedicated SSH key on the computer running your tools. ${link(["pair"], "Pair its public key")} as an agent, even when you will use it from your own terminal.</li>
        <li>Open that agent and grant access to the accounts it needs. Use separate identities for your laptop and automated workers when they need different permissions.</li>
        <li>Configure an SSH alias named <code>monitor</code> for the Monitor server, using that private key and the host key shown in the agent's settings. The SSH address and port come from your deployment, not the web app URL.</li>
      </ol><p>The private SSH key stays on your computer. Tool integrations use that identity; they do not need the web app's owner key.</p>
      <h2>Your agent setup</h2>${setupLinks ? `<ul>${setupLinks}</ul>` : `<p>No agents are paired yet. ${link(["pair"], "Pair an agent")} to get started.</p>`}
      <p>Agent settings include the host key and CA certificate. Open an account's <b>Connect your agent</b> section to copy its substitution values and see where to send them. If the existing Monitor client is installed, <code>monitor connections --json</code> checks which connections its SSH identity can reach.</p>
      <h2>Install the client</h2><p>Use Python 3.11 or newer and OpenSSH. From the Monitor repository:</p>
      ${code("integration-install", "Install on your laptop", 'mkdir -p "$HOME/.local/bin"\ninstall -m 755 client/monitor "$HOME/.local/bin/monitor"\nexport PATH="$HOME/.local/bin:$PATH"\nmonitor connections --json')}
      <p>The Go binary embeds the same client. The commands below use your paired SSH alias and verify its host key. See <code>docs/laptop-client.md</code> in the repository for complete SSH setup and local profile examples.</p>`,
    wrapped: `<h1>Wrap an existing command</h1><p><span class="badge">Available</span> Run a CLI or script locally, with its service requests routed through Monitor. Keep the command's arguments, working directory, output, and exit status.</p>
      ${code("integration-run", "Run a command", "monitor run -- gh api user\nmonitor run -- ./release.sh")}
      <h2>How it works</h2><ol><li>Use your paired SSH alias, or select a configured local profile.</li><li>The client opens a tunnel and prepares proxy settings, certificate trust, and the selected accounts' credential placeholders.</li><li>It starts the command and passes those settings to its children. Monitor checks requests and substitutes the real credentials before sending them upstream.</li><li>When the command exits, the client closes its tunnel and temporary files.</li></ol>
      <h2>When to use it</h2><p>Start here for an existing GitHub workflow, a one-off command, or a script. With a configured profile, use <code>monitor --profile work run -- gh pr list</code>.</p>
      <h2>Compatibility</h2><p>Programs must support the configured proxy and certificate settings. This mode does not force every network request through Monitor. Git HTTPS receives proxy, trust, and placeholder credential settings. SSH remotes need a separate Monitor SSH connection. Account policy and preset coverage still apply to each request.</p>
      <p>The wrapper stops if setup fails and ends the child session if its tunnel is lost. It never retries writes automatically. Your parent terminal keeps its original environment.</p>
      <h2>Use your accounts</h2><p>All connections are available by default. Shared credential names get separate variables per connection, such as <code>MONITOR_CREDENTIAL_ANTHROPIC_TOKEN</code>. For a tool that needs one account default, use <code>monitor run --connection work -- gh api user</code>. Connection names come from <code>monitor connections</code>.</p>`,
    shell: `<h1>Start a Monitor shell</h1><p><span class="badge">Available</span> Open a local terminal session with the same connection setup as a wrapped command.</p>
      ${code("integration-shell", "Open a shell", "monitor shell\ngh api user\nexit")}
      <h2>How it works</h2><p>The shell uses the wrapper's profiles, tunnel, credential placeholders, and certificate handling. Its prompt shows the active SSH alias or profile. Commands run in your local working directory.</p>
      <p>Type <code>exit</code> to return to the original terminal environment. User startup files are skipped to preserve routing and account selection. Each nested Monitor session owns its own tunnel.</p>
      <h2>When to use it</h2><p>Use a shell for a sequence of commands that share an identity. Choose <code>monitor run</code> for automation that needs a single command and a predictable exit status.</p>
      <h2>What it covers</h2><p>This session configures cooperating tools and their children. Other terminals and desktop apps have their own environments. A managed workspace with network restrictions is a separate option when every connection must pass through Monitor.</p>
      <h2>Select a shell</h2><p>Use <code>monitor shell --shell /bin/bash</code> or <code>monitor shell --shell /bin/zsh</code>. The shell includes all connections by default. Use the connection-specific credential variables when names overlap. The Linux integration suite exercises both shells; macOS validation remains open.</p>`,
    mcp: `<h1>Connect an MCP client</h1><p><span class="badge">Available</span> Each ready MCP connection gets its own Streamable HTTP server on a local port. Your SSH identity determines which accounts it can reach; tool calls still follow Monitor policy.</p>
      <h2>1. Prepare the connection</h2><p>Complete the ${link(["integrations", "start"], "identity setup")}. Add an account with an MCP connection, grant the paired identity access, and review tools awaiting approval on the account page. An HTTP API connection alone does not provide MCP tools.</p>
      <p>The commands below assume an SSH alias named <code>monitor</code> with the correct identity and a verified host key. You need an MCP client that supports Streamable HTTP.</p>
      <h2>2. Keep the tunnel running</h2>
      ${code("integration-mcp-serve", "Serve MCP connections", "monitor mcp serve --listen 127.0.0.1:8400")}
      <p>The client checks MCP initialization and tool discovery before reporting readiness. Put <code>--ssh-config /path/to/ssh_config</code> before <code>mcp</code> to use a separate configuration. Connections use consecutive ports starting at the selected port. Use port 0 to choose a free port for each connection.</p>
      <h2>3. Add each server in your MCP client</h2><p>Use the connection names and URLs printed by the command. For the first connection:</p><ul><li>Name: the Monitor connection name</li><li>Transport: <b>Streamable HTTP</b></li><li>URL:</li></ul>
      ${code("integration-endpoint", "MCP server URL", "http://127.0.0.1:8400/")}
      <p>No provider token or owner key goes in the client configuration. The SSH tunnel authenticates to Monitor. Programs on this computer can use the local endpoint as that identity; close the tunnel with Ctrl-C when finished.</p>
      <h2>4. Check the connection</h2><p>Refresh the client's tool list. Monitor preserves upstream tool names. Your MCP client separates servers' tools. Update allowlists that use the old <code>connection__tool</code> names. Call a read tool and check ${link(["activity"], "Activity")} for the expected agent and account. Pending requests appear first. Open one to allow or deny it.</p>
      <h2>If it does not connect</h2><ul><li><b>SSH fails:</b> check the server address, paired public key, private key, and host key.</li><li><b>No tools:</b> check account access, the MCP connection's status, and tool review. An identity with no reachable MCP connections has no MCP servers to add.</li><li><b>Client cannot reach the URL:</b> keep the tunnel running on the same computer as the client. A client in a container has its own localhost.</li><li><b>A tool fails or times out:</b> inspect Activity and the provider state before retrying a change.</li></ul>
      <p>Clients that only support stdio still need a separate adapter. <code>monitor mcp stdio</code> is not implemented.</p>`,
  }[page] ?? "";
}

// CAM serves this UI through the CLI's attested SSH tunnel. Its session token
// authorizes browser requests; private owner and storage keys never enter JS.
export function localOwnerClient({ token, generation, fetch = (...args) => globalThis.fetch(...args) }) {
  const json = ownerJSON(fetch);
  return ownerApi(async (method, path, body, signal) => {
    if (!token) throw new OwnerError("Open this panel with tinfoil monitor open NAME.", 401);
    if (path.split("?")[0] === "/unlock") throw new OwnerError("Run tinfoil monitor open NAME again to unlock over attested SSH.", 423);
    const asset = path.startsWith("/app/");
    return json(asset ? path : "/api" + path, { method, signal, cache: "no-store", credentials: "omit", redirect: "error",
      headers: { ...(!asset && { "X-Tinfoil-Session": token }), ...(body !== undefined && { "Content-Type": "application/json" }) },
      body: body === undefined ? undefined : JSON.stringify(body) });
  }, generation);
}
