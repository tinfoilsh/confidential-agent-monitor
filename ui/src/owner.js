// The owner API client and the request, permission and account semantics shared by
// Monitor's own app and embedding dashboards. The server remains the authority: these
// functions shape edits and describe its answers.

export const LEVELS = {
  off: "No access",
  read: "Read only",
  ask: "Ask",
  allow: "Allow",
};
export const MODES = { allow: "Allow", ask: "Ask", off: "Deny" };
export const AUDIENCES = { me: "Only me", team: "My team", anyone: "Anyone" };
export const TRUSTS = { trusted: "Trusted", untrusted: "Untrusted" };
export const CATALOG_GROUPS = { api: "API", mcp: "MCP", protocol: "Protocol" };
export const COMMON_PRESETS = [
  "tinfoil",
  "anthropic",
  "openai",
  "github",
  "gmail",
  "email",
  "web",
  "ssh",
  "tcp",
];
export const CREDENTIAL_STATUS = {
  "oauth-required": "Sign-in required",
  unset: "Not configured",
};
const DEFAULT_REVIEWER = {
  model: "gpt-oss-120b",
  instructions:
    "Approve routine, reversible actions. Ask me before payments, deletion, publishing, sharing private data, or changes to access. Deny requests that clearly violate these instructions. Ask me when context is missing.",
};
export const POLICY_PRESETS = {
  open: {
    title: "Open",
    description: "Allow all traffic to go through without approval.",
  },
  known_only: {
    title: "Known Only",
    description: "Only allow requests to connectors you configured.",
    recommended: true,
  },
  offline: {
    title: "Offline",
    description:
      "Block all requests. Nothing in a sandbox can talk to anything.",
  },
};
// A new preset starts as one bearer-token API; the owner sets its origin, slots and operations.
export const NEW_PRESET = {
  catalog: {
    group: "api",
    fields: [
      {
        key: "token",
        label: "API token",
        secret: true,
        path: ["connections", "", "http", "secrets", "token"],
      },
    ],
    connections: {
      "": {
        http: {
          slots: [
            {
              value: "token",
              origin: "https://api.example.com",
              path: "/",
              header: "Authorization",
              prefix: "Bearer ",
            },
          ],
        },
      },
    },
    defaults: { contents: "me", strangers: true, sends: "me" },
  },
  http: { operations: {} },
};
const LOOPBACK = ["localhost", "127.0.0.1", "[::1]"];

// Human input preserves UTF-8 bytes, including whitespace. Old canonical
// base64 32-byte keys keep their original meaning; base64 is only the wire format.
export function encodeOwnerKey(input) {
  if (typeof input === "string" && input.trim().startsWith("{"))
    throw new Error(
      "Use tinfoil monitor open. Do not load private credential files into a remote web page.",
    );
  if (typeof input !== "string")
    throw new Error("Enter your owner key or passphrase.");
  const legacy = input.trim();
  try {
    const decoded = atob(legacy);
    if (decoded.length === 32 && btoa(decoded) === legacy) return legacy;
  } catch {}
  const bytes = new TextEncoder().encode(input);
  if (bytes.length < 16 || bytes.length > 4096)
    throw new Error(
      "Use an owner key or passphrase between 16 and 4096 UTF-8 bytes.",
    );
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
    const read = options.method === "GET",
      known = read && cache.get(url);
    if (!read) cache.clear();
    const res = await fetch(url, {
      ...options,
      headers: {
        ...options.headers,
        ...(known && { "If-None-Match": known.tag }),
      },
    });
    if (res.status === 304 && known) {
      cache.delete(url);
      cache.set(url, known);
      return known.value;
    }
    const text = await res.text();
    if (!res.ok)
      throw new OwnerError(
        text.trim() || `Request failed (${res.status})`,
        res.status,
      );
    const value = text ? JSON.parse(text) : null,
      tag = res.headers.get("ETag");
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
export function ownerClient({
  endpoint,
  key,
  generation,
  fetch = (...args) => globalThis.fetch(...args),
}) {
  if (typeof key === "string" && key.trim().startsWith("{"))
    throw new Error(
      "Signing credentials require tinfoil monitor open and its attested connection.",
    );
  let base = "";
  if (endpoint !== undefined) {
    let url;
    try {
      url = new URL(endpoint);
    } catch {
      throw new Error("Invalid monitor endpoint.");
    }
    if (
      url.protocol !== "https:" &&
      !(url.protocol === "http:" && LOOPBACK.includes(url.hostname))
    )
      throw new Error("The monitor endpoint must use HTTPS.");
    if (url.username || url.password || url.search || url.hash)
      throw new Error("Invalid monitor endpoint.");
    base = url.href.replace(/\/$/, "");
  }
  const json = ownerJSON(fetch);
  return ownerApi(
    (method, path, body, signal) => {
      return json(base + path, {
        method,
        signal,
        cache: "no-store",
        credentials: "omit",
        redirect: "error",
        headers: {
          Authorization: "Bearer " + key,
          ...(body !== undefined && { "Content-Type": "application/json" }),
        },
        body: body === undefined ? undefined : JSON.stringify(body),
      });
    },
    generation,
    base,
  );
}

// With a known generation, an older view is a rollback, and a locked monitor unlocks at that minimum.
export function ownerApi(request, generation, base = "") {
  let minimum = generation;
  let catalog;
  const checked = (view) => {
    if (minimum !== undefined && view) {
      if (view.generation < minimum)
        throw new OwnerError(
          "The monitor state is older than the last state you saw. Restore the latest monitor state before continuing.",
          409,
        );
      minimum = view.generation;
    }
    return view;
  };
  const get = (path, signal) => request("GET", path, undefined, signal);
  const post = (path, body, signal) => request("POST", path, body, signal);
  const snapshot = async (method, path, body, signal) => {
    const known = catalog;
    const view = await request(
      method,
      known ? `${path}?catalog=${encodeURIComponent(known.id)}` : path,
      body,
      signal,
    );
    if (view?.catalog_id) {
      if (view.presets)
        catalog = { id: view.catalog_id, presets: view.presets };
      else if (known?.id === view.catalog_id) view.presets = known.presets;
      else
        throw new OwnerError(
          "Monitor returned an unknown preset catalog. Reload the page.",
          409,
        );
    }
    return view?.pending === true ? view : checked(view);
  };
  const unlock = (at = minimum ?? 0, signal) =>
    snapshot("POST", "/unlock", { generation: at }, signal);
  return {
    async read(signal, { summary = false } = {}) {
      const path = summary ? "/requests?summary" : "/requests";
      const [view, requests] = await Promise.all([
        snapshot("GET", "/", undefined, signal),
        get(path, signal),
      ]).catch(async (err) => {
        if (err.status !== 423 || minimum === undefined) throw err;
        return [await unlock(minimum, signal), await get(path, signal)];
      });
      return { view: checked(view), requests: requests ?? [] };
    },
    request: (id, signal) => get(`/requests/${encodeURIComponent(id)}`, signal),
    archive: (before, signal) =>
      get(`/audit?before=${encodeURIComponent(before)}`, signal),
    archived: (segment, id, signal) =>
      get(
        `/audit/${encodeURIComponent(segment)}/${encodeURIComponent(id)}`,
        signal,
      ),
    unlock,
    onboard: (
      view,
      preset,
      signal,
      { allowPaidInference = true, tinfoilApiKey } = {},
    ) =>
      onboarded(view)
        ? Promise.resolve(view)
        : snapshot(
            "POST",
            "/policy/edits",
            {
              changes: [
                ...onboardingChanges(view, preset, tinfoilApiKey),
                ...edits.setPaidInference(allowPaidInference),
              ],
              generation: view.generation,
            },
            signal,
          ),
    edit: (changes, signal) =>
      snapshot("POST", "/policy/edits", { changes }, signal),
    decide: (id, decision, signal) =>
      post(`/requests/${encodeURIComponent(id)}`, { decision }, signal),
    label: (name, label, signal) =>
      snapshot("POST", `/labels/${encodeURIComponent(name)}`, label, signal),
    preset: (name, signal) =>
      get(`/presets/${encodeURIComponent(name)}`, signal),
    policy: (effective, signal) =>
      get(effective ? "/policy?effective" : "/policy", signal),
    previewPolicy: (source, signal) =>
      post("/policy/preview", { source }, signal),
    applyPolicy: (source, signal) =>
      snapshot("POST", "/policy", { source }, signal),
    signIn: (account, path, redirect, credential, signal) =>
      post(
        `/accounts/${encodeURIComponent(account)}/sign-in`,
        { path, redirect, credential },
        signal,
      ),
    finishSignIn: (state, result, signal) =>
      snapshot(
        "POST",
        `/sign-in/${encodeURIComponent(state)}`,
        typeof result === "string" ? { code: result } : result,
        signal,
      ),
    browser: (name, body, signal) =>
      request(
        body ? "POST" : "GET",
        `/connections/${encodeURIComponent(name)}/browser`,
        body,
        signal,
      ),
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
  const icon = manifest?.[preset]?.src
    ? manifest[preset]
    : (manifest?.custom ?? { src: "custom.svg" });
  const url = (file) => `${base}/app/icons/${encodeURIComponent(file)}`;
  return { src: url(icon.src), ...(icon.dark && { dark: url(icon.dark) }) };
}

// Controls address source values; named rules and operations stay named.
export function sourceChanges(body, path = []) {
  return Object.entries(body).flatMap(([key, value]) => {
    const at = [...path, key];
    if (value === null) return [{ path: at, delete: true }];
    const atomic =
      key === "scope" ||
      key === "fields" ||
      key === "query" ||
      key === "headers" ||
      (at[0] === "identities" && at[2] === "rules" && at.length === 4) ||
      value?.oauth ||
      value?.$json;
    if (
      !atomic &&
      value &&
      typeof value === "object" &&
      !Array.isArray(value) &&
      Object.keys(value).length
    )
      return sourceChanges(value, at);
    return [{ path: at, value }];
  });
}

export function applyChanges(target, changes) {
  for (const change of changes) {
    let parent = target;
    for (const key of change.path.slice(0, -1)) {
      if (
        !Object.hasOwn(parent, key) ||
        !parent[key] ||
        typeof parent[key] !== "object"
      )
        Object.defineProperty(parent, key, {
          value: {},
          enumerable: true,
          configurable: true,
          writable: true,
        });
      parent = parent[key];
    }
    const key = change.path.at(-1);
    if (change.delete) delete parent[key];
    else
      Object.defineProperty(parent, key, {
        value: structuredClone(change.value),
        enumerable: true,
        configurable: true,
        writable: true,
      });
  }
  return target;
}

// previewChanges shows edits before the server confirms them, including edited presets' catalogs.
export function previewChanges(view, changes, shipped = {}) {
  // Fork only edited paths. Large preset catalogs remain shared with the confirmed view.
  const config = { ...view.config },
    copied = new WeakSet([config]);
  for (const change of changes) {
    let parent = config;
    for (const key of change.path.slice(0, -1)) {
      const child = Object.hasOwn(parent, key) ? parent[key] : undefined;
      if (!child || typeof child !== "object" || !copied.has(child)) {
        const value =
          !child || typeof child !== "object"
            ? {}
            : Array.isArray(child)
              ? [...child]
              : { ...child };
        Object.defineProperty(parent, key, {
          value,
          enumerable: true,
          configurable: true,
          writable: true,
        });
      }
      parent = parent[key];
      copied.add(parent);
    }
    applyChanges(config, [change]);
  }
  view.config = config;
  const presets = new Set(
    changes
      .filter((c) => c.path[0] === "presets" && c.path.length > 1)
      .map((c) => c.path[1]),
  );
  if (presets.size) view.presets = { ...view.presets };
  for (const name of presets) {
    const file = view.config.presets?.[name] ?? shipped[name];
    if (!file) continue; // A shipped preset not fetched yet needs the server's resolved catalog.
    const previous = view.presets[name] ?? view.presets.custom,
      catalog = file.catalog ?? {};
    view.presets[name] = {
      ...previous,
      ...catalog,
      title: typeof file.title === "string" ? file.title : name,
      fields: Array.isArray(catalog.fields)
        ? catalog.fields
        : (previous?.fields ?? []),
      actions: catalog.actions ?? {},
      operations: file.http?.operations ?? {},
    };
  }
  return view;
}

const identities = (view) => view.config.identities ?? {};
// Matches the device names assigned by owner enrollment.
export const isDevice = (name) => /^device-[0-9a-f]{16}$/.test(name);
export const onboarded = (view) =>
  view.config.data?.onboarding?.completed === true;
const accounts = (view) => view.config.accounts ?? {};
export const lattices = (view) => ({
  confidentiality: view.config.lattices?.confidentiality ?? true,
  integrity: view.config.lattices?.integrity ?? false,
});
export const presetOf = (view, account) =>
  view.presets[accounts(view)[account]?.preset] ?? view.presets.custom;
export const connectionName = (account, key) =>
  key ? `${account}-${key}` : account;
export const tinfoilConnection = (view) =>
  Object.entries(accounts(view)).flatMap(([account, config]) =>
    Object.entries(config.connections ?? {})
      .filter(([, kinds]) => kinds.tinfoil)
      .map(([key]) => connectionName(account, key)),
  )[0];
const fill = (text, scope) =>
  text.replace(/\{(\w+)\}/g, (m, k) => scope?.[k] ?? m);
const filled = (c, values) =>
  JSON.parse(JSON.stringify(c), (_, v) =>
    typeof v === "string" ? fill(v, values) : v,
  );
const atPath = (object, path) =>
  path.reduce((value, key) => value?.[key], object);
// JSON values are equal regardless of key order, which differs between server responses and edited copies.
const same = (a, b) =>
  a === b ||
  (!!a &&
    !!b &&
    typeof a === "object" &&
    typeof b === "object" &&
    Array.isArray(a) === Array.isArray(b) &&
    Object.keys(a).length === Object.keys(b).length &&
    Object.keys(a).every((k) => Object.hasOwn(b, k) && same(a[k], b[k])));
function putPath(object, path, value, defaults) {
  for (const [index, key] of path.slice(0, -1).entries()) {
    defaults = defaults?.[key];
    // Arrays replace inherited values as a whole, so retain every preset entry when editing one element.
    if (!Object.hasOwn(object, key))
      Object.defineProperty(object, key, {
        value: Array.isArray(defaults)
          ? structuredClone(defaults)
          : typeof path[index + 1] === "number"
            ? []
            : {},
        enumerable: true,
      });
    object = object[key];
  }
  Object.defineProperty(object, path.at(-1), {
    value,
    enumerable: true,
    configurable: true,
    writable: true,
  });
}
const esc = (s) =>
  String(s ?? "").replace(/[&<>"']/g, (c) => `&#${c.charCodeAt(0)};`);

export function summary(e) {
  if (e?.http) return `${e.http.method} ${e.http.host}${e.http.path}`;
  if (e?.smtp)
    return `To ${e.smtp.to.join(", ")}${e.mail?.subject ? `: ${e.mail.subject}` : ""}`;
  if (e?.imap) return `${e.imap.command} ${e.imap.args}`;
  if (e?.mcp) return e.mcp.tool;
  return "";
}
export const requestTitle = (r) =>
  r.facts?.title ||
  summary(r.facts?.details) ||
  r.facts?.operation?.id ||
  r.facts?.account;
// Requirements worth showing. "ask" is what pending already means, and the
// audience/trust label gates are a data-flow feature nobody set up on
// purpose; what remains is effect overrides and unrecognised operations.
const quietRequirements = new Set(["ask", "audience", "trust"]);
export const reasons = (r) =>
  (r.requirements ?? [])
    .filter((requirement) => !quietRequirements.has(requirement.id))
    .map((requirement) => requirement.message);
// A pending request past its deadline is expired, even before the next poll says so.
export const stateAt = (r, now) =>
  r.state === "pending" && r.expires && Date.parse(r.expires) <= now
    ? "expired"
    : r.state;
export const needsOwner = (r) => r.state === "pending" && !r.reviewer;
export function reviewStatus(r) {
  const last = r.reviews?.at(-1);
  if (r.state === "pending")
    return r.reviewer === "tinfoil"
      ? "Tinfoil is reviewing"
      : last?.decision === "escalate"
        ? "Tinfoil needs your decision"
        : "Needs your approval";
  if (
    (last || r.savingDecision) &&
    (r.state === "approved" || r.state === "denied")
  )
    return `${r.state === "approved" ? "Approved" : "Denied"} by ${!r.savingDecision && last?.by === "tinfoil" ? "Tinfoil" : "you"}`;
  return r.state.charAt(0).toUpperCase() + r.state.slice(1);
}
export const pendingSoonest = (records) =>
  records
    .filter((r) => r.state === "pending")
    .sort((a, b) => new Date(a.expires) - new Date(b.expires));
export function ordered(records, dismissed = []) {
  const hidden = new Set(dismissed);
  const priority = (r) =>
    needsOwner(r)
      ? 0
      : r.state === "pending"
        ? 1
        : r.state === "expired" && !hidden.has(r.id) && !r.segment
          ? 2
          : 3;
  return [...records].sort(
    (a, b) =>
      priority(a) - priority(b) ||
      (a.state === "pending" && b.state === "pending"
        ? new Date(a.expires) - new Date(b.expires)
        : 0),
  );
}
export function timeLeft(r, now = Date.now()) {
  const s = Math.max(0, Math.round((new Date(r.expires) - now) / 1000));
  return `${Math.floor(s / 60)}:${String(s % 60).padStart(2, "0")}`;
}

// A saved approval binds one operation and its grant. The text names fields, not values, which can be whole messages;
// fields left out of the grant are named as broad.
export function grantText(operation, grant, scope) {
  const fields = Object.keys(grant ?? {}),
    broad = Object.keys(scope ?? {}).filter((k) => !fields.includes(k));
  return (
    `Allow ${operation} ${fields.length ? "for the same " + fields.join(", ") : "for any request"}` +
    (fields.length && broad.length ? `, with any ${broad.join(", ")}` : "")
  );
}
export const saveText = (r) =>
  `${grantText(r.facts?.operation?.id, r.grant, r.facts?.parameters)} on future attempts. Retry this request after saving.`;
// Saving a rule never resumes the original call; it also works after a timeout.
export function decisions(r, now) {
  const state = now === undefined ? r.state : stateAt(r, now);
  const save = r.facts?.operation?.action != null && !!r.facts?.operation?.id;
  return r.savingDecision
    ? {}
    : state === "pending"
      ? { once: true, save, deny: true }
      : state === "expired"
        ? { save, dismiss: true }
        : {};
}
const WAIVED = {
  ask: "Ask",
  audience: "Confidentiality guardrail",
  trust: "Integrity guardrail",
};
const EFFECT_REQUIREMENT = "effect.";
export function ruleTitle(view, r) {
  const actions = actionsOf(view, r.account);
  return (
    r.action
      .split(".")
      .map((_, i, parts) => actions[parts.slice(0, i + 1).join(".")]?.title)
      .filter(Boolean)
      .join(" › ") || r.action
  );
}
export const ruleWaives = (r) =>
  (r.requirements ?? []).map(
    ({ id, message }) =>
      WAIVED[id] ??
      (id?.startsWith(EFFECT_REQUIREMENT)
        ? `Ask on ${id.slice(EFFECT_REQUIREMENT.length)}`
        : message),
  );

// Each pinned MCP tool is an action under read or use, by the hint the owner approved with the pin.
export const actionsOf = (view, account) => ({
  ...groupsOf(view, account),
  ...presetOf(view, account).actions,
  ...Object.fromEntries(
    Object.values(accounts(view)[account]?.connections ?? {})
      .flatMap((c) => (c.mcp ?? c["tinfoil-mcp"])?.pin?.tools ?? [])
      .map((t) => [
        `${t.annotations?.readOnlyHint ? "read" : "use"}.${t.name}`,
        { title: t.title || t.name },
      ]),
  ),
});
// Record operations also contribute permission groups to their preset.
const operationsOf = (view, account) =>
  Object.values(presetOf(view, account).operations ?? {});
const groupsOf = (view, account) =>
  Object.fromEntries(
    operationsOf(view, account).map((o) => [o.action, { title: o.action }]),
  );
// effectsOf unions the effects of every operation under an action, so a group shows its strictest obligations.
const effectGroups = new WeakMap();
const effectGroupsOf = (view, account) => {
  const preset = presetOf(view, account),
    actions = preset.actions ?? {};
  let groups = effectGroups.get(preset);
  if (!groups) {
    groups = new Map();
    const add = (action, effects) =>
      action.split(".").forEach((_, i, parts) => {
        const key = parts.slice(0, i + 1).join(".");
        if (!groups.has(key))
          groups.set(key, { effects: new Set(), otherPayments: false });
        const group = groups.get(key);
        for (const effect of effects) group.effects.add(effect);
        if (effects.includes("pay") && !effects.includes("generate"))
          group.otherPayments = true;
      });
    for (const [action, meta] of Object.entries(actions))
      add(action, meta.effects ?? []);
    for (const op of Object.values(preset.operations ?? {}))
      add(op.action, op.effects ?? []);
    effectGroups.set(preset, groups);
  }
  return groups;
};
export const effectsOf = (view, account, k) => {
  const actions = presetOf(view, account).actions ?? {},
    groups = effectGroupsOf(view, account);
  const lineage = k
    .split(".")
    .map((_, i, parts) => parts.slice(0, i + 1).join("."))
    .reverse();
  const inherited = lineage.find((a) => actions[a]?.effects);
  return [
    ...new Set([
      ...(actions[inherited]?.effects ?? []),
      ...(groups.get(k)?.effects ?? []),
    ]),
  ];
};

// Effect settings use the same precedence as config.effectModes. Keeping the
// inherited value lets editors remove an override without copying a default.
export function effectSettings(view, { agent, account } = {}, effects = []) {
  const id = identities(view)[agent] ?? {};
  const pair = id.accounts?.[account] ?? view.config.default_access?.[account];
  const layers = [["Global settings", view.config.effects]];
  if (account)
    layers.push([`Connection ${account}`, accounts(view)[account]?.effects]);
  if (agent) layers.push([`Sandbox ${agent}`, id.effects]);
  if (agent && account)
    layers.push([`Sandbox ${agent} on ${account}`, pair?.effects]);
  return Object.entries(view.vocabulary)
    .sort(([a], [b]) => a.localeCompare(b))
    .map(([effect, metadata]) => {
      let mode = metadata.ask ? "ask" : "allow",
        source = "Monitor defaults";
      if (
        effect === "pay" &&
        view.config.allow_paid_inference &&
        effects.includes("generate") &&
        effects.includes("pay")
      ) {
        mode = "allow";
        source = "Paid AI inference";
      }
      for (const [name, values] of layers.slice(0, -1)) {
        if (values?.[effect]) {
          mode = values[effect];
          source = name;
        }
      }
      const own = layers.at(-1)[1]?.[effect] ?? null;
      return {
        effect,
        own,
        inherited: mode,
        mode: own ?? mode,
        source: own ? layers.at(-1)[0] : source,
      };
    });
}

// Action access and effect settings are independent restrictions; the strictest wins.
export function mode(
  access,
  vocabulary,
  effects,
  k,
  settings = {},
  inherit = false,
) {
  if (!access.level || access.level === "off") return "off";
  const lineage = k
    .split(".")
    .map((_, i, p) => p.slice(0, p.length - i).join("."));
  const has = (name) => effects.some((e) => vocabulary[e]?.[name]);
  const action =
    lineage
      .filter((a) => !inherit || a !== k)
      .map((a) => access.actions?.[a])
      .find(Boolean) ??
    (has("change")
      ? access.level === "read"
        ? "off"
        : access.level
      : "allow");
  const modes = [
    action,
    ...effects.map(
      (e) => settings[e] ?? (vocabulary[e]?.ask ? "ask" : "allow"),
    ),
  ];
  return modes.includes("off")
    ? "off"
    : modes.includes("ask")
      ? "ask"
      : "allow";
}

// actionTree nests dotted actions under titled groups, each with its effects and number of descendant actions.
export function actionTree(view, account) {
  const roots = [],
    nodes = new Map();
  for (const [key, action] of Object.entries(actionsOf(view, account)).sort(
    ([a], [b]) => a.localeCompare(b),
  )) {
    let children = roots;
    key.split(".").forEach((part, i, parts) => {
      const path = parts.slice(0, i + 1).join(".");
      let node = nodes.get(path);
      if (!node) {
        node = {
          key: path,
          title:
            part.charAt(0).toUpperCase() + part.slice(1).replace(/[_-]/g, " "),
          action: false,
          children: [],
        };
        nodes.set(path, node);
        children.push(node);
      }
      if (path === key)
        Object.assign(node, { title: action.title || key, action: true });
      children = node.children;
    });
  }
  const finish = (node) => {
    node.children.forEach(finish);
    return Object.assign(node, {
      effects: effectsOf(view, account, node.key),
      total: node.children.reduce((n, c) => n + Number(c.action) + c.total, 0),
    });
  };
  return roots.map(finish);
}

export const levelsOf = (account) =>
  Object.entries(LEVELS).filter(
    ([l]) => account?.preset !== "custom_api" || l !== "read",
  );

// agentAccess describes an agent's level for every account and, below it, each action's own and inherited mode.
export function agentAccess(view, name, onlyAccount) {
  const id = identities(view)[name] ?? {};
  const entries =
    onlyAccount === undefined
      ? Object.entries(accounts(view))
      : accounts(view)[onlyAccount]
        ? [[onlyAccount, accounts(view)[onlyAccount]]]
        : [];
  return entries.map(([account, acc]) => {
    const access = id.accounts?.[account] ??
      view.config.default_access?.[account] ?? { level: "off" };
    let actions;
    return {
      account,
      preset: acc.preset,
      level: access.level,
      levels: levelsOf(acc),
      overrides: Object.values(access.actions ?? {}).filter(Boolean).length,
      // Summaries and collapsed editors need levels, not an entire permission tree.
      get actions() {
        if (actions) return actions;
        if (access.level === "off") return (actions = []);
        const overrides = new Map(),
          settings = new Map();
        for (const [key, value] of Object.entries(access.actions ?? {})) {
          if (!value) continue;
          const parts = key.split(".");
          for (let i = 1; i < parts.length; i++) {
            const prefix = parts.slice(0, i).join(".");
            overrides.set(prefix, (overrides.get(prefix) ?? 0) + 1);
          }
        }
        const describe = (node) => {
          // Only paid inference changes effect defaults based on the action's effects.
          const inference =
            !effectGroupsOf(view, account).get(node.key)?.otherPayments &&
            node.effects.includes("generate") &&
            node.effects.includes("pay");
          if (!settings.has(inference))
            settings.set(
              inference,
              Object.fromEntries(
                effectSettings(
                  view,
                  { agent: name, account },
                  inference ? ["generate", "pay"] : [],
                ).map(({ effect, mode }) => [effect, mode]),
              ),
            );
          return {
            ...node,
            own: access.actions?.[node.key] ?? null,
            inherited: mode(
              access,
              view.vocabulary,
              node.effects,
              node.key,
              settings.get(inference),
              true,
            ),
            overrides: overrides.get(node.key) ?? 0,
            children: node.children.map(describe),
          };
        };
        return (actions = actionTree(view, account).map(describe));
      },
    };
  });
}

export function browsingHint(view, name) {
  const id = identities(view)[name] ?? {};
  const reaches = (pred) =>
    Object.entries(accounts(view)).some(
      ([a, acc]) => (id.accounts?.[a]?.level ?? "off") !== "off" && pred(acc),
    );
  return (
    lattices(view).confidentiality &&
    reaches((acc) => acc.preset === "web") &&
    reaches((acc) => acc.contents !== "anyone")
  );
}

export function labelStatus(view, l) {
  const on = lattices(view);
  const lines = [
    on.confidentiality &&
      l?.audience &&
      l.audience !== "anyone" &&
      `Has seen private data${l.because?.audience ? ` from ${l.because.audience}` : ""}`,
    on.integrity &&
      l?.trust === "untrusted" &&
      "Has read content from strangers",
  ];
  return lines.filter(Boolean).join(" · ") || "Clean";
}

export const accountUsers = (view, account) =>
  Object.entries(identities(view)).flatMap(([name, id]) => {
    const access =
      id.accounts?.[account] ?? view.config.default_access?.[account];
    return (access?.level ?? "off") === "off"
      ? []
      : [
          {
            name,
            level: access.level,
            overrides: Object.values(access.actions ?? {}).filter(Boolean)
              .length,
          },
        ];
  });

// Report every connection's progress and errors, plus MCP tool changes awaiting the owner.
export const reviews = (view, account) =>
  Object.keys(accounts(view)[account]?.connections ?? {}).map((key) => {
    const name = connectionName(account, key),
      status = view.status[name] ?? {},
      s = status.details ?? {};
    const count = (sign) =>
      (s.changes ?? []).filter((x) => x.startsWith(sign)).length;
    return {
      key,
      name,
      state: status.state,
      error: status.error,
      blocked: s.blocked ?? 0,
      added: count("+"),
      changed: count("~"),
      removed: count("-"),
      changes: s.changes ?? [],
    };
  });

export function accountStatus(view, account) {
  const states = reviews(view, account);
  if (states.some((s) => s.error)) return { state: "error", blocked: 0 };
  if (states.some((s) => s.state === "connecting"))
    return { state: "connecting", blocked: 0 };
  const blocked = states.reduce((n, s) => n + s.blocked, 0);
  return { state: blocked ? "review" : null, blocked };
}

export const liveConnection = (view, account) => {
  const key = Object.entries(accounts(view)[account]?.connections ?? {}).find(
    ([, c]) => c.browser,
  )?.[0];
  return key == null ? null : connectionName(account, key);
};

export const fieldPaths = (f) => f.paths ?? [f.path];
const paths = fieldPaths;
const fieldsOf = (c) => c?.fields ?? [];
// A field with no paths, such as an OAuth client ID, only fills the account's templates when it is created.
const plain = (c) => fieldsOf(c).filter((f) => !f.secret && paths(f).length);
const fieldValue = (acc, f) =>
  atPath(acc, f.path ?? paths(f)[0]) ?? (f.list ? [] : f.json ? {} : "");
export const setupFields = (view, preset) =>
  fieldsOf(view.presets[preset]).filter((f) => !f.edit_only);
export const plainFields = (view, account) =>
  plain(presetOf(view, account)).map((f) => ({
    ...f,
    value: fieldValue(accounts(view)[account], f),
  }));
export const fieldText = (f, value) =>
  f.json
    ? value === undefined
      ? ""
      : JSON.stringify(value, null, 2)
    : f.list
      ? (value ?? []).join(", ")
      : (value ?? "");
export function readField(f, raw) {
  const v = f.secret ? raw : raw.trim();
  if (f.json) return v ? JSON.parse(v) : {};
  return f.list ? v.split(/[\s,]+/).filter(Boolean) : v;
}

// A grant template fills from the account's plain settings; one that needs a setup-only value, such as an OAuth client, cannot.
export function grantTemplate(view, account, f) {
  if (!f?.oauth) return;
  const values = Object.fromEntries(
    plainFields(view, account).map((p) => [p.key, p.value]),
  );
  const grant =
    f?.oauth && filled(f.oauth, { ...values, monitor_host_id: view.host_id });
  return grant && !/\{\w+\}/.test(JSON.stringify(grant)) ? grant : undefined;
}

// One control per preset field, including all of its active credential destinations.
// A stored grant keeps its client and endpoints for sign-in; unset or static values use the template.
export function credentialFields(view, account) {
  const byPath = new Map();
  for (const field of fieldsOf(presetOf(view, account)))
    for (const path of paths(field)) {
      const key = JSON.stringify(path);
      if (!byPath.has(key)) byPath.set(key, field);
    }
  const groups = new Map();
  for (const meta of view.fields?.[account] ?? []) {
    const field = byPath.get(JSON.stringify(meta.path));
    const key = field ?? meta;
    if (!groups.has(key)) groups.set(key, { field, members: [] });
    groups.get(key).members.push(meta);
  }
  return [...groups.values()]
    .map(({ field: f, members }) => {
      const meta =
        members.find((m) => m.kind.startsWith("oauth")) ?? members[0];
      const field = {
        ...f,
        ...meta,
        key: members[0].path.map(encodeURIComponent).join("/"),
        paths: members.map((m) => m.path),
        label:
          f?.label ??
          `${meta.path[1] ? meta.path[1] + ": " : ""}${meta.path.at(-1)}`,
        secret: true,
        multiline: f ? !!f.multiline : true,
      };
      const configured = members.filter((m) => !CREDENTIAL_STATUS[m.kind]);
      const grant = meta.kind.startsWith("oauth")
        ? undefined
        : grantTemplate(view, account, field);
      return {
        ...field,
        status:
          configured.length === members.length
            ? "Configured"
            : configured.length
              ? "Partially configured"
              : (CREDENTIAL_STATUS[meta.kind] ?? "Not configured"),
        signIn: meta.kind.startsWith("oauth") || !!grant,
        credential: grant && { oauth: grant },
      };
    })
    .sort((a, b) => a.key.localeCompare(b.key));
}

export const signInLabel = (view, preset) =>
  view.presets[preset]?.title
    ? "Sign in with " + view.presets[preset].title
    : "Sign in";

export function catalog(view) {
  const custom = ["custom_api", "mcp"].filter((name) => view.presets[name]);
  const counts = new Map();
  for (const acc of Object.values(accounts(view))) {
    const replacement = view.presets[acc.preset]?.replaced_by;
    const preset =
      replacement && view.presets[replacement] ? replacement : acc.preset;
    counts.set(preset, (counts.get(preset) ?? 0) + 1);
  }
  const groups = new Map(Object.keys(CATALOG_GROUPS).map((g) => [g, []]));
  for (const [name, preset] of Object.entries(view.presets).sort(
    ([, a], [, b]) => a.title.localeCompare(b.title),
  )) {
    // Retired definitions still serve stored credentials and permission names.
    if (preset.replaced_by && view.presets[preset.replaced_by]) continue;
    const group = preset.group ?? "api";
    if (!groups.has(group)) groups.set(group, []);
    groups
      .get(group)
      .push({ name, title: preset.title, accounts: counts.get(name) ?? 0 });
  }
  // The ones most people add first lead as "Common"; blank "custom"
  // presets live under Settings → Advanced, not in the browse list.
  const common = [];
  for (const entries of groups.values())
    for (let i = entries.length - 1; i >= 0; i--) {
      if (COMMON_PRESETS.includes(entries[i].name))
        common.push(...entries.splice(i, 1));
      else if (custom.includes(entries[i].name)) entries.splice(i, 1);
    }
  common.sort(
    (a, b) => COMMON_PRESETS.indexOf(a.name) - COMMON_PRESETS.indexOf(b.name),
  );
  return [
    ...(common.length
      ? [{ group: "common", title: "Common", presets: common }]
      : []),
    ...[...groups]
      .filter(([, entries]) => entries.length)
      .map(([group, presets]) => ({
        group,
        title: CATALOG_GROUPS[group] ?? group,
        presets,
      })),
  ];
}

// apiSettings describes a custom API account's slot as form settings; without an account, the defaults for a new one.
export function apiSettings(view, account) {
  const slot =
    account === undefined
      ? {}
      : (accounts(view)[account]?.connections?.[""]?.http?.slots?.[0] ?? {});
  const auth = slot.query
    ? "query"
    : slot.header &&
        !(
          slot.header.toLowerCase() === "authorization" &&
          slot.prefix === "Bearer "
        )
      ? "header"
      : "bearer";
  return {
    url: slot.origin
      ? slot.origin + (slot.path === "/" ? "" : (slot.path ?? ""))
      : "",
    auth,
    header: auth === "header" ? slot.header : "X-API-Key",
    prefix: auth === "header" ? (slot.prefix ?? "") : "",
    query: slot.query ?? "api_key",
  };
}

export function apiSlot(
  { url: raw = "", auth, header = "", prefix = "", query = "" },
  value = "token",
) {
  let url;
  try {
    url = new URL(raw.trim());
  } catch {
    throw new Error(
      "Enter the API's HTTPS URL, such as https://api.example.com.",
    );
  }
  if (
    url.protocol !== "https:" ||
    url.port === "80" ||
    url.username ||
    url.password ||
    url.search ||
    url.hash
  ) {
    throw new Error(
      "Use an HTTPS URL without credentials, query parameters, or a fragment.",
    );
  }
  const slot = {
    value,
    origin: url.origin,
    path: url.pathname.replace(/\/+$/, "") || "/",
  };
  switch (auth) {
    case "bearer":
      return { ...slot, header: "Authorization", prefix: "Bearer " };
    case "header": {
      header = header.trim();
      if (!/^[!#$%&'*+.^_`|~0-9a-z-]+$/i.test(header))
        throw new Error("Enter a valid header name, such as X-API-Key.");
      if (/[\r\n]/.test(prefix))
        throw new Error("The header prefix must be on one line.");
      return { ...slot, header, ...(prefix ? { prefix } : {}) };
    }
    case "query": {
      query = query.trim();
      if (!query || /[\s&=#?]/.test(query))
        throw new Error("Enter a query parameter name, such as api_key.");
      return { ...slot, query };
    }
    default:
      throw new Error("Choose an authentication method.");
  }
}

// The agent sends this placeholder; Monitor substitutes the real key at the slot's address.
export function apiSetup(view, account, key = "", index = 0) {
  const [kind, config] =
    Object.entries(accounts(view)[account]?.connections?.[key] ?? {})[0] ?? [];
  const slot = config?.slots?.[index];
  if (!slot) return null;
  const path = ["connections", key, kind, "secrets", slot.value];
  const placeholder = view.fields?.[account]?.find((f) =>
    same(f.path, path),
  )?.placeholder;
  if (!placeholder) return null;
  const value = (slot.prefix ?? "") + placeholder;
  const placement = slot.header
    ? `Header: ${slot.header}: ${value}`
    : slot.query
      ? `Query parameter: ${slot.query}=${value}`
      : slot.basic
        ? `HTTP Basic ${slot.basic === "user" ? "username" : "password"}: ${value}`
        : slot.segment
          ? `Path segment ${slot.segment}: ${value}`
          : slot.form
            ? `${slot.form === "otp" ? "One-time code" : slot.form === "password" ? "Password" : "Username"} field: ${value}`
            : slot.sigv4
              ? `AWS SigV4 access key: ${value}`
              : "";
  return {
    connection: connectionName(account, key),
    credential: slot.value,
    placeholder,
    address: slot.origin + (slot.path === "/" ? "" : (slot.path ?? "")),
    header: slot.header,
    query: slot.query,
    value,
    placement,
  };
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

export function tinfoilSetup(view, account) {
  return Object.entries(accounts(view)[account]?.connections ?? {}).flatMap(
    ([key, config]) => {
      const mcp = !!config["tinfoil-mcp"];
      if (!mcp && !config.tinfoil) return [];
      const connection = connectionName(account, key);
      return [
        {
          connection,
          mcp,
          url: `https://${connection}.monitor/${mcp ? "mcp" : "v1"}`,
        },
      ];
    },
  );
}

// Only valid, unmatched HTTP input can become a new operation, including policy refusals.
const unmatchedHTTP = (r) =>
  r?.facts?.details?.http && !r.invalid && r.facts.operation == null;
export const draftable = (view, r) =>
  unmatchedHTTP(r) &&
  accounts(view)[r.facts.account] &&
  presetOf(view, r.facts.account).operations
    ? accounts(view)[r.facts.account].preset
    : null;

// The draft matches only this exact path; the owner turns segments into {parameters} and sets its effects and scope.
export function draftOperation(e) {
  const h = e.http,
    read = ["GET", "HEAD"].includes(h.method),
    params = Object.keys(h.query ?? {});
  return {
    id: `${h.method} ${h.path}`,
    action: read ? "read" : "write",
    effects: [read ? "read" : "write"],
    method: h.method,
    origin: h.origin,
    path: h.path,
    ...(params.length && { params }),
    ...(h.body_kind !== "none" && {
      body: ["json", "form"].includes(h.body_kind) ? h.body_kind : "any",
    }),
    ...(e.graphql?.fields?.length === 1 && {
      body: "graphql",
      graphql: { operation: e.graphql.kind, field: e.graphql.fields[0].name },
    }),
    scope: {},
  };
}

export function withDraft(file, r) {
  file = structuredClone(file);
  if (unmatchedHTTP(r)) {
    const { id, ...operation } = draftOperation(r.facts.details);
    file.http = {
      ...file.http,
      operations: { ...(file.http?.operations ?? {}), [id]: operation },
    };
  }
  return file;
}

export const newPreset = (name) => ({
  title: name,
  ...structuredClone(NEW_PRESET),
});

// Preset files keep one field, action and operation per line, as the shipped files do.
const EXPANDED = [
  "",
  "catalog",
  "catalog.fields",
  "catalog.actions",
  "http",
  "http.operations",
];
const compact = (v) =>
  Array.isArray(v)
    ? `[${v.map(compact).join(", ")}]`
    : v && typeof v === "object"
      ? `{${Object.entries(v)
          .map(([k, x]) => `${JSON.stringify(k)}: ${compact(x)}`)
          .join(", ")}}`
      : JSON.stringify(v);
export function presetText(v, path = "", indent = "") {
  if (!EXPANDED.includes(path) || v === null || typeof v !== "object")
    return compact(v);
  const [open, close, items] = Array.isArray(v)
    ? ["[", "]", v.map((x) => presetText(x, path + ".*", indent + "  "))]
    : [
        "{",
        "}",
        Object.entries(v).map(
          ([k, x]) =>
            `${JSON.stringify(k)}: ${presetText(x, path ? `${path}.${k}` : k, indent + "  ")}`,
        ),
      ];
  return items.length
    ? `${open}\n${indent}  ${items.join(`,\n${indent}  `)}\n${indent}${close}`
    : open + close;
}

// The starting choice only produces the initial policy. Persist completion and
// the effective configuration, without retaining a preset to reapply later.
function onboardingChanges(view, preset, tinfoilApiKey) {
  if (!Object.hasOwn(POLICY_PRESETS, preset))
    throw new Error("Choose a policy preset.");
  const connections = new Set(
    Object.entries(accounts(view)).flatMap(([name, acc]) =>
      Object.keys(acc.connections ?? {}).map((key) =>
        connectionName(name, key),
      ),
    ),
  );
  let account = "network";
  for (
    let i = 2;
    Object.hasOwn(accounts(view), account) || connections.has(account);
    i++
  )
    account = `network-${i}`;
  const changes = sourceChanges({
    data: { onboarding: { completed: true } },
    lattices: { confidentiality: preset !== "open", integrity: false },
    allow_networks: preset === "open" ? ["0.0.0.0/0", "::/0"] : [],
    accounts: {
      [account]: {
        preset: "tcp",
        contents: "anyone",
        strangers: true,
        sends: "anyone",
        connections: { "": { tcp: { hosts: ["*"] } } },
      },
    },
  });
  if (preset !== "open") {
    let policy = "network-default";
    for (let i = 2; Object.hasOwn(view.config.policies ?? {}, policy); i++)
      policy = `network-default-${i}`;
    changes.push(
      ...sourceChanges({
        policies: {
          [policy]:
            preset === "offline"
              ? 'package sentinel\n\ndeny contains "Network access is disabled."\n'
              : 'package sentinel\n\ndeny contains "This request has no recognized policy operation." if input.facts.operation == null\n',
        },
      }),
    );
  }
  const access = { level: preset === "open" ? "allow" : "off" };
  changes.push(
    preset === "offline"
      ? { path: ["default_access"], value: { [account]: access } }
      : { path: ["default_access", account], value: access },
  );
  // "Offline" means ONLY that sandboxes cannot send anything out (the deny
  // rule above). Trusted devices keep their sandbox routes and identities
  // keep their grants, so turning networking back on restores everything.
  if (tinfoilApiKey !== undefined) {
    const key = tinfoilApiKey.trim();
    if (!key) throw new Error("Enter your Tinfoil API key, or skip this step.");
    const catalog = view.presets.tinfoil;
    let name = "tinfoil";
    for (
      let i = 2;
      Object.hasOwn(accounts(view), name) ||
      Object.keys(catalog.connections).some((key) =>
        connections.has(connectionName(name, key)),
      );
      i++
    )
      name = `tinfoil-${i}`;
    changes.push(
      ...edits.addAccount(view, "tinfoil", {
        name,
        values: { TINFOIL_API_KEY: key },
        answers: catalog.defaults,
      }),
      {
        path: ["default_access", name],
        value: { level: preset === "offline" ? "off" : "allow" },
      },
    );
  }
  return changes;
}

const KNOWN_ONLY_RULE =
  'package sentinel\n\ndeny contains "This request has no recognized policy operation." if input.facts.operation == null\n';
const networkRuleName = (view) =>
  Object.keys(view.config.policies ?? {}).find((k) =>
    /deny contains "(Network access is disabled|This request has no recognized policy operation)/.test(
      view.config.policies[k],
    ),
  ) ?? "network-default";
// Raw TCP: the Monitor only sees host and port, never what is sent.
export const isRawNetwork = (view, account) =>
  view.config.accounts?.[account]?.preset === "tcp";
// "api.github.com:443" for a raw-network scope, else "key: value" pairs.
export const scopeText = (view, account, scope = {}) =>
  isRawNetwork(view, account) && scope.host
    ? `${scope.host}${scope.port ? `:${scope.port}` : ""}`
    : Object.entries(scope).map(
        ([k, v]) => `${k}: ${typeof v === "string" ? v : JSON.stringify(v)}`,
      );
// "Open" = every raw-TCP catch-all at allow for everyone, no deny rule, the
// whole internet in allow_networks. Settings → Dangerous only.
export const networkingOpen = (view) =>
  (view.config.allow_networks ?? []).includes("0.0.0.0/0") &&
  !Object.values(view.config.policies ?? {}).some((p) =>
    p.includes("package sentinel\n\ndeny contains"),
  );

// Each edit returns the source changes for POST /policy/edits.
export const edits = {
  setNetworkingOpen: (view, open) => {
    const tcpAccounts = Object.entries(accounts(view))
      .filter(([, a]) => a.preset === "tcp")
      .map(([name]) => name);
    return [
      { path: ["allow_networks"], value: open ? ["0.0.0.0/0", "::/0"] : [] },
      open
        ? { path: ["policies", networkRuleName(view)], delete: true }
        : { path: ["policies", networkRuleName(view)], value: KNOWN_ONLY_RULE },
      ...tcpAccounts.map((name) => ({
        path: ["default_access", name],
        value: { level: open ? "allow" : "off" },
      })),
    ];
  },
  pairAgent: (name, key) =>
    sourceChanges({
      identities: { [name.trim()]: { key: key.trim(), accounts: {} } },
    }),
  pairDevice: (name, key) =>
    sourceChanges({
      identities: { [name]: { key: key.trim(), routes: true, accounts: {} } },
    }),
  removeAgent: (name) => [{ path: ["identities", name], delete: true }],
  replaceKey: (name, key) => [
    { path: ["identities", name, "key"], value: key.trim() },
  ],
  setRoutes: (name, routes) => [
    { path: ["identities", name, "routes"], value: routes },
  ],
  setReviewer: (view, name, on) => [
    ...(on && !view.config.reviewer
      ? [
          {
            path: ["reviewer"],
            value: { ...DEFAULT_REVIEWER, connection: tinfoilConnection(view) },
          },
        ]
      : []),
    {
      path: ["identities", name, "reviewer"],
      ...(on ? { value: "tinfoil" } : { delete: true }),
    },
  ],
  setReviewerInstructions: (text) => [
    { path: ["reviewer", "instructions"], value: text.trim() },
  ],
  // An action set to null inherits again.
  setAccess: (name, account, access) =>
    sourceChanges({
      identities: { [name]: { accounts: { [account]: access } } },
    }),
  setEffect: ({ agent, account } = {}, effect, mode) => [
    {
      path: [
        ...(agent
          ? ["identities", agent, ...(account ? ["accounts", account] : [])]
          : account
            ? ["accounts", account]
            : []),
        "effects",
        effect,
      ],
      ...(mode ? { value: mode } : { delete: true }),
    },
  ],
  copySettings: (view, from, name) =>
    ["accounts", "rules", "effects", "reviewer"].map((key) => ({
      path: ["identities", name, key],
      value: structuredClone(
        identities(view)[from]?.[key] ?? (key === "reviewer" ? "" : {}),
      ),
    })),
  removeRule: (name, id) => [
    { path: ["identities", name, "rules", id], delete: true },
  ],
  setLattice: (lattice, on) => [{ path: ["lattices", lattice], value: on }],
  setNetworks: (text) => [
    { path: ["allow_networks"], value: text.split(/\s+/).filter(Boolean) },
  ],
  setPaidInference: (allow) => [
    { path: ["allow_paid_inference"], value: allow },
  ],
  setAccountPolicy: (account, source) =>
    sourceChanges({ policies: { [account]: source.trim() || null } }),
  approveTools: (view, account, key) =>
    sourceChanges({
      accounts: {
        [account]: {
          connections: {
            [key]: {
              [Object.keys(accounts(view)[account].connections[key])[0]]: {
                pin: view.status[connectionName(account, key)].details.pin,
              },
            },
          },
        },
      },
    }),
  // Identities may not name a missing account, so removing one also clears it from every agent.
  removeAccount: (view, account) => {
    const reviewer = Object.keys(
      accounts(view)[account]?.connections ?? {},
    ).some(
      (key) =>
        connectionName(account, key) === view.config.reviewer?.connection,
    );
    return sourceChanges({
      ...(reviewer ? { reviewer: null } : {}),
      accounts: { [account]: null },
      policies: { [account]: null },
      default_access: { [account]: null },
      identities: Object.fromEntries(
        Object.keys(identities(view)).map((n) => [
          n,
          {
            accounts: { [account]: null },
            ...(reviewer ? { reviewer: null } : {}),
          },
        ]),
      ),
    });
  },
  // values holds every setup field read with readField; oauth names the fields that sign in instead of taking a token.
  addAccount(view, preset, { name, values, answers, oauth = [] }) {
    const c = view.presets[preset];
    name = name.trim();
    if (!name) throw new Error("Name this account.");
    if (Object.hasOwn(accounts(view), name))
      throw new Error(
        "An account with that name already exists. Choose another name.",
      );
    const fields = setupFields(view, preset);
    // Only the non-secret values fill a preset's connections; secrets go to their fields' paths.
    const plainValues = Object.fromEntries(
      fields.filter((f) => !f.secret).map((f) => [f.key, values[f.key]]),
    );
    const connections = c.connections
      ? filled(c.connections, plainValues)
      : values.connections;
    const acc = {
      preset,
      ...answers,
      ...(JSON.stringify(connections) !== JSON.stringify(c.connections) && {
        connections,
      }),
    };
    for (const f of fields) {
      const value =
        f.oauth && oauth.includes(f.key)
          ? {
              oauth: filled(f.oauth, {
                ...values,
                monitor_host_id: view.host_id,
              }),
            }
          : f.secret && values[f.key] === ""
            ? null
            : values[f.key];
      for (const path of paths(f)) putPath(acc, path, value, { connections });
    }
    return sourceChanges({ accounts: { [name]: acc } });
  },
  addCustomApi(view, { name, api, token, agent, level, answers }) {
    name = name.trim();
    if (!/^[a-zA-Z0-9][a-zA-Z0-9-]*$/.test(name))
      throw new Error("Name this account using letters, numbers, and hyphens.");
    if (Object.hasOwn(accounts(view), name))
      throw new Error(
        "An account with that name already exists. Choose another name.",
      );
    if (!token.trim()) throw new Error("Enter the API key or token.");
    const body = {
      accounts: {
        [name]: {
          preset: "custom_api",
          ...answers,
          connections: {
            "": { http: { slots: [apiSlot(api)], secrets: { token } } },
          },
        },
      },
    };
    if (agent)
      body.identities = { [agent]: { accounts: { [name]: { level } } } };
    return sourceChanges(body);
  },
  // credentials maps a credential field key to keep, replace with a value, or clear; unchanged settings send nothing.
  saveAccount(
    view,
    account,
    { answers = {}, api, values = {}, credentials = {} },
  ) {
    const acc = accounts(view)[account],
      updated = structuredClone(acc),
      changed = new Set(),
      removals = [];
    const set = (path, value) => {
      if (same(atPath(acc, path), value)) return;
      putPath(updated, path, value);
      // Several controls can edit the same array; submit its final value once.
      const n = path.findIndex(
        (_, i) => i > 0 && Array.isArray(atPath(updated, path.slice(0, i))),
      );
      changed.add(JSON.stringify(n < 0 ? path : path.slice(0, n)));
    };
    for (const [key, value] of Object.entries(answers)) set([key], value);
    if (
      acc.preset === "custom_api" &&
      api &&
      !same(api, apiSettings(view, account))
    )
      set(
        ["connections", "", "http", "slots"],
        [apiSlot(api, acc.connections?.[""]?.http?.slots?.[0]?.value)],
      );
    for (const f of plainFields(view, account))
      if (Object.hasOwn(values, f.key) && !same(f.value, values[f.key]))
        for (const path of paths(f)) set(path, values[f.key]);
    for (const f of credentialFields(view, account)) {
      const { mode, value } = credentials[f.key] ?? {};
      if (mode === "replace") {
        if (value === "")
          throw new Error(
            `Enter a value for ${f.label}, or cancel the replacement.`,
          );
        for (const path of paths(f)) set(path, value);
      }
      if (mode === "clear")
        for (const path of paths(f))
          removals.push({ path: ["accounts", account, ...path], delete: true });
    }
    return [
      ...[...changed].map((key) => {
        const path = JSON.parse(key);
        return {
          path: ["accounts", account, ...path],
          value: atPath(updated, path),
        };
      }),
      ...removals,
    ];
  },
  // Operations missing from an edited preset are disabled rather than left to the shipped definition.
  savePreset(name, text, previous) {
    const value = JSON.parse(text);
    for (const id of Object.keys(previous?.http?.operations ?? {})) {
      if (value.http?.operations && !Object.hasOwn(value.http.operations, id))
        value.http.operations[id] = { enabled: false };
    }
    return [{ path: ["presets", name], value }];
  },
  removePreset: (name) => [{ path: ["presets", name], delete: true }],
};

// Setup guides for connecting tools. href maps a route such as ["pair"] or ["agent-settings", name] to a link, which
// also carries the route as data-route; code blocks carry data-copy with the id of the text to copy.
export const INTEGRATION_PAGES = {
  start: "Start here",
  wrapped: "Wrap commands",
  shell: "Monitor shell",
  mcp: "MCP connections",
};
export function integrationGuide(view, page, href) {
  const link = (route, text) =>
    `<a href="${esc(href(route))}" data-route="${esc(route.join("/"))}">${text}</a>`;
  const code = (id, title, text) =>
    `<div class="integration-code"><pre id="${esc(id)}">${esc(text)}</pre><button type="button" data-copy="${esc(id)}" aria-label="Copy ${esc(title)}">Copy</button></div>`;
  return (
    {
      start: `<h1>Get connected</h1><ol>
        <li>Add your apps in ${link(["connections"], "Connections")}.</li>
        <li>${link(["pair"], "Add your device's SSH key")}, then grant access in ${link(["agents"], "Agents")}.</li>
        <li>Set up the SSH alias <code>monitor</code> with your server address, private key, and the host key in agent <b>Settings</b>.</li>
      </ol>
      ${code("integration-check", "Check your connections", "monitor connections")}
      <details><summary>Install the client</summary><p>From the Monitor repository, with Python 3.11+ and OpenSSH installed:</p>
        ${code("integration-install", "Install Monitor", './install.sh\nexport PATH="$HOME/.local/bin:$PATH"')}</details>`,
      wrapped: `<h1>Wrap commands</h1><p>Run a local command through Monitor.</p>
      ${code("integration-run", "Run a command", "monitor run -- gh api user")}
      <p>Replace <code>gh api user</code> with your command. Requires proxy-compatible tools. ${link(["integrations", "start"], "Setup")}</p>`,
      shell: `<h1>Monitor shell</h1><p>Use your connections in a local terminal session.</p>
      ${code("integration-shell", "Open a shell", "monitor shell")}
      <p>Run commands as usual. Type <code>exit</code> to leave. ${link(["integrations", "start"], "Setup")}</p>`,
      mcp: `<h1>MCP connections</h1><p>Grant your agent access to a ready ${link(["connections"], "MCP connection")}, then run:</p>
      ${code("integration-mcp-serve", "Start MCP", "monitor mcp serve")}
      <p>Add the printed URLs to your MCP client using <b>Streamable HTTP</b>. Keep the command running. ${link(["integrations", "start"], "Setup")}</p>`,
    }[page] ?? ""
  );
}

// CAM serves this UI through the CLI's attested SSH tunnel. Its session token
// authorizes browser requests; private owner and storage keys never enter JS.
export function localOwnerClient({
  token,
  generation,
  fetch = (...args) => globalThis.fetch(...args),
}) {
  const json = ownerJSON(fetch);
  return ownerApi(async (method, path, body, signal) => {
    if (!token)
      throw new OwnerError(
        "Open this panel with tinfoil monitor open NAME.",
        401,
      );
    if (path.split("?")[0] === "/unlock")
      throw new OwnerError(
        "Run tinfoil monitor open NAME again to unlock over attested SSH.",
        423,
      );
    const asset = path.startsWith("/app/");
    return json(asset ? path : "/api" + path, {
      method,
      signal,
      cache: "no-store",
      credentials: "omit",
      redirect: "error",
      headers: {
        ...(!asset && { "X-Tinfoil-Session": token }),
        ...(body !== undefined && { "Content-Type": "application/json" }),
      },
      body: body === undefined ? undefined : JSON.stringify(body),
    });
  }, generation);
}
