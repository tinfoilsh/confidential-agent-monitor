// The owner API client and the request, permission and connection semantics of
// Monitor's app. The server remains the authority: these functions shape edits
// and describe its answers.

import { sha256 } from "@noble/hashes/sha2.js";
import { bytesToHex, utf8ToBytes } from "@noble/hashes/utils.js";

export type Json =
  null | boolean | number | string | Json[] | { [key: string]: Json };
export type Level = "off" | "read" | "ask" | "allow" | "custom";
export type GrantLevel = Exclude<Level, "custom">;
export type Mode = "off" | "ask" | "allow";
export type Audience = "me" | "team" | "anyone";
export type Trust = "trusted" | "untrusted";
export type Choice = "once" | "save" | "deny";
export type ApprovalAnswer = {
  by: string;
  decision: Choice;
  reason?: string;
  time: string;
};
export type RequestState =
  | "pending"
  | "allowed"
  | "refused"
  | "denied"
  | "expired"
  | "revoked"
  | "outdated";
export type Access = {
  level?: GrantLevel;
  actions?: Record<string, Mode>;
  effects?: Record<string, Mode>;
};
export type Setting = { mode: Mode; from: string };
export type ResolvedNode = Setting & {
  key: string;
  title: string;
  effects: string[];
  children?: ResolvedNode[];
};
export type Resolved = {
  reaches: boolean;
  level: Level;
  effects: Record<string, Setting>;
  actions?: Record<string, Setting>;
  tree?: ResolvedNode[];
};
export type Requirement = { id: string; message: string };
export type Decision =
  | { outcome: "allow"; sends_to: Audience; next: Label }
  | { outcome: "ask"; sends_to: Audience; gaps: Requirement[] }
  | { outcome: "deny"; sends_to: Audience; reasons: string[] };
// A denied refusal of a deny decision leaves its reasons to the decision.
export type Refusal = {
  cause: "invalid" | "precondition" | "denied" | "rejected" | "expired";
  reasons?: string[];
};
export type Rule = {
  enabled?: boolean;
  version?: number;
  connection: string;
  action: string;
  operation?: string;
  scope?: Record<string, Json>;
  requirements?: Requirement[];
};
export type Identity = {
  key?: string;
  certificate?: boolean;
  sandbox?: { source: string; instance_id: string };
  groups?: string[];
  connections?: Record<string, Access>;
  rules?: Record<string, Rule>;
};
// A connection's one key that is not a setting is its connector's kind, holding the setup.
const SETTINGS = [
  "preset",
  "match_only",
  "policy_options",
  "contents",
  "strangers",
  "sends",
];
export type Connection = {
  preset: string;
  match_only?: boolean;
  contents: Audience;
  sends: Audience;
  strangers?: boolean;
} & { [kind: string]: Json | undefined };
export type PresetField = {
  key: string;
  label: string;
  hint?: string;
  help?: string;
  secret?: boolean;
  multiline?: boolean;
  json?: boolean;
  list?: boolean;
  number?: boolean;
  min?: number;
  max?: number;
  edit_only?: boolean;
  default?: Json;
  path?: string[];
  paths?: string[][];
  credential?: boolean;
  oauth?: Json;
  compose?: Json;
  optional?: boolean;
};
export type PresetAction = { title: string; effects?: string[] };
export type Preset = {
  title: string;
  group?: string;
  warning?: string;
  replaced_by?: string;
  defaults: ConnectionAnswers;
  fields?: PresetField[];
  connection?: { [kind: string]: Json };
  actions?: Record<string, PresetAction>;
};
export type Label = {
  audience: Audience;
  trust: Trust;
  because?: Record<string, string>;
};
export type ConnectionStatus = {
  state: string;
  error?: string;
  details?: { blocked?: number; changes?: string[]; pin?: Json };
};
// The newer version a followed catalog can move to, by the SHA-256 it is at now.
export type CatalogUpdate = {
  pin?: string;
  url?: string;
  error?: string;
  // The update is to the presets the Perimeter ships with, not to a listed source.
  shipped?: boolean;
};
export type View = {
  generation: number;
  revision: number;
  catalog_id?: string;
  host_key: string;
  host_id: string;
  ca: string;
  config: {
    access?: Access;
    default_access?: Record<string, Access>;
    groups?: Record<string, { connections?: Record<string, Access> }>;
    data?: { [key: string]: Json };
    identities?: Record<string, Identity> | null;
    connections?: Record<string, Connection> | null;
    policies?: Record<string, string> | null;
    lattices?: { confidentiality?: boolean; integrity?: boolean };
    allow_networks?: string[] | null;
    catalogs?: Record<string, string> | null;
    resolved: Record<string, Record<string, Resolved>>;
    stale?: Record<string, Record<string, string>>;
  };
  labels: Record<string, Label>;
  status: Record<string, ConnectionStatus>;
  fields: Record<
    string,
    {
      name: string;
      kind: string;
      placeholder?: string;
      account?: string;
    }[]
  >;
  presets: Record<string, Preset>;
};
export type RequestDetails = {
  http?: { method: string; host: string; path: string };
  mcp?: { tool: string };
  smtp?: { to: string[] };
  mail?: { subject?: string };
  imap?: { command: string; args: string };
  policy?: { source_diff: string };
};
export type RequestRecord = {
  summary?: boolean;
  id: string;
  state: RequestState;
  time: string;
  expires?: string;
  decision?: Decision;
  refusal?: Refusal;
  scope?: { [key: string]: Json };
  savingDecision?: boolean;
  reviews?: ApprovalAnswer[];
  segment?: string;
  changes?: Change[];
  facts: {
    kind: "operation" | "admission" | "";
    title?: string;
    principal: { key?: string; name: string };
    connection: string;
    service?: string;
    operation: { id: string; action: string; effects?: string[] } | null;
    parameters?: { [key: string]: Json };
    details?: RequestDetails;
  };
};
export type Change = {
  path: string[];
  value?: Json;
  delete?: boolean;
  // Moves the value at another path here.
  from?: string[];
};
export type Snapshot = { view: View; requests: RequestRecord[] };
export type Request = (
  method: "GET" | "POST",
  path: string,
  body?: unknown,
  signal?: AbortSignal,
) => Promise<unknown>;
export type DeviceSignIn = {
  url: string;
  state: string;
  user_code: string;
  expires: string;
};
export type OwnerApi = {
  read(signal?: AbortSignal): Promise<Snapshot>;
  request(id: string, signal?: AbortSignal): Promise<RequestRecord>;
  archive(
    before: string,
    signal?: AbortSignal,
  ): Promise<{ records: RequestRecord[]; next?: string }>;
  archived(
    segment: string,
    id: string,
    signal?: AbortSignal,
  ): Promise<RequestRecord>;
  catalogUpdates(signal?: AbortSignal): Promise<Record<string, CatalogUpdate>>;
  unlock(generation?: number, signal?: AbortSignal): Promise<View>;
  onboard(
    view: View,
    choices: OnboardingChoices,
    signal?: AbortSignal,
  ): Promise<View>;
  edit(
    changes: Change[],
    credentials?: { [connection: string]: Credentials },
    signal?: AbortSignal,
  ): Promise<View>;
  decide(
    id: string,
    decision: Choice,
    gaps?: string[],
    signal?: AbortSignal,
  ): Promise<null>;
  enroll(
    identities: {
      [name: string]: { key: string; routes: boolean; restore: boolean };
    },
    signal?: AbortSignal,
  ): Promise<View>;
  signIn(
    connection: string,
    name: string,
    redirect: string,
    credential?: Json,
    signal?: AbortSignal,
  ): Promise<{ url: string } | DeviceSignIn>;
  finishSignIn(
    state: string,
    result:
      | string
      | { code?: string; client_id?: string; error?: string; cancel?: boolean },
    signal?: AbortSignal,
  ): Promise<View | { pending: true } | null>;
};
export type ShellOpen = {
  cols: number;
  rows: number;
};
export type Shell = {
  input(data: Uint8Array): void;
  resize(cols: number, rows: number): void;
};
export type ShellHandlers = {
  output(data: Uint8Array): void;
  exit(code?: number): void;
  error(cause: unknown): void;
};
export type ShellOpener = (
  open: ShellOpen,
  handlers: ShellHandlers,
  signal: AbortSignal,
) => Promise<Shell>;
export type ConnectorIcon = { src: string; dark?: string };
export type IconManifest = { [preset: string]: { src: string; dark?: string } };
export type AccessNode = Omit<ResolvedNode, "children"> & {
  children: AccessNode[];
};
export type Review = {
  name: string;
  state?: string;
  error?: string;
  blocked: number;
  added: number;
  changed: number;
  removed: number;
  changes: ReturnType<typeof toolChange>[];
  previouslyApproved: boolean;
};
export type McpTool = {
  name: string;
  description?: string;
  inputSchema?: {
    properties?: Record<
      string,
      { type?: string | string[]; description?: string }
    >;
    required?: string[];
  };
  annotations?: { readOnlyHint?: boolean; destructiveHint?: boolean };
};
// Credentials maps a connection's credential names to values; null clears one.
export type Credentials = { [name: string]: Json | null };
export type CredentialField = PresetField & {
  account?: string;
  status: string;
  stored: boolean;
  ready: boolean;
  signIn: boolean;
  grant?: { oauth: Json };
};
export type ApiSettings = {
  url: string;
  auth: "bearer" | "header" | "query";
  header: string;
  prefix: string;
  query: string;
};
export type ConnectionAnswers = {
  contents: Audience;
  strangers: boolean;
  sends: Audience;
};
// What the owner picked at first setup: connections with their credential, if
// they take one, and how bunkers reach hosts outside those connections.
export type OnboardingChoices = {
  connections: { preset: string; level: GrantLevel; credential?: string }[];
  network: Exclude<GrantLevel, "read">;
  registries: boolean;
};

export const LEVELS: { [L in GrantLevel]: string } = {
  off: "No access",
  read: "Read only",
  ask: "Ask",
  allow: "Allow",
};
export const MODES: { [M in Mode]: string } = {
  allow: "Allow",
  ask: "Ask",
  off: "Deny",
};
export const CATALOG_GROUPS: { [group: string]: string } = {
  api: "API",
  mcp: "MCP",
  protocol: "Protocol",
  generic: "Generic",
};
export const COMMON_PRESETS = [
  "tinfoil",
  "anthropic",
  "openai",
  "github",
  "gmail",
  "email",
];
// Most important first within each group; presets not listed follow alphabetically.
export const PRESET_ORDER = [
  "web",
  "ssh",
  "tcp",
  "custom_api",
  "mcp",
  "aws",
  "google_cloud",
  "google_drive",
  "google_calendar",
  "google_docs",
  "google_sheets",
  "slack",
  "notion",
  "linear",
  "jira",
  "confluence",
  "gitlab",
  "outlook",
  "microsoft_teams",
  "microsoft_onedrive",
  "discord",
  "telegram",
  "stripe",
  "hubspot",
  "salesforce",
  "airtable",
  "asana",
  "dropbox",
  "zoom_api",
  "zendesk",
  "shopify",
  "twilio",
  "cloudflare_api",
  "google_gemini",
  "tinfoil_websearch",
  "github_mcp",
  "slack_mcp",
  "notion_mcp",
  "linear_mcp",
  "atlassian",
  "asana_mcp",
  "sentry",
  "stripe_mcp",
  "supabase_mcp",
  "cloudflare",
  "vercel",
  "figma",
  "canva",
  "context7",
];
const LOOPBACK = ["localhost", "127.0.0.1", "[::1]"];

// Human input preserves UTF-8 bytes, including whitespace. Old canonical
// base64 32-byte keys keep their original meaning; base64 is only the wire format.
export function encodeOwnerKey(input: string): string {
  if (typeof input === "string" && input.trim().startsWith("{"))
    throw new Error(
      "Use tinfoil perimeter open. Do not load private credential files into a remote web page.",
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
  status: number;
  constructor(message: string, status: number) {
    super(message);
    this.status = status;
  }
}

// Keep validators and parsed responses in this authenticated client's memory,
// never in browser storage. Bound the cache when navigating through audit details.
function ownerJSON(
  fetch: typeof globalThis.fetch,
  base: string,
  auth: Record<string, string>,
): Request {
  const cache = new Map<string, { tag: string; value: unknown }>();
  return async (method, path, body, signal) => {
    const url = base + path,
      read = method === "GET",
      known = read && cache.get(url);
    if (!read) cache.clear();
    const res = await fetch(url, {
      method,
      signal,
      cache: "no-store",
      credentials: "omit",
      redirect: "error",
      headers: {
        ...auth,
        ...(body !== undefined && { "Content-Type": "application/json" }),
        ...(known && { "If-None-Match": known.tag }),
      },
      body: body === undefined ? undefined : JSON.stringify(body),
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
      if (cache.size > 4) cache.delete(cache.keys().next().value!);
    }
    return value;
  };
}

function endpointBase(endpoint: string) {
  let url;
  try {
    url = new URL(endpoint);
  } catch {
    throw new Error("Invalid Perimeter endpoint.");
  }
  if (
    url.protocol !== "https:" &&
    !(url.protocol === "http:" && LOOPBACK.includes(url.hostname))
  )
    throw new Error("The Perimeter endpoint must use HTTPS.");
  if (url.username || url.password || url.search || url.hash)
    throw new Error("Invalid Perimeter endpoint.");
  return url.href.replace(/\/$/, "");
}

// Without an endpoint, requests go to the page's own origin; any given endpoint, even an empty one, must be a valid URL.
// A remote owner API needs HTTPS. The key is never sent on a redirect.
export function ownerClient({
  endpoint,
  key,
  fetch,
}: {
  endpoint?: string;
  key: string;
  fetch: typeof globalThis.fetch;
}): OwnerApi {
  if (typeof key === "string" && key.trim().startsWith("{"))
    throw new Error(
      "Signing credentials require tinfoil perimeter open and its attested connection.",
    );
  return ownerApi(
    ownerJSON(fetch, endpoint === undefined ? "" : endpointBase(endpoint), {
      Authorization: "Bearer " + key,
    }),
  );
}

const ROLLBACK =
  "The Perimeter state is older than the last state you saw. Restore the latest Perimeter state before continuing.";

// With a known generation, an older view is a rollback, and a locked monitor unlocks at that minimum.
export function ownerApi(
  request: Request,
  generation?: number,
  advance?: (generation: number) => void,
): OwnerApi {
  let minimum = generation;
  let catalog: { id: string; presets: Record<string, Preset> } | undefined;
  // Writes name the settings revision of the last view this client received.
  let revision = 0;
  const checked = (view: View) => {
    if (minimum !== undefined && view) {
      if (!Number.isSafeInteger(view.generation) || view.generation < minimum)
        throw new OwnerError(ROLLBACK, 409);
      if (view.generation > minimum) advance?.(view.generation);
      minimum = view.generation;
    }
    if (view) revision = view.revision;
    return view;
  };
  const get = <T>(path: string, signal?: AbortSignal) =>
    request("GET", path, undefined, signal) as Promise<T>;
  const post = <T>(path: string, body: unknown, signal?: AbortSignal) =>
    request("POST", path, body, signal) as Promise<T>;
  const snapshot = async (
    method: "GET" | "POST",
    path: string,
    body?: unknown,
    signal?: AbortSignal,
  ): Promise<View> => {
    const known = catalog;
    const view = (await request(
      method,
      known ? `${path}?catalog=${encodeURIComponent(known.id)}` : path,
      body,
      signal,
    )) as View & { pending?: true };
    // An older Perimeter sends no resolved access, which every page reads.
    if (view?.config && !("resolved" in view.config))
      throw new OwnerError(
        "This Perimeter is older than this console. Update the Perimeter to manage it here.",
        426,
      );
    if (view?.catalog_id) {
      if (view.presets)
        catalog = { id: view.catalog_id, presets: view.presets };
      else if (known?.id === view.catalog_id) view.presets = known.presets;
      else
        throw new OwnerError(
          "The Perimeter returned an unknown preset catalog. Reload the page.",
          409,
        );
    }
    return view?.pending === true ? view : checked(view);
  };
  const unlock = (at = minimum ?? 0, signal?: AbortSignal) =>
    snapshot("POST", "/unlock", { generation: at }, signal);
  return {
    async read(signal) {
      const path = "/requests";
      const [view, requests] = await Promise.all([
        snapshot("GET", "/", undefined, signal),
        get<RequestRecord[] | null>(path, signal),
      ]).catch(async (err) => {
        if (err.status !== 423 || minimum === undefined) throw err;
        return [
          await unlock(minimum, signal),
          await get<RequestRecord[] | null>(path, signal),
        ] as const;
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
    catalogUpdates: (signal) => get("/catalogs/updates", signal),
    unlock,
    async onboard(view, choices, signal) {
      if (onboarded(view)) return view;
      const { changes, credentials } = onboardingChanges(view, choices);
      return snapshot(
        "POST",
        "/policy/edits",
        {
          changes,
          credentials,
          revision: view.revision,
        },
        signal,
      );
    },
    edit: (changes, credentials, signal) =>
      snapshot(
        "POST",
        "/policy/edits",
        { changes, credentials, revision },
        signal,
      ),
    decide: (id, decision, gaps, signal) =>
      snapshot(
        "POST",
        `/requests/${encodeURIComponent(id)}`,
        { decision, gaps, revision },
        signal,
      ).then(() => null),
    enroll: (identities, signal) =>
      snapshot("POST", "/enroll", identities, signal),
    signIn: (connection, name, redirect, credential, signal) =>
      post(
        `/connections/${encodeURIComponent(connection)}/sign-in`,
        { name, redirect, credential },
        signal,
      ),
    finishSignIn: (state, result, signal) =>
      snapshot(
        "POST",
        `/sign-in/${encodeURIComponent(state)}`,
        typeof result === "string" ? { code: result } : result,
        signal,
      ),
  };
}

// The manifest names each preset's file and optional dark variant; a preset without one shows the custom icon.
export function connectorIcon(
  manifest: IconManifest | undefined,
  preset: string,
  assets: string,
): ConnectorIcon {
  const icon = manifest?.[preset]?.src
    ? manifest[preset]
    : (manifest?.custom ?? { src: "custom.svg" });
  const url = (file: string) => `${assets}icons/${encodeURIComponent(file)}`;
  return { src: url(icon.src), ...(icon.dark && { dark: url(icon.dark) }) };
}

// Controls address source values; named rules and operations stay named.
export function sourceChanges(
  body: { [key: string]: any },
  path: string[] = [],
): Change[] {
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

export function applyChanges<T extends object>(
  target: T,
  changes: Change[],
): T {
  for (const change of changes) {
    let source: any,
      moved: any = target;
    for (const key of change.from ?? []) {
      source = moved;
      moved =
        source && typeof source === "object" && Object.hasOwn(source, key)
          ? source[key]
          : undefined;
    }
    if (change.from) {
      if (moved === undefined) continue;
      delete source[change.from.at(-1)!];
    }
    let parent: any = target;
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
    const key = change.path.at(-1)!;
    if (change.delete) delete parent[key];
    else
      Object.defineProperty(parent, key, {
        value: clone(change.from ? moved : change.value),
        enumerable: true,
        configurable: true,
        writable: true,
      });
  }
  return target;
}

export function previewChanges(view: View, changes: Change[]): View {
  const config = { ...view.config },
    copied = new WeakSet<object>([config]);
  for (const change of changes) {
    let parent: any = config;
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
  return view;
}

const identities = (view: View) => view.config.identities ?? {};
export const BUNKERS = "bunkers";
// Matches the device names assigned by owner enrollment.
export const isDevice = (name: string) => /^device-[0-9a-f]{16}$/.test(name);
export const sandboxNames = (view: View) =>
  Object.keys(identities(view)).filter((name) => !isDevice(name));
export const onboarded = (view: View) =>
  (view.config.data?.onboarding as { completed?: Json } | undefined)
    ?.completed === true;
const connections = (view: View) => view.config.connections ?? {};
const PERIMETER = "perimeter";
export const isBuiltin = (name: string) => name === PERIMETER;
export const serviceNames = (view: View) =>
  Object.keys(connections(view)).filter((name) => !isBuiltin(name));
const ROUTES_PUBLISH = "routes.publish";
// The built-in group granting config.deviceActions on the Perimeter.
const DEVICE = "device";
const flatten = (nodes: ResolvedNode[] = []): ResolvedNode[] =>
  nodes.flatMap((node) => [node, ...flatten(node.children)]);
export const publishesRoutes = (view: View, name: string) =>
  flatten(view.config.resolved[name]?.[PERIMETER]?.tree).some(
    (node) => node.key === ROUTES_PUBLISH && node.mode === "allow",
  );
export const kindOf = (c?: Connection) =>
  Object.keys(c ?? {}).find((key) => !SETTINGS.includes(key));
export const setupOf = (c?: Connection) =>
  c?.[kindOf(c)!] as { [key: string]: Json } | undefined;
const UNKNOWN_PRESET = { title: "Connection" };
export const presetOf = (view: View, name: string): Omit<Preset, "defaults"> =>
  view.presets[connections(view)[name]?.preset] ?? UNKNOWN_PRESET;
export const matchOnly = (view: View, name: string) =>
  !!connections(view)[name]?.match_only;
const fill = (text: string, scope?: { [key: string]: any }) =>
  text.replace(/\{(\w+)\}/g, (m, k) => scope?.[k] ?? m);
const filled = <T>(c: T, values?: { [key: string]: any }): T =>
  JSON.parse(JSON.stringify(c), (_, v) =>
    typeof v === "string" ? fill(v, values) : v,
  );
// View values can be store proxies, which structuredClone refuses; they are JSON.
const clone = <T>(value: T): T =>
  value === undefined ? value : JSON.parse(JSON.stringify(value));
const atPath = (object: any, path: string[]): any =>
  path.reduce((value, key) => value?.[key], object);
// JSON values are equal regardless of key order, which differs between server responses and edited copies.
const same = (a: any, b: any): boolean =>
  a === b ||
  (!!a &&
    !!b &&
    typeof a === "object" &&
    typeof b === "object" &&
    Array.isArray(a) === Array.isArray(b) &&
    Object.keys(a).length === Object.keys(b).length &&
    Object.keys(a).every((k) => Object.hasOwn(b, k) && same(a[k], b[k])));
function putPath(object: any, path: string[], value: unknown, defaults?: any) {
  for (const [index, key] of path.slice(0, -1).entries()) {
    defaults = defaults?.[key];
    // Arrays replace inherited values as a whole, so retain every preset entry when editing one element.
    if (!Object.hasOwn(object, key))
      Object.defineProperty(object, key, {
        value: Array.isArray(defaults)
          ? clone(defaults)
          : typeof path[index + 1] === "number"
            ? []
            : {},
        enumerable: true,
      });
    object = object[key];
  }
  Object.defineProperty(object, path.at(-1)!, {
    value,
    enumerable: true,
    configurable: true,
    writable: true,
  });
}

export function summary(e?: RequestDetails): string {
  if (e?.http) return `${e.http.method} ${e.http.host}${e.http.path}`;
  if (e?.smtp)
    return `To ${e.smtp.to.join(", ")}${e.mail?.subject ? `: ${e.mail.subject}` : ""}`;
  if (e?.imap) return `${e.imap.command} ${e.imap.args}`;
  if (e?.mcp) return e.mcp.tool;
  return "";
}
export const requestTitle = (r: RequestRecord): string =>
  r.facts?.title ||
  summary(r.facts?.details) ||
  r.facts?.operation?.id ||
  r.facts?.connection;
const effectOf = (gap: Requirement) =>
  gap.id.startsWith("effect.") && gap.id !== "effect.unknown"
    ? gap.id.slice("effect.".length)
    : undefined;
const listText = (items: string[]) =>
  items.length < 3
    ? items.join(" and ")
    : `${items.slice(0, -1).join(", ")}, and ${items.at(-1)}`;
const gapReasons = (gaps: Requirement[]) => {
  const asking = gaps.filter(effectOf);
  return [
    ...(asking.length > 1
      ? [
          `The ${listText(asking.map(effectOf) as string[])} effects require approval (Ask).`,
        ]
      : asking.map((gap) => gap.message)),
    ...gaps.filter((gap) => !effectOf(gap)).map((gap) => gap.message),
  ];
};
export const gapIds = (r?: RequestRecord) =>
  r?.decision?.outcome === "ask"
    ? r.decision.gaps.map((gap) => gap.id)
    : undefined;
export const reasons = ({
  decision,
  refusal,
}: Pick<RequestRecord, "decision" | "refusal">) => [
  ...(decision?.outcome === "deny"
    ? decision.reasons
    : decision?.outcome === "ask"
      ? gapReasons(decision.gaps)
      : []),
  ...(refusal?.reasons ?? []),
];
// A pending request past its deadline is expired, even before the next poll says so.
export const stateAt = (r: RequestRecord, now: number): RequestState =>
  r.state === "pending" && r.expires && Date.parse(r.expires) <= now
    ? "expired"
    : r.state;
export const isProposal = (r: RequestRecord) =>
  r.facts.service === "policy-proposal";
const OWNER = "owner";
export const isOwner = (name: string) => name === OWNER;
export const isOwnerCall = (r: RequestRecord) =>
  isOwner(r.facts.principal.name);
export const requester = (r: RequestRecord) =>
  isOwnerCall(r) ? "You" : r.facts.principal.name;
const approval = (r: RequestRecord) =>
  r.state === "allowed"
    ? r.reviews?.filter((review) => review.decision !== "deny").at(-1)
    : undefined;
export const approved = (r: RequestRecord) => !!approval(r);
export function reviewStatus(r: RequestRecord): string {
  if (isOwnerCall(r)) return r.state === "allowed" ? "Done" : "Failed";
  const by = (review: ApprovalAnswer) =>
    ` by ${isOwner(review.by) ? "you" : review.by}`;
  const approver = approval(r);
  if (approver) return "Approved" + by(approver);
  if (r.state === "denied") {
    const denier = r.reviews
      ?.filter((review) => review.decision === "deny")
      .at(-1);
    return (isProposal(r) ? "Rejected" : "Denied") + (denier ? by(denier) : "");
  }
  if (r.state === "revoked") return "Stopped";
  return r.state.charAt(0).toUpperCase() + r.state.slice(1);
}
// Rejected and expired refusals end in states of their own.
const refusedText: Partial<Record<Refusal["cause"], string>> = {
  invalid: "Refused: the Perimeter could not read this request.",
  precondition: "Refused: the Perimeter could not complete it.",
  denied: "Refused by policy.",
};
// Undefined where the reviews already say how it ended.
export function outcomeText(r: RequestRecord): string | undefined {
  if (isOwnerCall(r))
    return r.state === "allowed"
      ? "You did this. Your own actions are not checked against policy."
      : "You did this, and it failed.";
  switch (r.state) {
    case "pending":
      return r.savingDecision ? undefined : "Waiting for you.";
    case "allowed":
      return approved(r) ? undefined : "Allowed by policy.";
    case "refused":
      return (r.refusal && refusedText[r.refusal.cause]) ?? "Refused.";
    case "denied":
      return undefined;
    case "expired":
      return "Nobody answered in time.";
    case "revoked":
      return "Stopped: this access no longer passes.";
    case "outdated":
      return "Settings for this connection changed before review.";
  }
}
export function ordered(records: RequestRecord[], dismissed: string[] = []) {
  const hidden = new Set(dismissed);
  const priority = (r: RequestRecord) =>
    r.state === "pending"
      ? 0
      : r.state === "expired" && !hidden.has(r.id) && !r.segment
        ? 1
        : 2;
  return [...records].sort(
    (a, b) =>
      priority(a) - priority(b) ||
      (a.state === "pending" && b.state === "pending"
        ? Date.parse(a.expires!) - Date.parse(b.expires!)
        : 0),
  );
}
export function timeLeft(r: RequestRecord, now = Date.now()) {
  const s = Math.max(0, Math.round((Date.parse(r.expires!) - now) / 1000));
  return `${Math.floor(s / 60)}:${String(s % 60).padStart(2, "0")}`;
}

// A saved approval binds one operation and its grant. The text names fields, not values, which can be whole messages;
// fields left out of the grant are named as broad.
export function grantText(
  operation: string | undefined,
  grant?: { [key: string]: Json },
  scope?: { [key: string]: Json },
) {
  const fields = Object.keys(grant ?? {}),
    broad = Object.keys(scope ?? {}).filter((k) => !fields.includes(k));
  return (
    `Allow ${operation} ${fields.length ? "for the same " + fields.join(", ") : "for any request"}` +
    (fields.length && broad.length ? `, with any ${broad.join(", ")}` : "")
  );
}
export const saveText = (r: RequestRecord) =>
  `${grantText(r.facts?.operation?.id, r.scope, r.facts?.parameters)} on ${stateAt(r, Date.now()) === "expired" ? "future attempts. Retry this request after saving." : "this and future attempts."}`;
// Saving a rule also works after a timeout.
export function decisions(
  r: RequestRecord,
  now?: number,
): { once?: boolean; save?: boolean; deny?: boolean; dismiss?: boolean } {
  const state = now === undefined ? r.state : stateAt(r, now);
  const save = !!r.facts.operation?.id;
  return r.savingDecision
    ? {}
    : state === "pending"
      ? { once: true, save, deny: true }
      : state === "expired"
        ? { save, dismiss: true }
        : {};
}
// Every identity has every connection's tree, so any one gives the titles.
const titlesOf = (view: View, connection: string) =>
  Object.fromEntries(
    flatten(
      Object.values(view.config.resolved).find(
        (access) => access[connection],
      )?.[connection]?.tree,
    ).map((node) => [node.key, node.title]),
  );
export function ruleTitle(view: View, r: Rule) {
  const titles = titlesOf(view, r.connection);
  return (
    r.action
      .split(".")
      .map((_, i, parts) => titles[parts.slice(0, i + 1).join(".")])
      .filter(Boolean)
      .join(" › ") || r.action
  );
}

const inherited = (s: Setting) =>
  /^(access|default_access|groups)\./.test(s.from);
export const provenance = (s: Setting) =>
  `${s.mode}, ${inherited(s) ? "inherited from" : "set by"} ${s.from}`;

export const levelsOf = (c?: Connection) =>
  (Object.entries(LEVELS) as [GrantLevel, string][]).filter(
    ([l]) =>
      !["custom_api", "tcp", BUNKERS].includes(c?.preset ?? "") || l !== "read",
  );

const UNRESOLVED: Resolved = { reaches: false, level: "off", effects: {} };
export function agentAccess(view: View, name: string, only?: string) {
  const known: Record<string, Connection> = {
    [BUNKERS]: { preset: BUNKERS } as Connection,
    ...connections(view),
  };
  const entries: [string, Connection][] =
    only === undefined
      ? Object.entries(connections(view))
      : known[only]
        ? [[only, known[only]]]
        : [];
  const resolved = view.config.resolved[name] ?? {},
    own = identities(view)[name]?.connections ?? {};
  return entries.map(([connection, c]) => {
    const r = resolved[connection] ?? UNRESOLVED,
      named = r.actions ?? {};
    const describe = ({ children, ...node }: ResolvedNode): AccessNode => ({
      ...node,
      children: (children ?? []).map(describe),
    });
    // A lone group nobody named repeats the connection's own row.
    const ungrouped = (nodes: AccessNode[]): AccessNode[] =>
      nodes.length === 1 &&
      nodes[0].children.length > 1 &&
      !Object.hasOwn(named, nodes[0].key)
        ? nodes[0].children
        : nodes;
    let actions: AccessNode[] | undefined;
    return {
      connection,
      preset: c.preset,
      level: r.level,
      reaches: r.reaches,
      levels: levelsOf(c),
      overrides: Object.keys(own[connection]?.actions ?? {}).length,
      get actions(): AccessNode[] {
        return (actions ??= ungrouped((r.tree ?? []).map(describe)));
      },
    };
  });
}

export function review(view: View, name: string): Review | undefined {
  const c = connections(view)[name];
  if (!c) return;
  const status = view.status[name] ?? {},
    s = status.details ?? {},
    pin = setupOf(c)?.pin as { tools?: McpTool[] } | null | undefined;
  const tools = (s.pin as { tools?: McpTool[] } | undefined)?.tools ?? [];
  const changes = (s.changes ?? []).map((change) =>
    toolChange(change, tools, pin?.tools),
  );
  const count = (kind: string) =>
    changes.filter((change) => change.kind === kind).length;
  return {
    name,
    state: status.state,
    error: status.error,
    blocked: s.blocked ?? 0,
    added: count("New"),
    changed: count("Changed"),
    removed: count("Removed"),
    changes,
    previouslyApproved: pin != null,
  };
}

export function toolReviewDescription(review: Review): string {
  if (!review.previouslyApproved)
    return `Bunkers can use ${review.blocked === 1 ? "this tool" : "these tools"} once you approve.`;
  if (review.changes.some((change) => change.instructions))
    return "The server's instructions changed since you approved them. Bunkers can use the affected tools again once you approve.";
  return "These tools changed since you approved them. Bunkers can use them again once you approve.";
}
// Connections whose MCP tools wait for the owner's approval.
export const toolReviews = (view: View) =>
  Object.keys(connections(view))
    .filter((name) => (view.status[name]?.details?.blocked ?? 0) > 0)
    .sort();
export const toolReviewCount = (view: View) =>
  toolReviews(view).reduce(
    (count, name) => count + view.status[name].details!.blocked!,
    0,
  );

// A pin change is "+ name", "~ name" or "- name" and then the tool's definition,
// or "~ instructions:" and then the server's instructions.
const PIN_CHANGES: { [sign: string]: "New" | "Changed" | "Removed" } = {
  "+": "New",
  "~": "Changed",
  "-": "Removed",
};
export function toolChange(
  change: string,
  tools: McpTool[],
  previousTools: McpTool[] = [],
) {
  const [head, ...rest] = change.split("\n");
  const name = head.slice(2);
  const previous = previousTools.find((t) => t.name === name);
  const tool = head[0] === "-" ? previous : tools.find((t) => t.name === name);
  // Compare the fetched definition with the saved, owner-approved pin. The
  // server's change text contains only the new definition, not a before/after.
  const changedFields: { name: string; kind: string }[] = [];
  const compare = (before: object = {}, after: object = {}, prefix = "") => {
    const old = before as Record<string, unknown>,
      next = after as Record<string, unknown>;
    for (const key of new Set([...Object.keys(old), ...Object.keys(next)])) {
      if (same(old[key], next[key])) continue;
      changedFields.push({
        name: prefix + key,
        kind: !Object.hasOwn(old, key)
          ? "Added"
          : !Object.hasOwn(next, key)
            ? "Removed"
            : "Changed",
      });
    }
  };
  if (head[0] === "~" && previous && tool) {
    const { inputSchema: oldSchema, ...old } = previous,
      { inputSchema: newSchema, ...next } = tool;
    compare(old, next);
    const { properties: oldProperties, ...oldRest } = oldSchema ?? {},
      { properties: newProperties, ...newRest } = newSchema ?? {};
    compare(oldRest, newRest, "inputSchema.");
    compare(oldProperties, newProperties, "parameter: ");
  }
  return {
    kind: PIN_CHANGES[head[0]],
    name,
    instructions: head === "~ instructions:",
    tool,
    changedFields,
    text: rest.join("\n"),
    parameters: Object.entries(tool?.inputSchema?.properties ?? {}).map(
      ([key, p]) => ({
        name: key,
        type: [p.type ?? []].flat().join(" | "),
        description: p.description,
        required: !!tool?.inputSchema?.required?.includes(key),
      }),
    ),
  };
}

export function connectionStatus(
  r?: Review,
): { state: "error" | "connecting" | "review"; text: string } | undefined {
  if (r?.error) return { state: "error", text: "Can't connect" };
  if (r?.state === "connecting")
    return { state: "connecting", text: "Connecting…" };
  if (r?.blocked)
    return {
      state: "review",
      text: `${r.blocked} ${r.blocked === 1 ? "tool" : "tools"} to review`,
    };
}

const paths = (f: PresetField) => f.paths ?? [f.path!];
const fieldsOf = (c?: Pick<Preset, "fields">) => c?.fields ?? [];
// A field with no paths, such as an OAuth client ID, fills templates but is never stored on the connection.
const plain = (c: Pick<Preset, "fields">) =>
  fieldsOf(c).filter((f) => !f.secret && paths(f).length);
const fieldValue = (
  c: Connection | undefined,
  f: PresetField,
  preset?: Pick<Preset, "connection">,
): Json =>
  atPath(c, f.path ?? paths(f)[0]) ??
  atPath(preset?.connection, f.path ?? paths(f)[0]) ??
  (f.list ? [] : f.json ? {} : "");
export const setupFields = (view: View, preset: string) =>
  fieldsOf(view.presets[preset]).filter((f) => !f.edit_only);
export const clientFields = (view: View, name: string) =>
  fieldsOf(presetOf(view, name)).filter((f) => !paths(f).length);
export const plainFields = (view: View, name: string) =>
  plain(presetOf(view, name)).map((f) => ({
    ...f,
    value: fieldValue(connections(view)[name], f, presetOf(view, name)),
  }));
export const fieldText = (f: PresetField, value?: Json): string =>
  f.json
    ? value === undefined
      ? ""
      : JSON.stringify(value, null, 2)
    : f.list
      ? ((value ?? []) as string[]).join(", ")
      : String(value ?? "");
export const listDelimiter = /[\s,]+/;
export const listItems = (text: string) =>
  text.split(listDelimiter).filter(Boolean);
export const fieldError = (f: PresetField, s: string) => {
  if (!f.number) return;
  if (!/^\d+$/.test(s))
    return `${f.label} takes whole numbers, not "${s}".`;
  if (f.min !== undefined && Number(s) < f.min)
    return `${f.label} must be at least ${f.min}.`;
  if (f.max !== undefined && Number(s) > f.max)
    return `${f.label} must be at most ${f.max}.`;
};
export function readField(f: PresetField, raw: string): Json {
  const v = f.secret ? raw : raw.trim();
  if (f.json) return v ? JSON.parse(v) : {};
  const read = (s: string) => {
    if (f.number && s === "") s = fieldText(f, f.default);
    const error = fieldError(f, s);
    if (error) throw new Error(error);
    return f.number ? Number(s) : s;
  };
  return f.list ? listItems(v).map(read) : read(v);
}
// A composed credential is entered whole: any input enters it, and then every input not marked optional is required.
const composed = (
  template: Json,
  inputs: PresetField[],
  values: { [key: string]: Json | undefined },
) => {
  if (!inputs.some((c) => values[c.key])) return null;
  const blank = inputs.find((c) => !c.optional && !values[c.key]);
  if (blank) throw new Error(`Enter a value for ${blank.label}.`);
  return filled(
    template,
    Object.fromEntries(inputs.map((c) => [c.key, values[c.key] ?? ""])),
  );
};

// A grant template fills from the connection's plain settings and, when given, its client values; blank ones take their defaults.
export function grantTemplate(
  view: View,
  name: string,
  f?: PresetField,
  client?: Record<string, string>,
): Json | undefined {
  if (!f?.oauth) return;
  const values = Object.fromEntries(
    plainFields(view, name).map((p) => [p.key, p.value]),
  );
  if (client)
    for (const c of clientFields(view, name))
      values[c.key] = client[c.key] || fieldText(c, c.default);
  const grant =
    f?.oauth &&
    (filled(f.oauth, { ...values, monitor_host_id: view.host_id }) as {
      [key: string]: Json;
    });
  // An authorization URL needs a client ID unless the preset supplies or registers one.
  return grant &&
    !/\{\w+\}/.test(JSON.stringify(grant)) &&
    (grant.client_id ||
      grant.default_client ||
      grant.callback_registration ||
      !grant.auth_url)
    ? grant
    : undefined;
}

// Kinds are connector/credential.Describe's: unset, static, oauth and oauth-required.
// A stored grant keeps its client and endpoints for sign-in unless client values are entered; unset or static values use the template.
export function credentialFields(
  view: View,
  name: string,
  client?: Record<string, string>,
): CredentialField[] {
  const entered = clientFields(view, name).some((c) => client?.[c.key]);
  const byName = new Map(
    fieldsOf(presetOf(view, name))
      .filter((f) => f.credential)
      .map((f) => [f.key, f]),
  );
  return (view.fields?.[name] ?? [])
    .map((meta) => {
      const f = byName.get(meta.name);
      const field = {
        ...f,
        ...meta,
        key: meta.name,
        label: f?.label ?? meta.name,
        secret: true,
        multiline: f ? !!f.multiline : true,
      };
      const oauth = meta.kind.startsWith("oauth"),
        stored = meta.kind !== "unset",
        ready = stored && meta.kind !== "oauth-required";
      const grant =
        oauth && !entered
          ? undefined
          : grantTemplate(view, name, field, client);
      return {
        ...field,
        status: !stored
          ? "Not configured"
          : ready
            ? "Configured"
            : "Sign-in required",
        stored,
        ready,
        signIn: oauth || !!grant,
        grant: grant ? { oauth: grant } : undefined,
      };
    })
    .sort((a, b) => a.key.localeCompare(b.key));
}

export const signInLabel = (view: View, preset: string) =>
  view.presets[preset]?.title
    ? "Sign in with " + view.presets[preset].title
    : "Sign in";

export function loopbackSignIn(f: PresetField, values: Record<string, string>) {
  if (!f.oauth) return false;
  const grant = filled(f.oauth, values) as {
    loopback?: boolean;
    client_id?: string;
    default_client?: { loopback?: boolean };
  };
  return (
    !!grant.loopback || (!grant.client_id && !!grant.default_client?.loopback)
  );
}

export function catalog(view: View) {
  const counts = new Map<string, number>();
  for (const c of Object.values(connections(view))) {
    const replacement = view.presets[c.preset]?.replaced_by;
    const preset =
      replacement && view.presets[replacement] ? replacement : c.preset;
    counts.set(preset, (counts.get(preset) ?? 0) + 1);
  }
  // A retired preset's name and title still find its replacement.
  const aliases = new Map<string, string>();
  for (const [name, preset] of Object.entries(view.presets))
    if (preset.replaced_by)
      aliases.set(
        preset.replaced_by,
        `${aliases.get(preset.replaced_by) ?? ""} ${name} ${preset.title}`,
      );
  const groups = new Map(
    Object.keys(CATALOG_GROUPS).map((g) => [g, [] as CatalogEntry[]]),
  );
  for (const [name, preset] of Object.entries(view.presets).sort(
    ([, a], [, b]) => a.title.localeCompare(b.title),
  )) {
    // Retired definitions still serve stored credentials and permission names.
    if (preset.replaced_by && view.presets[preset.replaced_by]) continue;
    if (name === PERIMETER) continue;
    const group = preset.group ?? "api";
    if (!groups.has(group)) groups.set(group, []);
    groups.get(group)!.push({
      name,
      title: preset.title,
      connections: counts.get(name) ?? 0,
      aliases: aliases.get(name) ?? "",
    });
  }
  const common: CatalogEntry[] = [];
  for (const entries of groups.values())
    for (let i = entries.length - 1; i >= 0; i--) {
      if (COMMON_PRESETS.includes(entries[i].name))
        common.push(...entries.splice(i, 1));
    }
  common.sort(
    (a, b) => COMMON_PRESETS.indexOf(a.name) - COMMON_PRESETS.indexOf(b.name),
  );
  const rank = (name: string) => {
    const index = PRESET_ORDER.indexOf(name);
    return index < 0 ? PRESET_ORDER.length : index;
  };
  for (const entries of groups.values())
    entries.sort(
      (a, b) => rank(a.name) - rank(b.name) || a.title.localeCompare(b.title),
    );
  return [
    ...(common.length
      ? [{ group: "common", title: "Popular", presets: common }]
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

type CatalogEntry = {
  name: string;
  title: string;
  connections: number;
  aliases: string;
};
type Slot = { value: string } & { [key: string]: string | undefined };

export function apiSettings(view: View, name?: string): ApiSettings {
  const slot: Partial<Slot> =
    name === undefined
      ? {}
      : ((setupOf(connections(view)[name])?.slots as Slot[] | undefined)?.[0] ??
        {});
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
    header: auth === "header" ? slot.header! : "X-API-Key",
    prefix: auth === "header" ? (slot.prefix ?? "") : "",
    query: slot.query ?? "api_key",
  };
}

export function apiSlot(
  {
    url: raw = "",
    auth,
    header = "",
    prefix = "",
    query = "",
  }: Partial<ApiSettings>,
  value = "token",
): { [key: string]: string } {
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
export function apiSetup(view: View, name: string, index = 0) {
  const slot = (
    setupOf(connections(view)[name])?.slots as Slot[] | undefined
  )?.[index];
  if (!slot) return null;
  const placeholder = view.fields?.[name]?.find(
    (f) => f.name === slot.value,
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
    connection: name,
    credential: slot.value,
    placeholder,
    address: slot.origin + (slot.path === "/" ? "" : (slot.path ?? "")),
    header: slot.header,
    query: slot.query,
    value,
    placement,
  };
}

export function codexSetup(view: View, name: string): string | null {
  if (connections(view)[name]?.preset !== "codex") return null;
  const setup = apiSetup(view, name);
  if (!setup) return null;
  return `model = "gpt-6.1-sol"
model_provider = "perimeter_chatgpt"

[model_providers.perimeter_chatgpt]
name = "ChatGPT through Perimeter"
base_url = "https://api.openai.com/v1"
experimental_bearer_token = ${JSON.stringify(setup.placeholder)}
wire_api = "responses"
requires_openai_auth = false
supports_websockets = false`;
}

// Enough of a key to tell keys apart without showing it.
const KEY_PREFIX_LENGTH = 8;
export const apiKeyLabel = (key: { name: string; key: string }) =>
  `${key.name || "Unnamed key"} · ${key.key.slice(0, KEY_PREFIX_LENGTH)}…`;
// Which of the owner's Tinfoil API keys a connection uses is kept as a short hash
// in owner-only data, so the key can be shown without storing it again.
const TINFOIL_KEYS = ["data", "tinfoil_keys"];
const FINGERPRINT_LENGTH = 16;
export const keyFingerprint = (key: string) =>
  bytesToHex(sha256(utf8ToBytes(key))).slice(0, FINGERPRINT_LENGTH);
export const tinfoilKeyOf = (view: View, connection: string) => {
  const keys = view.config.data?.tinfoil_keys as { [name: string]: Json };
  const value = keys?.[connection];
  return typeof value === "string" ? value : undefined;
};
const tinfoilKeyChange = (connection: string, key: string): Change => ({
  path: [...TINFOIL_KEYS, connection],
  value: keyFingerprint(key),
});

export function tinfoilSetup(view: View, name: string) {
  const kind = kindOf(connections(view)[name]);
  if (kind !== "tinfoil" && kind !== "tinfoil-mcp") return;
  const mcp = kind === "tinfoil-mcp";
  return { mcp, url: `https://${name}.perimeter/${mcp ? "mcp" : "v1"}` };
}

// Bunkers reach these connections by name and send no password; the Perimeter adds it upstream.
export function serviceURL(view: View, name: string) {
  const c = connections(view)[name];
  const kind = kindOf(c);
  if (kind === "ssh" || kind === "sftp") return `${kind}://${name}.perimeter`;
  if (kind === "mcp") return `https://${name}.perimeter/mcp`;
  const url = setupOf(c)?.url;
  if (typeof url !== "string" || !URL.canParse(url)) return;
  const u = new URL(url);
  if (u.protocol.startsWith("http")) return;
  u.host = name + ".perimeter";
  u.port = u.password = "";
  return u.href;
}

const unusedName = (view: View, base: string, suffixes: string[] = [""]) => {
  let name = base;
  for (
    let i = 2;
    suffixes.some((suffix) => Object.hasOwn(connections(view), name + suffix));
    i++
  )
    name = `${base}-${i}`;
  return name;
};

const PACKAGE_REGISTRY_HOSTS = [
  "downloads.claude.ai",
  "registry.npmjs.org",
  "pypi.org",
  "files.pythonhosted.org",
  "archive.ubuntu.com",
  "*.archive.ubuntu.com",
  "security.ubuntu.com",
  "ports.ubuntu.com",
  "crates.io",
  "static.crates.io",
  "index.crates.io",
  "proxy.golang.org",
  "sum.golang.org",
  "cache.nixos.org",
];
// Ubuntu's repositories are served over plain HTTP.
const PACKAGE_REGISTRY_PORTS = [80, 443];

function onboardingChanges(
  view: View,
  choices: OnboardingChoices,
): { changes: Change[]; credentials: { [connection: string]: Credentials } } {
  const network = unusedName(view, "network");
  const policy = networkRuleName(view);
  const changes = sourceChanges({
    data: { onboarding: { completed: true } },
    // Label guardrails are recorded but never enforced in this release.
    lattices: { confidentiality: false, integrity: false },
    allow_networks: [],
    connections: {
      [network]: {
        preset: "tcp",
        contents: "anyone",
        strangers: true,
        sends: "anyone",
        tcp: { hosts: ["*"] },
      },
    },
    policies: { [policy]: KNOWN_ONLY_RULE },
  });
  changes.push({
    path: ["default_access", network],
    value: { level: choices.network },
  });
  if (choices.registries) {
    const registries = unusedName(view, "package-registries");
    changes.push(
      ...sourceChanges({
        connections: {
          [registries]: {
            preset: "tcp",
            contents: "anyone",
            strangers: true,
            sends: "anyone",
            tcp: {
              hosts: PACKAGE_REGISTRY_HOSTS,
              ports: PACKAGE_REGISTRY_PORTS,
            },
          },
        },
      }),
      { path: ["default_access", registries], value: { level: "allow" } },
    );
  }
  const credentials: { [connection: string]: Credentials } = {};
  const approveTools: string[] = [];
  const add = (
    connection: string,
    preset: string,
    level: GrantLevel,
    credential?: string,
  ) => {
    const fields = setupFields(view, preset);
    const key = fields.find((f) => f.credential && !f.oauth)?.key;
    const values = Object.fromEntries(
      fields.map((f) => [f.key, readField(f, fieldText(f, f.default))]),
    );
    if (key && credential !== undefined) values[key] = credential;
    const added = edits.addConnection(view, preset, {
      name: connection,
      values,
      answers: view.presets[preset].defaults,
    });
    changes.push(...added.changes, {
      path: ["default_access", connection],
      value: { level },
    });
    credentials[connection] = added.credentials;
    const kind = Object.keys(view.presets[preset].connection ?? {})[0];
    if (PINNED_KINDS.includes(kind)) approveTools.push(connection);
  };
  for (const { preset, level, credential } of choices.connections) {
    if (preset !== "tinfoil") {
      add(unusedName(view, preset), preset, level, credential);
      continue;
    }
    const key = credential?.trim();
    if (!key) throw new Error("Choose a Tinfoil API key.");
    const name = unusedName(view, "tinfoil", ["", "-websearch"]);
    add(name, "tinfoil", level, key);
    add(`${name}-websearch`, "tinfoil_websearch", level, key);
    changes.push(
      tinfoilKeyChange(name, key),
      tinfoilKeyChange(`${name}-websearch`, key),
    );
  }
  if (approveTools.length)
    changes.push({ path: SETUP_TOOLS, value: approveTools });
  return { changes, credentials };
}

// MCP connections chosen during setup have their first reported tools approved
// without a review; later changes to those tools still wait for the owner.
const SETUP_TOOLS = ["data", "onboarding", "approve_tools"];
const PINNED_KINDS = ["mcp", "tinfoil-mcp"];
export function setupToolApprovals(view: View): Change[] {
  const listed = (view.config.data?.onboarding as { approve_tools?: Json })
    ?.approve_tools;
  const names = Array.isArray(listed)
    ? listed.filter((name): name is string => typeof name === "string")
    : [];
  const approved = (name: string) =>
    setupOf(connections(view)[name])?.pin != null;
  const ready = names.filter(
    (name) => view.status[name]?.details?.pin != null && !approved(name),
  );
  // A removed or already approved connection needs no first approval.
  const settled = names.filter(
    (name) => !connections(view)[name] || approved(name),
  );
  if (!ready.length && !settled.length) return [];
  const waiting = names.filter(
    (name) => !ready.includes(name) && !settled.includes(name),
  );
  return [
    ...ready.flatMap((name) => edits.approveTools(view, name)),
    waiting.length
      ? { path: SETUP_TOOLS, value: waiting }
      : { path: SETUP_TOOLS, delete: true },
  ];
}

const KNOWN_ONLY_RULE =
  'package sentinel\n\nallow if input.facts.operation != null\n\nallow if input.facts.kind == "admission"\n';
const OPEN_RULE = "package sentinel\n\nallow := true\n";
// Allow rules add up, so the network rule lives in one policy that each edit replaces.
const networkRuleName = (view: View) => {
  const policies = view.config.policies ?? {};
  const managed = Object.keys(policies).find(
    (k) =>
      [KNOWN_ONLY_RULE, OPEN_RULE].includes(policies[k]) ||
      /deny contains "(Network access is disabled|This request has no recognized policy operation)/.test(
        policies[k],
      ),
  );
  if (managed) return managed;
  let name = "network-default";
  for (let i = 2; Object.hasOwn(policies, name); i++)
    name = `network-default-${i}`;
  return name;
};
// Raw TCP: the Monitor only sees host and port, never what is sent.
export const isRawNetwork = (view: View, name: string) =>
  connections(view)[name]?.preset === "tcp";
export const scopeText = (
  view: View,
  name: string,
  scope: Record<string, unknown> = {},
) =>
  isRawNetwork(view, name) && scope.host
    ? `${scope.host}${scope.port ? `:${scope.port}` : ""}`
    : Object.entries(scope).map(
        ([k, v]) => `${k}: ${typeof v === "string" ? v : JSON.stringify(v)}`,
      );
export const networkingOpen = (view: View) =>
  (view.config.allow_networks ?? []).includes("0.0.0.0/0") &&
  Object.values(view.config.policies ?? {}).includes(OPEN_RULE);

const NAME = /^[a-zA-Z0-9][a-zA-Z0-9-]*$/;
// Identities may not name a missing connection, so every agent's access is included.
const connectionPaths = (view: View, name: string) => [
  ["connections", name],
  ["policies", name],
  ["default_access", name],
  [...TINFOIL_KEYS, name],
  ...Object.keys(identities(view)).map((agent) => [
    "identities",
    agent,
    "connections",
    name,
  ]),
  ...Object.entries(view.config.groups ?? {})
    .filter(([, group]) => group.connections?.[name])
    .map(([group]) => ["groups", group, "connections", name]),
];
// Each edit returns the source changes for POST /policy/edits.
export const edits = {
  setNetworkingOpen: (view: View, open: boolean): Change[] => {
    const tcp = Object.entries(connections(view))
      .filter(([, c]) => c.preset === "tcp")
      .map(([name]) => name);
    return [
      { path: ["allow_networks"], value: open ? ["0.0.0.0/0", "::/0"] : [] },
      {
        path: ["policies", networkRuleName(view)],
        value: open ? OPEN_RULE : KNOWN_ONLY_RULE,
      },
      ...tcp.map((name) => ({
        path: ["default_access", name],
        value: { level: open ? "allow" : "off" },
      })),
    ];
  },
  addIdentity: (name: string, key: string, device: boolean) =>
    sourceChanges({
      identities: {
        [name]: {
          key: key.trim(),
          ...(device && { groups: [DEVICE] }),
          connections: {},
        },
      },
    }),
  removeAgent: (name: string): Change[] => [
    { path: ["identities", name], delete: true },
  ],
  renameAgent(view: View, from: string, to: string): Change[] {
    if (!NAME.test(to) || to !== to.toLowerCase())
      throw new Error(
        "Name this bunker using lowercase letters, numbers, and hyphens.",
      );
    if (Object.hasOwn(identities(view), to))
      throw new Error("This name is already in use.");
    return [{ path: ["identities", to], from: ["identities", from] }];
  },
  // Saved credentials and rules follow the connection to its new name.
  renameConnection(view: View, from: string, to: string): Change[] {
    if (!NAME.test(to))
      throw new Error("Name this connection using letters, numbers, and hyphens.");
    if (Object.hasOwn(connections(view), to))
      throw new Error(
        "A connection with that name already exists. Choose another name.",
      );
    return [
      ...connectionPaths(view, from).map((path) => ({
        path: [...path.slice(0, -1), to],
        from: path,
      })),
      ...Object.entries(identities(view)).flatMap(([name, identity]) =>
        Object.entries(identity.rules ?? {})
          .filter(([, rule]) => rule.connection === from)
          .map(([id]) => ({
            path: ["identities", name, "rules", id, "connection"],
            value: to,
          })),
      ),
    ];
  },
  setRoutes: (view: View, name: string, routes: boolean): Change[] => [
    {
      path: ["identities", name, "groups"],
      value: [
        ...(identities(view)[name]?.groups ?? []).filter(
          (group) => group !== DEVICE,
        ),
        ...(routes ? [DEVICE] : []),
      ],
    },
  ],
  // The bunkers connection is added by the first access set to it.
  setLevel: (
    view: View,
    name: string,
    connection: string,
    level: GrantLevel,
  ): Change[] => [
    ...(connection === BUNKERS && !connections(view)[BUNKERS]
      ? edits.addConnection(view, BUNKERS, {
          name: BUNKERS,
          values: {},
          answers: view.presets[BUNKERS].defaults,
        }).changes
      : []),
    ...edits.setAccess(name, connection, { level }),
  ],
  // An action set to null inherits again.
  setAccess: (
    name: string,
    connection: string,
    access: {
      level?: GrantLevel;
      actions?: { [action: string]: Mode | null };
      effects?: { [effect: string]: Mode | null };
    },
  ) =>
    sourceChanges({
      identities: { [name]: { connections: { [connection]: access } } },
    }),
  setMatchOnly: (name: string, on: boolean): Change[] => [
    on
      ? { path: ["connections", name, "match_only"], value: true }
      : { path: ["connections", name, "match_only"], delete: true },
  ],
  setEffect: (effect: string, mode?: Mode): Change[] => [
    {
      path: ["access", "effects", effect],
      ...(mode ? { value: mode } : { delete: true }),
    },
  ],
  // Access to the Perimeter itself stays the identity's own.
  copySettings: (view: View, from: string, name: string): Change[] => {
    const source = identities(view)[from] ?? {},
      target = identities(view)[name] ?? {};
    const access = (identity: Identity, perimeter: boolean) => ({
      connections: Object.entries(identity.connections ?? {}).filter(
        ([connection]) => (connection === PERIMETER) === perimeter,
      ),
      rules: Object.entries(identity.rules ?? {}).filter(
        ([, rule]) => (rule.connection === PERIMETER) === perimeter,
      ),
      groups: (identity.groups ?? []).filter(
        (group) => (group === DEVICE) === perimeter,
      ),
    });
    const copied = access(source, false),
      kept = access(target, true);
    return Object.entries({
      connections: Object.fromEntries([
        ...copied.connections,
        ...kept.connections,
      ]),
      rules: Object.fromEntries([...copied.rules, ...kept.rules]),
      groups: [...copied.groups, ...kept.groups],
    }).map(([key, value]) => ({
      path: ["identities", name, key],
      value: clone(value),
    }));
  },
  removeRule: (name: string, id: string): Change[] => [
    { path: ["identities", name, "rules", id], delete: true },
  ],
  approveTools: (view: View, name: string) =>
    sourceChanges({
      connections: {
        [name]: {
          [kindOf(connections(view)[name])!]: {
            pin: view.status[name].details!.pin,
          },
        },
      },
    }),
  // Replaces a Tinfoil connection's key with another of the owner's keys.
  setTinfoilKey: (connection: string, field: string, key: string) => ({
    changes: [tinfoilKeyChange(connection, key)],
    credentials: { [connection]: { [field]: key } },
  }),
  removeConnection: (view: View, connection: string): Change[] =>
    connectionPaths(view, connection).map((path) => ({ path, delete: true })),
  addConnection(
    view: View,
    preset: string,
    {
      name,
      values,
      answers,
      oauth = [],
    }: {
      name: string;
      values: { [key: string]: Json };
      answers: ConnectionAnswers;
      oauth?: string[];
    },
  ): { changes: Change[]; credentials: Credentials } {
    const c = view.presets[preset];
    name = name.trim();
    if (!name) throw new Error("Name this connection.");
    if (Object.hasOwn(connections(view), name))
      throw new Error(
        "A connection with that name already exists. Choose another name.",
      );
    const fields = setupFields(view, preset);
    // Only the non-secret values fill a preset's setup; credentials are stored apart from the connection.
    const plainValues = Object.fromEntries(
      fields.filter((f) => !f.secret).map((f) => [f.key, values[f.key]]),
    );
    const setup = c.connection && filled(c.connection, plainValues);
    const connection = {
      preset,
      ...answers,
      ...(JSON.stringify(setup) !== JSON.stringify(c.connection) && setup),
    };
    const credentials: Credentials = {};
    for (const f of fields) {
      const value =
        f.oauth && oauth.includes(f.key)
          ? {
              oauth: filled(f.oauth, {
                ...values,
                monitor_host_id: view.host_id,
              }),
            }
          : f.compose
            ? composed(
                f.compose,
                fields.filter((c) => !paths(c).length),
                values,
              )
            : f.secret && values[f.key] === ""
              ? null
              : values[f.key];
      if (!f.credential)
        for (const path of paths(f)) putPath(connection, path, value, setup);
      else if (value !== null) credentials[f.key] = value;
    }
    return {
      changes: sourceChanges({ connections: { [name]: connection } }),
      credentials,
    };
  },
  addCustomApi(
    view: View,
    {
      name,
      api,
      token,
      agent,
      level,
      answers,
    }: {
      name: string;
      api: Partial<ApiSettings>;
      token: string;
      agent?: string;
      level?: GrantLevel;
      answers: ConnectionAnswers;
    },
  ): { changes: Change[]; credentials: Credentials } {
    name = name.trim();
    if (!NAME.test(name))
      throw new Error("Name this connection using letters, numbers, and hyphens.");
    if (Object.hasOwn(connections(view), name))
      throw new Error(
        "A connection with that name already exists. Choose another name.",
      );
    const http = { slots: [apiSlot(api)] };
    const body: { [key: string]: unknown } = {
      connections: {
        [name]: { preset: "custom_api", ...answers, http },
      },
    };
    if (agent)
      body.identities = { [agent]: { connections: { [name]: { level } } } };
    return {
      changes: sourceChanges(body),
      credentials: token.trim() ? { token } : {},
    };
  },
  saveConnection(
    view: View,
    name: string,
    {
      api,
      values = {},
      client = {},
      credentials = {},
    }: {
      api?: Partial<ApiSettings>;
      values?: { [key: string]: Json };
      client?: { [key: string]: Json | undefined };
      credentials?: {
        [key: string]: { mode: "keep" | "replace"; value?: Json };
      };
    },
  ): { changes: Change[]; credentials: Credentials } {
    const c = connections(view)[name],
      updated = clone(c),
      changed = new Set<string>(),
      stored: Credentials = {};
    const set = (path: string[], value: unknown) => {
      if (same(atPath(c, path), value)) return;
      putPath(updated, path, value);
      const n = path.findIndex(
        (_, i) => i > 0 && Array.isArray(atPath(updated, path.slice(0, i))),
      );
      changed.add(JSON.stringify(n < 0 ? path : path.slice(0, n)));
    };
    if (c.preset === "custom_api" && api && !same(api, apiSettings(view, name)))
      set(
        ["http", "slots"],
        [apiSlot(api, (setupOf(c)?.slots as Slot[] | undefined)?.[0]?.value)],
      );
    for (const f of plainFields(view, name))
      if (Object.hasOwn(values, f.key) && !same(f.value, values[f.key]))
        for (const path of paths(f)) set(path, values[f.key]);
    for (const f of credentialFields(view, name)) {
      const { mode, value } = credentials[f.key] ?? {};
      const whole =
        f.compose && composed(f.compose, clientFields(view, name), client);
      if (whole) stored[f.key] = whole;
      else if (mode === "replace") {
        if (value === "")
          throw new Error(
            `Enter a value for ${f.label}, or cancel the replacement.`,
          );
        stored[f.key] = value!;
      }
    }
    return {
      changes: [...changed].map((key) => {
        const path = JSON.parse(key);
        return {
          path: ["connections", name, ...path],
          value: atPath(updated, path),
        };
      }),
      credentials: stored,
    };
  },
};

// CAM serves this UI through the CLI's attested SSH tunnel. Its session token
// authorizes browser requests; private owner and storage keys never enter JS.
export function localOwnerClient({
  token,
  fetch,
}: {
  token: string;
  fetch: typeof globalThis.fetch;
}): OwnerApi {
  const json = ownerJSON(fetch, "/api", { "X-Tinfoil-Session": token });
  return ownerApi(async (method, path, body, signal) => {
    if (path.split("?")[0] === "/unlock")
      throw new OwnerError(
        "Run tinfoil perimeter open NAME again to unlock over attested SSH.",
        423,
      );
    return json(method, path, body, signal);
  });
}
