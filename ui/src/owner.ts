// The owner API client and the request, permission and account semantics shared by
// Monitor's own app and embedding dashboards. The server remains the authority: these
// functions shape edits and describe its answers.

export type Json =
  null | boolean | number | string | Json[] | { [key: string]: Json };
export type Level = "off" | "read" | "ask" | "allow";
export type Mode = "off" | "ask" | "allow";
export type PolicyPreset = "open" | "known_only" | "offline";
export type Audience = "me" | "team" | "anyone";
export type Trust = "trusted" | "untrusted";
export type Decision = "once" | "save" | "deny";
export type ApprovalAnswer = {
  by: "owner";
  decision: Decision;
  reason?: string;
  time: string;
};
export type RequestState =
  "pending" | "allowed" | "approved" | "refused" | "denied" | "expired" | "outdated";
export type Access = {
  level: Level;
  actions?: Record<string, Mode>;
  effects?: Record<string, Mode>;
};
export type EffectScope = { agent?: string; account?: string };
export type Requirement = { id?: string; message: string };
export type Rule = {
  account: string;
  action: string;
  operation?: string;
  definition?: string;
  scope?: Record<string, Json>;
  requirements?: Requirement[];
};
export type Identity = {
  key: string;
  sandbox?: { source: string; instance_id: string };
  effects?: Record<string, Mode>;
  routes?: boolean;
  accounts?: Record<string, Access>;
  rules?: Record<string, Rule>;
};
export type Account = {
  preset: string;
  effects?: Record<string, Mode>;
  contents: Audience;
  sends: Audience;
  strangers?: boolean;
  connections?: Record<string, Record<string, { [key: string]: Json }>>;
};
export type PresetField = {
  key: string;
  label: string;
  hint?: string;
  help?: string;
  secret?: boolean;
  multiline?: boolean;
  json?: boolean;
  list?: boolean;
  edit_only?: boolean;
  default?: Json;
  path?: string[];
  paths?: string[][];
  oauth?: Json;
};
export type PresetAction = { title: string; effects?: string[] };
export type Preset = {
  title: string;
  group?: string;
  warning?: string;
  replaced_by?: string;
  defaults?: { contents?: Audience; sends?: Audience; strangers?: boolean };
  fields?: PresetField[];
  connections?: Json;
  actions?: Record<string, PresetAction>;
  operations?: Record<string, { action: string; effects?: string[] }>;
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
export type View = {
  generation: number;
  catalog_id?: string;
  host_key: string;
  host_id: string;
  ca: string;
  config: {
    allow_paid_inference?: boolean;
    effects?: Record<string, Mode>;
    default_access?: Record<string, Access>;
    data?: { [key: string]: Json };
    identities?: Record<string, Identity> | null;
    accounts?: Record<string, Account> | null;
    policies?: Record<string, string> | null;
    lattices?: { confidentiality?: boolean; integrity?: boolean };
    allow_networks?: string[] | null;
  };
  labels: Record<string, Label>;
  status: Record<string, ConnectionStatus>;
  fields: Record<
    string,
    { path: string[]; kind: string; placeholder?: string; account?: string }[]
  >;
  presets: Record<string, Preset>;
  vocabulary: Record<string, { change?: boolean; ask?: boolean }>;
};
export type RequestDetails = {
  http?: { method: string; host: string; path: string };
  mcp?: { tool: string };
  smtp?: { to: string[] };
  mail?: { subject?: string };
  imap?: { command: string; args: string };
  policy?: { source_diff: string; effective_diff?: string };
};
export type RequestRecord = {
  invalid?: boolean;
  summary?: boolean;
  id: string;
  state: RequestState;
  time: string;
  expires?: string;
  deny?: string[];
  requirements?: Requirement[];
  grant?: { [key: string]: Json };
  definition?: string;
  savingDecision?: boolean;
  reviews?: ApprovalAnswer[];
  segment?: string;
  facts: {
    title?: string;
    principal: { name: string };
    account: string;
    service?: string;
    operation?: { id: string; action: string; effects?: string[] };
    parameters?: { [key: string]: Json };
    details?: RequestDetails;
  };
};
export type Change = { path: string[]; value?: Json; delete?: boolean };
export type PolicyProposal = {
  id: string;
  digest: string;
  created_at: string;
  reason: string;
  proposer: { key?: string; name: string };
  proposer_kind: "owner_api" | "trusted_device" | "sandbox";
  connection: string;
  affected: { kind: "connection"; target: string }[];
  changes: Change[];
  source_diff: string;
  stale?: boolean;
};
export type PolicyProposalInput = {
  reason: string;
  idempotency_key?: string;
} & (
  | { changes: Change[]; source?: never; delete?: never }
  | { source: string; delete?: string[][]; changes?: never }
);
export type Snapshot = { view: View; requests: RequestRecord[]; proposals?: PolicyProposal[] };
export type PolicyDiff = { source_diff: string; effective_diff: string };
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
  unlock(generation?: number, signal?: AbortSignal): Promise<View>;
  onboard(
    view: View,
    preset: PolicyPreset,
    signal?: AbortSignal,
    options?: { allowPaidInference?: boolean; tinfoilApiKey?: string },
  ): Promise<View>;
  edit(changes: Change[], signal?: AbortSignal): Promise<View>;
  proposals(signal?: AbortSignal): Promise<PolicyProposal[]>;
  proposal(id: string, signal?: AbortSignal): Promise<PolicyProposal>;
  submitProposal(input: PolicyProposalInput, signal?: AbortSignal): Promise<PolicyProposal[]>;
  approveProposal(proposal: PolicyProposal, signal?: AbortSignal): Promise<View>;
  rejectProposal(proposal: PolicyProposal, signal?: AbortSignal): Promise<null>;
  decide(id: string, decision: Decision, signal?: AbortSignal): Promise<null>;
  label(
    name: string,
    label: { trust: Trust; audience: Audience },
    signal?: AbortSignal,
  ): Promise<View>;
  policy(
    effective?: boolean,
    signal?: AbortSignal,
  ): Promise<{ source: string; effective?: string }>;
  previewPolicy(source: string, signal?: AbortSignal): Promise<PolicyDiff>;
  applyPolicy(source: string, signal?: AbortSignal): Promise<View>;
  signIn(
    account: string,
    path: string[],
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
  icons(signal?: AbortSignal): Promise<(preset: string) => ConnectorIcon>;
};
/** An authenticated owner socket that carries whole messages. */
export type OwnerChannel = {
  send(message: Uint8Array): void;
  receive(): Promise<Uint8Array>;
  close(): void;
};
/** One owner call over a channel: the parsed reply, or an OwnerError. */
export type OwnerRpc = (
  method: "GET" | "POST",
  path: string,
  body: unknown,
  generation: number,
  signal?: AbortSignal,
) => Promise<unknown>;
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
// Only builds holding a sandbox signer can open a shell.
export type ShellOpener = (
  open: ShellOpen,
  handlers: ShellHandlers,
  signal: AbortSignal,
) => Promise<Shell>;
export type ConnectorIcon = { src: string; dark?: string };
export type IconManifest = { [preset: string]: { src: string; dark?: string } };
export type ActionNode = {
  key: string;
  title: string;
  action: boolean;
  effects: string[];
  total: number;
  children: ActionNode[];
};
export type AccessNode = Omit<ActionNode, "children"> & {
  own: Mode | null;
  inherited: Mode;
  overrides: number;
  children: AccessNode[];
};
export type Review = {
  key: string;
  name: string;
  state?: string;
  error?: string;
  blocked: number;
  added: number;
  changed: number;
  removed: number;
  changes: string[];
  tools: McpTool[];
  previousTools: McpTool[];
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
export type CredentialField = PresetField & {
  path: string[];
  kind: string;
  account?: string;
  status: string;
  signIn: boolean;
  credential?: { oauth: Json };
};
export type ApiSettings = {
  url: string;
  auth: "bearer" | "header" | "query";
  header: string;
  prefix: string;
  query: string;
};
export type AccountAnswers = {
  contents: Audience;
  strangers: boolean;
  sends: Audience;
};

export const LEVELS: { [L in Level]: string } = {
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
export const AUDIENCES: { [A in Audience]: string } = {
  me: "Only me",
  team: "My team",
  anyone: "Anyone",
};
export const TRUSTS: { [T in Trust]: string } = {
  trusted: "Trusted",
  untrusted: "Untrusted",
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
export const GENERIC_PRESETS = ["web", "ssh", "tcp", "custom_api", "mcp"];
export const CREDENTIAL_STATUS: { [kind: string]: string } = {
  "oauth-required": "Sign-in required",
  unset: "Not configured",
};
export const POLICY_PRESETS: Record<
  PolicyPreset,
  { title: string; description: string; recommended?: boolean }
> = {
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
const LOOPBACK = ["localhost", "127.0.0.1", "[::1]"];

// Human input preserves UTF-8 bytes, including whitespace. Old canonical
// base64 32-byte keys keep their original meaning; base64 is only the wire format.
export function encodeOwnerKey(input: string): string {
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
  status: number;
  constructor(message: string, status: number) {
    super(message);
    this.status = status;
  }
}

// Keep validators and parsed responses in this authenticated client's memory,
// never in browser storage. Bound the cache when navigating through audit details.
function ownerJSON<O extends { method?: string; headers?: HeadersInit }>(
  fetch: (url: string, options: O) => Promise<Response>,
) {
  const cache = new Map<string, { tag: string; value: unknown }>();
  return async (url: string, options: O): Promise<unknown> => {
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
    throw new Error("Invalid monitor endpoint.");
  }
  if (
    url.protocol !== "https:" &&
    !(url.protocol === "http:" && LOOPBACK.includes(url.hostname))
  )
    throw new Error("The monitor endpoint must use HTTPS.");
  if (url.username || url.password || url.search || url.hash)
    throw new Error("Invalid monitor endpoint.");
  return url.href.replace(/\/$/, "");
}

// Without an endpoint, requests go to the page's own origin; any given endpoint, even an empty one, must be a valid URL.
// A remote owner API needs HTTPS. The key is never sent on a redirect.
export function ownerClient({
  endpoint,
  key,
  generation,
  fetch = (...args) => globalThis.fetch(...args),
}: {
  endpoint?: string;
  key: string;
  generation?: number;
  fetch?: typeof globalThis.fetch;
}): OwnerApi {
  if (typeof key === "string" && key.trim().startsWith("{"))
    throw new Error(
      "Signing credentials require tinfoil monitor open and its attested connection.",
    );
  const base = endpoint === undefined ? "" : endpointBase(endpoint);
  const json = ownerJSON<RequestInit>(fetch);
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

const ROLLBACK =
  "The monitor state is older than the last state you saw. Restore the latest monitor state before continuing.";

// With a known generation, an older view is a rollback, and a locked monitor unlocks at that minimum.
export function ownerApi(
  request: Request,
  generation?: number,
  base = "",
  remember?: (generation: number) => void,
): OwnerApi {
  let minimum = generation;
  let catalog: { id: string; presets: Record<string, Preset> } | undefined;
  const checked = (view: View) => {
    if (minimum !== undefined && view) {
      if (view.generation < minimum) throw new OwnerError(ROLLBACK, 409);
      remember?.(view.generation);
      minimum = view.generation;
    }
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
  const unlock = (at = minimum ?? 0, signal?: AbortSignal) =>
    snapshot("POST", "/unlock", { generation: at }, signal);
  return {
    async read(signal) {
      const path = "/requests";
      const [view, requests, proposals] = await Promise.all([
        snapshot("GET", "/", undefined, signal),
        get<RequestRecord[] | null>(path, signal),
        get<PolicyProposal[]>("/policy/proposals", signal),
      ]).catch(async (err) => {
        if (err.status !== 423 || minimum === undefined) throw err;
        return [
          await unlock(minimum, signal),
          await get<RequestRecord[] | null>(path, signal),
          await get<PolicyProposal[]>("/policy/proposals", signal),
        ] as const;
      });
      return { view: checked(view), requests: requests ?? [], proposals };
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
    proposals: (signal) => get("/policy/proposals", signal),
    proposal: (id, signal) => get(`/policy/proposals/${encodeURIComponent(id)}`, signal),
    submitProposal: (input, signal) => post("/policy/proposals", input, signal),
    approveProposal: (proposal, signal) => snapshot(
      "POST", `/policy/proposals/${encodeURIComponent(proposal.id)}/approve`,
      { digest: proposal.digest }, signal,
    ),
    rejectProposal: (proposal, signal) => post(
      `/policy/proposals/${encodeURIComponent(proposal.id)}/reject`,
      { digest: proposal.digest }, signal,
    ),
    decide: (id, decision, signal) =>
      post(`/requests/${encodeURIComponent(id)}`, { decision }, signal),
    label: (name, label, signal) =>
      snapshot("POST", `/labels/${encodeURIComponent(name)}`, label, signal),
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
    icons: async (signal) => {
      const manifest = await get<IconManifest>(ICON_MANIFEST, signal);
      return (preset) => connectorIcon(manifest, preset, base);
    },
  };
}

// Monitor serves connector icons with its app. The manifest names each preset's file and optional dark variant;
// a preset without one shows the custom icon. assets is the URL prefix of the app's build.
const ICON_MANIFEST = "/app/icons/manifest.json";
export function connectorIcon(
  manifest: IconManifest | undefined,
  preset: string,
  base = "",
  assets = `${base}/app/`,
): ConnectorIcon {
  if (preset === "codex") preset = "openai";
  if (preset === "openrouter") preset = "open_router";
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
        value: clone(change.value),
        enumerable: true,
        configurable: true,
        writable: true,
      });
  }
  return target;
}

// previewChanges shows ordinary configuration edits before the server confirms them.
export function previewChanges(view: View, changes: Change[]): View {
  // Fork only edited paths. Large preset catalogs remain shared with the confirmed view.
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
// Matches the device names assigned by owner enrollment.
export const isDevice = (name: string) => /^device-[0-9a-f]{16}$/.test(name);
export const onboarded = (view: View) =>
  (view.config.data?.onboarding as { completed?: Json } | undefined)
    ?.completed === true;
const accounts = (view: View) => view.config.accounts ?? {};
export const lattices = (view: View) => ({
  confidentiality: view.config.lattices?.confidentiality ?? true,
  integrity: view.config.lattices?.integrity ?? false,
});
const UNKNOWN_PRESET: Preset = { title: "Connection" };
export const presetOf = (view: View, account: string): Preset =>
  view.presets[accounts(view)[account]?.preset] ?? UNKNOWN_PRESET;
export const connectionName = (account: string, key: string) =>
  key ? `${account}-${key}` : account;
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
const esc = (s: unknown) =>
  String(s ?? "").replace(/[&<>"']/g, (c) => `&#${c.charCodeAt(0)};`);

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
  r.facts?.account;
// Requirements worth showing. "ask" is what pending already means, and the
// audience/trust label gates are a data-flow feature nobody set up on
// purpose; what remains is effect overrides and unrecognised operations.
const quietRequirements = new Set<string | undefined>([
  "ask",
  "audience",
  "trust",
]);
export const reasons = (r: { requirements?: Requirement[] }) =>
  (r.requirements ?? [])
    .filter((requirement) => !quietRequirements.has(requirement.id))
    .map((requirement) => requirement.message);
// A pending request past its deadline is expired, even before the next poll says so.
export const stateAt = (r: RequestRecord, now: number): RequestState =>
  r.state === "pending" && r.expires && Date.parse(r.expires) <= now
    ? "expired"
    : r.state;
export const needsOwner = (r: RequestRecord) => r.state === "pending";
export const isConnectionProposalRecord = (r: RequestRecord) =>
  r.facts.service === "policy-proposal" ||
  (r.facts.title === "Change connection" && !!r.facts.details?.policy);
export function reviewStatus(r: RequestRecord): string {
  const last = r.reviews?.at(-1);
  if (r.state === "pending") return "Needs your approval";
  if (
    (last || r.savingDecision) &&
    (r.state === "approved" || r.state === "denied")
  ) {
    const outcome =
      r.state === "approved"
        ? "Approved"
        : isConnectionProposalRecord(r)
          ? "Rejected"
          : "Denied";
    return `${outcome} by you`;
  }
  return r.state.charAt(0).toUpperCase() + r.state.slice(1);
}
export const pendingSoonest = (records: RequestRecord[]) =>
  records
    .filter((r) => r.state === "pending")
    .sort((a, b) => Date.parse(a.expires!) - Date.parse(b.expires!));
export function ordered(records: RequestRecord[], dismissed: string[] = []) {
  const hidden = new Set(dismissed);
  const priority = (r: RequestRecord) =>
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
  `${grantText(r.facts?.operation?.id, r.grant, r.facts?.parameters)} on future attempts. Retry this request after saving.`;
// Saving a rule never resumes the original call; it also works after a timeout.
export function decisions(
  r: RequestRecord,
  now?: number,
): { once?: boolean; save?: boolean; deny?: boolean; dismiss?: boolean } {
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
const WAIVED: { [id: string]: string } = {
  ask: "Ask",
  audience: "Confidentiality guardrail",
  trust: "Integrity guardrail",
};
const EFFECT_REQUIREMENT = "effect.";
export function ruleTitle(view: View, r: Rule) {
  const actions = actionsOf(view, r.account);
  return (
    r.action
      .split(".")
      .map((_, i, parts) => actions[parts.slice(0, i + 1).join(".")]?.title)
      .filter(Boolean)
      .join(" › ") || r.action
  );
}
export const ruleWaives = (r: Rule) =>
  (r.requirements ?? []).map(
    ({ id, message }) =>
      WAIVED[id!] ??
      (id?.startsWith(EFFECT_REQUIREMENT)
        ? `Ask on ${id.slice(EFFECT_REQUIREMENT.length)}`
        : message),
  );

// Each pinned MCP tool is an action under read or use, by the hint the owner approved with the pin.
export const actionsOf = (
  view: View,
  account: string,
): { [action: string]: PresetAction } => ({
  ...groupsOf(view, account),
  ...presetOf(view, account).actions,
  ...Object.fromEntries(
    Object.values(accounts(view)[account]?.connections ?? {})
      .flatMap(
        (c) =>
          (
            (c.mcp ?? c["tinfoil-mcp"])?.pin as
              | {
                  tools?: {
                    name: string;
                    title?: string;
                    annotations?: { readOnlyHint?: boolean };
                  }[];
                }
              | undefined
          )?.tools ?? [],
      )
      .map((t) => [
        `${t.annotations?.readOnlyHint ? "read" : "use"}.${t.name}`,
        { title: t.title || t.name },
      ]),
  ),
});
// Record operations also contribute permission groups to their preset.
const operationsOf = (view: View, account: string) =>
  Object.values(presetOf(view, account).operations ?? {});
const groupsOf = (view: View, account: string) =>
  Object.fromEntries(
    operationsOf(view, account).map((o) => [o.action, { title: o.action }]),
  );
// effectsOf unions the effects of every operation under an action, so a group shows its strictest obligations.
// A preset keeps its identity when a read changes it in place; a new catalog marks the change.
const effectGroups = new WeakMap<
  Preset,
  {
    catalog?: string;
    groups: Map<string, { effects: Set<string>; otherPayments: boolean }>;
  }
>();
const effectGroupsOf = (view: View, account: string) => {
  const preset = presetOf(view, account),
    actions = preset.actions ?? {};
  const cached = effectGroups.get(preset);
  let groups = cached?.catalog === view.catalog_id ? cached?.groups : undefined;
  if (!groups) {
    groups = new Map();
    const add = (action: string, effects: string[]) =>
      action.split(".").forEach((_, i, parts) => {
        const key = parts.slice(0, i + 1).join(".");
        if (!groups!.has(key))
          groups!.set(key, { effects: new Set(), otherPayments: false });
        const group = groups!.get(key)!;
        for (const effect of effects) group.effects.add(effect);
        if (effects.includes("pay") && !effects.includes("generate"))
          group.otherPayments = true;
      });
    for (const [action, meta] of Object.entries(actions))
      add(action, meta.effects ?? []);
    for (const op of Object.values(preset.operations ?? {}))
      add(op.action, op.effects ?? []);
    effectGroups.set(preset, { catalog: view.catalog_id, groups });
  }
  return groups;
};
export const effectsOf = (view: View, account: string, k: string) => {
  const actions = presetOf(view, account).actions ?? {},
    groups = effectGroupsOf(view, account);
  const lineage = k
    .split(".")
    .map((_, i, parts) => parts.slice(0, i + 1).join("."))
    .reverse();
  const inherited = lineage.find((a) => actions[a]?.effects);
  return [
    ...new Set([
      ...(actions[inherited!]?.effects ?? []),
      ...(groups.get(k)?.effects ?? []),
    ]),
  ];
};

// Effect settings use the same precedence as config.effectModes. Keeping the
// inherited value lets editors remove an override without copying a default.
export function effectSettings(
  view: View,
  { agent, account }: EffectScope = {},
  effects: string[] = [],
) {
  const id: Partial<Identity> = identities(view)[agent!] ?? {};
  const pair =
    id.accounts?.[account!] ?? view.config.default_access?.[account!];
  const layers: [string, Record<string, Mode> | undefined][] = [
    ["Global settings", view.config.effects],
  ];
  if (account)
    layers.push([`Connection ${account}`, accounts(view)[account]?.effects]);
  if (agent) layers.push([`Sandbox ${agent}`, id.effects]);
  if (agent && account)
    layers.push([`Sandbox ${agent} on ${account}`, pair?.effects]);
  return Object.entries(view.vocabulary)
    .sort(([a], [b]) => a.localeCompare(b))
    .map(([effect, metadata]) => {
      let mode: Mode = metadata.ask ? "ask" : "allow",
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
      const own = layers.at(-1)![1]?.[effect] ?? null;
      return {
        effect,
        own,
        inherited: mode,
        mode: own ?? mode,
        source: own ? layers.at(-1)![0] : source,
      };
    });
}

// Action access and effect settings are independent restrictions; the strictest wins.
export function mode(
  access: Access,
  vocabulary: View["vocabulary"],
  effects: string[],
  k: string,
  settings: Record<string, Mode> = {},
  inherit = false,
): Mode {
  if (!access.level || access.level === "off") return "off";
  const lineage = k
    .split(".")
    .map((_, i, p) => p.slice(0, p.length - i).join("."));
  const has = (name: "change" | "ask") =>
    effects.some((e) => vocabulary[e]?.[name]);
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
export function actionTree(view: View, account: string): ActionNode[] {
  const roots: ActionNode[] = [],
    nodes = new Map<string, ActionNode>();
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
        } as unknown as ActionNode;
        nodes.set(path, node);
        children.push(node);
      }
      if (path === key)
        Object.assign(node, { title: action.title || key, action: true });
      children = node.children;
    });
  }
  const finish = (node: ActionNode): ActionNode => {
    node.children.forEach(finish);
    return Object.assign(node, {
      effects: effectsOf(view, account, node.key),
      total: node.children.reduce((n, c) => n + Number(c.action) + c.total, 0),
    });
  };
  return roots.map(finish);
}

export const levelsOf = (account?: Account) =>
  (Object.entries(LEVELS) as [Level, string][]).filter(
    ([l]) =>
      !["custom_api", "tcp"].includes(account?.preset ?? "") || l !== "read",
  );

// agentAccess describes an agent's level for every account and, below it, each action's own and inherited mode.
export function agentAccess(view: View, name: string, onlyAccount?: string) {
  const id: Partial<Identity> = identities(view)[name] ?? {};
  const entries: [string, Account][] =
    onlyAccount === undefined
      ? Object.entries(accounts(view))
      : accounts(view)[onlyAccount]
        ? [[onlyAccount, accounts(view)[onlyAccount]]]
        : [];
  return entries.map(([account, acc]) => {
    const access: Access = id.accounts?.[account] ??
      view.config.default_access?.[account] ?? { level: "off" };
    let actions: AccessNode[] | undefined;
    return {
      account,
      preset: acc.preset,
      level: access.level,
      levels: levelsOf(acc),
      overrides: Object.values(access.actions ?? {}).filter(Boolean).length,
      // Summaries and collapsed editors need levels, not an entire permission tree.
      get actions(): AccessNode[] {
        if (actions) return actions;
        if (access.level === "off") return (actions = []);
        const overrides = new Map<string, number>(),
          settings = new Map<boolean, Record<string, Mode>>();
        for (const [key, value] of Object.entries(access.actions ?? {})) {
          if (!value) continue;
          const parts = key.split(".");
          for (let i = 1; i < parts.length; i++) {
            const prefix = parts.slice(0, i).join(".");
            overrides.set(prefix, (overrides.get(prefix) ?? 0) + 1);
          }
        }
        const describe = (node: ActionNode): AccessNode => {
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

export function browsingHint(view: View, name: string) {
  const id: Partial<Identity> = identities(view)[name] ?? {};
  const reaches = (pred: (acc: Account) => boolean) =>
    Object.entries(accounts(view)).some(
      ([a, acc]) => (id.accounts?.[a]?.level ?? "off") !== "off" && pred(acc),
    );
  return (
    lattices(view).confidentiality &&
    reaches((acc) => acc.preset === "web") &&
    reaches((acc) => acc.contents !== "anyone")
  );
}

export function labelStatus(view: View, l?: Label) {
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
  return lines.filter(Boolean).join(" · ");
}

export const accountUsers = (view: View, account: string) =>
  Object.entries(identities(view)).flatMap(([name, id]) => {
    const access =
      id.accounts?.[account] ?? view.config.default_access?.[account];
    return (access?.level ?? "off") === "off"
      ? []
      : [
          {
            name,
            level: access!.level,
            overrides: Object.values(access!.actions ?? {}).filter(Boolean)
              .length,
          },
        ];
  });

// Report every connection's progress and errors, plus MCP tool changes awaiting the owner.
export const reviews = (view: View, account: string): Review[] =>
  Object.keys(accounts(view)[account]?.connections ?? {}).map((key) => {
    const name = connectionName(account, key),
      status = view.status[name] ?? {},
      s = status.details ?? {};
    const count = (sign: string) =>
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
      tools: (s.pin as { tools?: McpTool[] } | undefined)?.tools ?? [],
      previouslyApproved: Object.values(
        accounts(view)[account].connections![key],
      ).some((connection) => connection.pin != null),
      previousTools: Object.values(
        accounts(view)[account].connections![key],
      ).flatMap(
        (connection) =>
          (connection.pin as { tools?: McpTool[] } | undefined)?.tools ?? [],
      ),
    };
  });

export function toolReviewDescription(review: Review): string {
  if (!review.previouslyApproved)
    return `${review.name} advertises ${review.blocked} MCP ${review.blocked === 1 ? "tool you haven’t" : "tools you haven’t"} approved yet. Review their definitions before using them.`;
  if (review.changes.some((change) => change.startsWith("~ instructions:")))
    return `Server instructions advertised by ${review.name} differ from those you last approved. Review the instructions and any tool-definition changes before using the affected tools.`;
  return `Tool definitions advertised by ${review.name} differ from those you last approved. Review and approve the changes before using the affected tools.`;
}

// A pin change is "+ name", "~ name" or "- name" and then the tool's definition,
// or "~ instructions:" and then the server's instructions.
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
    sign: head[0],
    name,
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

export function accountStatus(
  view: View,
  account: string,
): { state: "error" | "connecting" | "review" | null; blocked: number } {
  const states = reviews(view, account);
  if (states.some((s) => s.error)) return { state: "error", blocked: 0 };
  if (states.some((s) => s.state === "connecting"))
    return { state: "connecting", blocked: 0 };
  const blocked = states.reduce((n, s) => n + s.blocked, 0);
  return { state: blocked ? "review" : null, blocked };
}

export const fieldPaths = (f: PresetField) => f.paths ?? [f.path!];
const paths = fieldPaths;
const fieldsOf = (c?: Preset) => c?.fields ?? [];
// A field with no paths, such as an OAuth client ID, only fills the account's templates when it is created.
const plain = (c: Preset) =>
  fieldsOf(c).filter((f) => !f.secret && paths(f).length);
const fieldValue = (acc: Account | undefined, f: PresetField): Json =>
  atPath(acc, f.path ?? paths(f)[0]) ?? (f.list ? [] : f.json ? {} : "");
export const setupFields = (view: View, preset: string) =>
  fieldsOf(view.presets[preset]).filter((f) => !f.edit_only);
export const plainFields = (view: View, account: string) =>
  plain(presetOf(view, account)).map((f) => ({
    ...f,
    value: fieldValue(accounts(view)[account], f),
  }));
export const fieldText = (f: PresetField, value?: Json): string =>
  f.json
    ? value === undefined
      ? ""
      : JSON.stringify(value, null, 2)
    : f.list
      ? ((value ?? []) as string[]).join(", ")
      : ((value ?? "") as string);
export function readField(f: PresetField, raw: string): Json {
  const v = f.secret ? raw : raw.trim();
  if (f.json) return v ? JSON.parse(v) : {};
  return f.list ? v.split(/[\s,]+/).filter(Boolean) : v;
}

// A grant template fills from the account's plain settings; one that needs a setup-only value, such as an OAuth client, cannot.
export function grantTemplate(
  view: View,
  account: string,
  f?: PresetField,
): Json | undefined {
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
export function credentialFields(
  view: View,
  account: string,
): CredentialField[] {
  const byPath = new Map<string, PresetField>();
  for (const field of fieldsOf(presetOf(view, account)))
    for (const path of paths(field)) {
      const key = JSON.stringify(path);
      if (!byPath.has(key)) byPath.set(key, field);
    }
  const groups = new Map<
    object,
    { field?: PresetField; members: View["fields"][string] }
  >();
  for (const meta of view.fields?.[account] ?? []) {
    const field = byPath.get(JSON.stringify(meta.path));
    const key = field ?? meta;
    if (!groups.has(key)) groups.set(key, { field, members: [] });
    groups.get(key)!.members.push(meta);
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
        credential: grant ? { oauth: grant } : undefined,
      };
    })
    .sort((a, b) => a.key.localeCompare(b.key));
}

export const signInLabel = (view: View, preset: string) =>
  view.presets[preset]?.title
    ? "Sign in with " + view.presets[preset].title
    : "Sign in";

export function catalog(view: View) {
  const counts = new Map<string, number>();
  for (const acc of Object.values(accounts(view))) {
    const replacement = view.presets[acc.preset]?.replaced_by;
    const preset =
      replacement && view.presets[replacement] ? replacement : acc.preset;
    counts.set(preset, (counts.get(preset) ?? 0) + 1);
  }
  const groups = new Map(
    Object.keys(CATALOG_GROUPS).map((g) => [g, [] as CatalogEntry[]]),
  );
  for (const [name, preset] of Object.entries(view.presets).sort(
    ([, a], [, b]) => a.title.localeCompare(b.title),
  )) {
    // Retired definitions still serve stored credentials and permission names.
    if (preset.replaced_by && view.presets[preset.replaced_by]) continue;
    const group = preset.group ?? "api";
    if (!groups.has(group)) groups.set(group, []);
    groups
      .get(group)!
      .push({ name, title: preset.title, accounts: counts.get(name) ?? 0 });
  }
  // The ones most people add first lead as "Common"; generic connection
  // presets live under Settings → Advanced, not in the browse list.
  const common: CatalogEntry[] = [];
  for (const entries of groups.values())
    for (let i = entries.length - 1; i >= 0; i--) {
      if (COMMON_PRESETS.includes(entries[i].name))
        common.push(...entries.splice(i, 1));
    }
  common.sort(
    (a, b) => COMMON_PRESETS.indexOf(a.name) - COMMON_PRESETS.indexOf(b.name),
  );
  groups.get("generic")?.sort(
    (a, b) => GENERIC_PRESETS.indexOf(a.name) - GENERIC_PRESETS.indexOf(b.name),
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

type CatalogEntry = { name: string; title: string; accounts: number };
type Slot = { value: string } & { [key: string]: string | undefined };

// apiSettings describes a custom API account's slot as form settings; without an account, the defaults for a new one.
export function apiSettings(view: View, account?: string): ApiSettings {
  const slot: Partial<Slot> =
    account === undefined
      ? {}
      : ((
          accounts(view)[account]?.connections?.[""]?.http?.slots as Slot[]
        )?.[0] ?? {});
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
export function apiSetup(view: View, account: string, key = "", index = 0) {
  const [kind, config] =
    Object.entries(accounts(view)[account]?.connections?.[key] ?? {})[0] ?? [];
  const slot = (config?.slots as Slot[] | undefined)?.[index];
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

export function codexSetup(view: View, account: string): string | null {
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

export function tinfoilSetup(view: View, account: string) {
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

// The starting choice only produces the initial policy. Persist completion and
// the effective configuration, without retaining a preset to reapply later.
function onboardingChanges(
  view: View,
  preset: PolicyPreset,
  tinfoilApiKey?: string,
): Change[] {
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
    // Label guardrails are recorded but never enforced in this release.
    lattices: { confidentiality: false, integrity: false },
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
      Object.keys(catalog.connections!).some((key) =>
        connections.has(connectionName(name, key)),
      );
      i++
    )
      name = `tinfoil-${i}`;
    changes.push(
      ...edits.addAccount(view, "tinfoil", {
        name,
        values: { TINFOIL_API_KEY: key },
        answers: catalog.defaults as AccountAnswers,
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
const networkRuleName = (view: View) =>
  Object.keys(view.config.policies ?? {}).find((k) =>
    /deny contains "(Network access is disabled|This request has no recognized policy operation)/.test(
      view.config.policies![k],
    ),
  ) ?? "network-default";
// Raw TCP: the Monitor only sees host and port, never what is sent.
export const isRawNetwork = (view: View, account: string) =>
  view.config.accounts?.[account]?.preset === "tcp";
// "api.github.com:443" for a raw-network scope, else "key: value" pairs.
export const scopeText = (
  view: View,
  account: string,
  scope: Record<string, unknown> = {},
) =>
  isRawNetwork(view, account) && scope.host
    ? `${scope.host}${scope.port ? `:${scope.port}` : ""}`
    : Object.entries(scope).map(
        ([k, v]) => `${k}: ${typeof v === "string" ? v : JSON.stringify(v)}`,
      );
// "Open" = every raw-TCP catch-all at allow for everyone, no deny rule, the
// whole internet in allow_networks. Settings → Dangerous only.
export const networkingOpen = (view: View) =>
  (view.config.allow_networks ?? []).includes("0.0.0.0/0") &&
  !Object.values(view.config.policies ?? {}).some((p) =>
    p.includes("package sentinel\n\ndeny contains"),
  );

// Each edit returns the source changes for POST /policy/edits.
export const edits = {
  setNetworkingOpen: (view: View, open: boolean): Change[] => {
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
  pairAgent: (name: string, key: string) =>
    sourceChanges({
      identities: { [name.trim()]: { key: key.trim(), accounts: {} } },
    }),
  pairDevice: (name: string, key: string) =>
    sourceChanges({
      identities: { [name]: { key: key.trim(), routes: true, accounts: {} } },
    }),
  removeAgent: (name: string): Change[] => [
    { path: ["identities", name], delete: true },
  ],
  replaceKey: (name: string, key: string): Change[] => [
    { path: ["identities", name, "key"], value: key.trim() },
  ],
  setRoutes: (name: string, routes: boolean): Change[] => [
    { path: ["identities", name, "routes"], value: routes },
  ],
  // An action set to null inherits again.
  setAccess: (
    name: string,
    account: string,
    access: {
      level?: Level;
      actions?: { [action: string]: Mode | null };
      effects?: { [effect: string]: Mode | null };
    },
  ) =>
    sourceChanges({
      identities: { [name]: { accounts: { [account]: access } } },
    }),
  setEffect: (
    { agent, account }: EffectScope = {},
    effect: string,
    mode: Mode | null,
  ): Change[] => [
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
  copySettings: (view: View, from: string, name: string): Change[] =>
    ["accounts", "rules", "effects"].map((key) => ({
      path: ["identities", name, key],
      value: clone(identities(view)[from]?.[key as keyof Identity] ?? {}),
    })),
  removeRule: (name: string, id: string): Change[] => [
    { path: ["identities", name, "rules", id], delete: true },
  ],
  setLattice: (
    lattice: "confidentiality" | "integrity",
    on: boolean,
  ): Change[] => [{ path: ["lattices", lattice], value: on }],
  setNetworks: (text: string): Change[] => [
    { path: ["allow_networks"], value: text.split(/\s+/).filter(Boolean) },
  ],
  setPaidInference: (allow: boolean): Change[] => [
    { path: ["allow_paid_inference"], value: allow },
  ],
  setAccountPolicy: (account: string, source: string) =>
    sourceChanges({ policies: { [account]: source.trim() || null } }),
  approveTools: (view: View, account: string, key: string) =>
    sourceChanges({
      accounts: {
        [account]: {
          connections: {
            [key]: {
              [Object.keys(accounts(view)[account].connections![key])[0]]: {
                pin: view.status[connectionName(account, key)].details!.pin,
              },
            },
          },
        },
      },
    }),
  // Identities may not name a missing account, so removing one also clears it from every agent.
  removeAccount: (view: View, account: string) =>
    sourceChanges({
      accounts: { [account]: null },
      policies: { [account]: null },
      default_access: { [account]: null },
      identities: Object.fromEntries(
        Object.keys(identities(view)).map((name) => [
          name,
          { accounts: { [account]: null } },
        ]),
      ),
    }),
  // values holds every setup field read with readField; oauth names the fields that sign in instead of taking a token.
  addAccount(
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
      answers: AccountAnswers;
      oauth?: string[];
    },
  ): Change[] {
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
      level?: Level;
      answers: AccountAnswers;
    },
  ): Change[] {
    name = name.trim();
    if (!/^[a-zA-Z0-9][a-zA-Z0-9-]*$/.test(name))
      throw new Error("Name this account using letters, numbers, and hyphens.");
    if (Object.hasOwn(accounts(view), name))
      throw new Error(
        "An account with that name already exists. Choose another name.",
      );
    if (!token.trim()) throw new Error("Enter the API key or token.");
    const body: { [key: string]: unknown } = {
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
    view: View,
    account: string,
    {
      answers = {},
      api,
      values = {},
      credentials = {},
    }: {
      answers?: Partial<AccountAnswers>;
      api?: Partial<ApiSettings>;
      values?: { [key: string]: Json };
      credentials?: {
        [key: string]: { mode: "keep" | "replace" | "clear"; value?: Json };
      };
    },
  ): Change[] {
    const acc = accounts(view)[account],
      updated = clone(acc),
      changed = new Set<string>(),
      removals: Change[] = [];
    const set = (path: string[], value: unknown) => {
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
        [
          apiSlot(
            api,
            (acc.connections?.[""]?.http?.slots as Slot[] | undefined)?.[0]
              ?.value,
          ),
        ],
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
};

// Setup guides for connecting tools. href maps a route such as ["pair"] or ["agent-settings", name] to a link, which
// also carries the route as data-route; code blocks carry data-copy with the id of the text to copy.
export const INTEGRATION_PAGES: { [page: string]: string } = {
  start: "Start here",
  wrapped: "Wrap commands",
  shell: "Monitor shell",
  mcp: "MCP connections",
};
export function integrationGuide(
  view: View,
  page: string,
  href: (route: string[]) => string,
): string {
  const link = (route: string[], text: string) =>
    `<a href="${esc(href(route))}" data-route="${esc(route.join("/"))}">${text}</a>`;
  const code = (id: string, title: string, text: string) =>
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
}: {
  token: string;
  generation?: number;
  fetch?: typeof globalThis.fetch;
}): OwnerApi {
  const json = ownerJSON<RequestInit>(fetch);
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

const SHELL_INPUT_BYTES = 16384;
export const toBase64 = (bytes: Uint8Array) => {
  let text = "";
  for (const byte of bytes) text += String.fromCharCode(byte);
  return btoa(text);
};
export const fromBase64 = (text: string) =>
  Uint8Array.from(atob(text), (c) => c.charCodeAt(0));
const isGeneration = (n: number) => Number.isSafeInteger(n) && n >= 0;

// The caller supplies a call over an authenticated channel to the attested Monitor.
// Each call carries the newest generation seen; the caller persists advances.
export function sealedOwnerClient({
  call,
  generation = 0,
  storageKey,
  remember,
  assets = "/",
}: {
  call: OwnerRpc;
  generation?: number;
  storageKey: string;
  /** Called with each newer generation the Monitor reports. */
  remember?: (generation: number) => void;
  /** URL prefix of the local build whose icons/ icons() reads. */
  assets?: string;
}): OwnerApi & { call: Request } {
  if (!isGeneration(generation)) throw new Error("Invalid monitor generation.");
  let floor = generation;
  const request: Request = (method, path, body = null, signal) =>
    call(
      method,
      path,
      path.split("?")[0] === "/unlock"
        ? { ...(body as object), storage_key: storageKey }
        : body,
      floor,
      signal,
    );
  const api = ownerApi(request, floor, "", (seen) => {
    if (!isGeneration(seen) || seen < floor)
      throw new OwnerError(ROLLBACK, 409);
    if (seen > floor) remember?.(seen);
    floor = seen;
  });
  return {
    ...api,
    // Hosted callers also reach owner routes outside the shared management API.
    call: request,
    icons: async (signal) => {
      const response = await globalThis.fetch(assets + "icons/manifest.json", {
        signal,
      });
      if (!response.ok)
        throw new OwnerError("Could not load icons.", response.status);
      const manifest = await response.json();
      return (preset) => connectorIcon(manifest, preset, "", assets);
    },
  };
}

// One sandbox shell for as long as its socket: input and resizes go out as they happen,
// output streams back until the exit code.
export function openShell(
  channel: OwnerChannel,
  { output, exit, error }: ShellHandlers,
  signal: AbortSignal,
): Shell {
  const send = (message: object) =>
    channel.send(new TextEncoder().encode(JSON.stringify(message)));
  signal.addEventListener("abort", () => channel.close(), { once: true });
  void (async () => {
    for (;;) {
      const message = JSON.parse(
        new TextDecoder().decode(await channel.receive()),
      );
      if ("exit" in message) return exit(message.exit ?? undefined);
      output(fromBase64(message.output));
    }
  })().catch((cause) => signal.aborted || error(cause));
  return {
    input(bytes) {
      for (let at = 0; at < bytes.length; at += SHELL_INPUT_BYTES)
        send({ input: toBase64(bytes.subarray(at, at + SHELL_INPUT_BYTES)) });
    },
    resize: (cols, rows) => send({ resize: { cols, rows } }),
  };
}
