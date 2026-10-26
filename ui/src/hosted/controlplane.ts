import { sha256 } from "@noble/hashes/sha2.js";
import { bytesToHex, utf8ToBytes } from "@noble/hashes/utils.js";
import { parse } from "yaml";

export const API_BASE_URL =
  import.meta.env.VITE_API_BASE_URL || "https://api.tinfoil.sh";
export const MONITOR_REPO = "tinfoilsh/confidential-agent-monitor";
export const SANDBOX_REPO = "tinfoilsh/confidential-agent-sandbox";
// Sandboxes reach their Monitor's SSH port through this fixed private alias.
export const MONITOR_ALIAS = { ip: "10.254.0.1", port: 22 };
const MONITOR_SSH_PORT = 22;
const CONFIG_PREFIX = "/tinfoil/containers/";
export const POLL_MS = 3000;
const FOLLOW_TIMEOUT_MS = 15 * 60 * 1000;

export type Status =
  | "created"
  | "pending"
  | "deploying"
  | "started"
  | "running"
  | "failed"
  | "stopping"
  | "stopped";
export type NetworkPolicy = {
  public: boolean;
  egress_mode: string;
  egress: {
    container_id: string;
    port: number;
    alias?: typeof MONITOR_ALIAS;
  }[];
};
export type Container = {
  id: string;
  name: string;
  repo: string;
  status: Status;
  domain: string;
  config: string;
  config_name: string;
  debug: boolean;
  clerk_user_id?: string;
  network_policy?: NetworkPolicy | null;
  // Only the single-container view carries volumes.
  volumes?: Record<string, string>;
  error_message?: string;
  last_deploy_attempt_error?: string;
};
// Volumes are unified: a detached one may back any template the controlplane accepts it for.
export type Volume = {
  id: string;
  name: string;
  container_id: string | null;
  size_bytes: number;
};

export class ControlplaneError extends Error {
  constructor(
    message: string,
    readonly status: number,
  ) {
    super(message);
  }
}

export function controlplane(
  token: () => Promise<string | null>,
  fetch: typeof globalThis.fetch = (...args) => globalThis.fetch(...args),
  base = API_BASE_URL,
) {
  const call = async <T>(
    method: string,
    path: string,
    body?: unknown,
    signal?: AbortSignal,
  ): Promise<T> => {
    const auth = await token();
    if (!auth) throw new ControlplaneError("Sign in again.", 401);
    const res = await fetch(base + path, {
      method,
      signal,
      credentials: "omit",
      headers: {
        Accept: "application/json",
        Authorization: `Bearer ${auth}`,
        ...(body !== undefined && { "Content-Type": "application/json" }),
      },
      body: body === undefined ? undefined : JSON.stringify(body),
    });
    const text = await res.text();
    let data: any;
    try {
      data = text ? JSON.parse(text) : null;
    } catch {}
    if (!res.ok)
      throw new ControlplaneError(
        data?.error || data?.message || `Request failed (${res.status})`,
        res.status,
      );
    return data as T;
  };
  const container = (id: string) => `/api/containers/${encodeURIComponent(id)}`;
  return {
    list: (signal?: AbortSignal) =>
      call<Container[]>("GET", "/api/containers", undefined, signal).then(
        (rows) => rows ?? [],
      ),
    get: (id: string, signal?: AbortSignal) =>
      call<Container>("GET", container(id), undefined, signal),
    create: (body: object, signal?: AbortSignal) =>
      call<Container>("POST", "/api/containers", body, signal),
    start: (id: string, signal?: AbortSignal) =>
      call<Container>("POST", container(id) + "/deploy", undefined, signal),
    stop: (id: string, signal?: AbortSignal) =>
      call<Container>("POST", container(id) + "/stop", undefined, signal),
    volumes: (signal?: AbortSignal) =>
      call<{ volumes?: Volume[] }>(
        "GET",
        "/api/volumes",
        undefined,
        signal,
      ).then((list) => list?.volumes ?? []),
    // The dashboard's deploy default: GitHub's latest release, else the newest released tag.
    latestTag: async (repo: string, signal?: AbortSignal) => {
      const tags =
        (
          await call<{
            tags?: { name: string; has_release: boolean; latest: boolean }[];
          }>("GET", `/api/github/repos/${repo}/tags`, undefined, signal)
        )?.tags ?? [];
      const tag =
        tags.find((t) => t.latest && t.has_release) ??
        tags.find((t) => t.has_release);
      if (!tag) throw new Error(`${repo} has no published release.`);
      return tag.name;
    },
  };
}
export type Controlplane = ReturnType<typeof controlplane>;

// Mirrors the CLI: every measured env entry is a single explicit string mapping.
export function measuredEnv(config: string): Map<string, string> {
  const doc = parse(config, { schema: "core" }) as {
    containers?: { env?: unknown[] }[];
  } | null;
  const env = new Map<string, string>();
  for (const container of doc?.containers ?? [])
    for (const entry of container?.env ?? []) {
      const pairs =
        entry && typeof entry === "object" && !Array.isArray(entry)
          ? Object.entries(entry)
          : [];
      if (pairs.length !== 1 || typeof pairs[0][1] !== "string")
        throw new Error(
          "Workload requires explicit measured environment mappings.",
        );
      const [name, value] = pairs[0];
      if (env.has(name))
        throw new Error(`Workload environment ${name} is ambiguous.`);
      env.set(name, value);
    }
  return env;
}

export type Workload = {
  row: Container;
  env: Map<string, string>;
  // Digest-pinned registry reference of the measured config, as the CLI derives it.
  source: string;
};

export function workload(row: Container, repo: string): Workload {
  if (row.repo !== repo || row.debug || !row.config)
    throw new Error(`${row.name} has an unexpected workload configuration.`);
  const digest = bytesToHex(sha256(utf8ToBytes(row.config)));
  if (row.config_name !== CONFIG_PREFIX + digest)
    throw new Error(
      `${row.name}'s config reference does not match its digest.`,
    );
  return {
    row,
    env: measuredEnv(row.config),
    source: `${CONFIG_PREFIX.slice(1, -1)}@${digest}@sha256:${digest}`,
  };
}

export const monitorRequest = (name: string, tag: string, owner: string) => ({
  name,
  repo: MONITOR_REPO,
  tag,
  variables: { MONITOR_OWNER_PUBLIC_KEY: owner },
  object_storage: {},
});

export const sandboxNetwork = (monitorId: string): NetworkPolicy => ({
  public: false,
  egress_mode: "restricted",
  egress: [
    { container_id: monitorId, port: MONITOR_SSH_PORT, alias: MONITOR_ALIAS },
  ],
});

export const sandboxRequest = (options: {
  name: string;
  tag: string;
  owner: string;
  instanceId: string;
  monitorId: string;
  monitorSSH: boolean;
  workspace?: string;
}) => ({
  name: options.name,
  repo: SANDBOX_REPO,
  tag: options.tag,
  variables: {
    SANDBOX_INSTANCE_ID: options.instanceId,
    SANDBOX_OWNER_PUBLIC_KEY: options.owner,
    SANDBOX_MONITOR_SSH: options.monitorSSH ? "1" : "0",
  },
  network_policy: sandboxNetwork(options.monitorId),
  ...(options.workspace && { volumes: { workspace: options.workspace } }),
});

export function attachedMonitor(row: Container): string | undefined {
  const policy = row.network_policy,
    peer = policy?.egress?.[0];
  const matches =
    policy &&
    !policy.public &&
    policy.egress_mode === "restricted" &&
    policy.egress.length === 1 &&
    peer?.port === MONITOR_SSH_PORT &&
    peer.alias?.ip === MONITOR_ALIAS.ip &&
    peer.alias.port === MONITOR_ALIAS.port;
  return matches ? peer.container_id : undefined;
}

// Creation is not idempotent, but names are unique: after a lost reply, adopt the
// same-named row only when its measured bindings show this request created it.
// `created` is true only for a positive reply to this request.
export async function createOnce(
  cp: Controlplane,
  body: { name: string },
  ours: (row: Container) => boolean,
  signal?: AbortSignal,
): Promise<{ row: Container; created: boolean }> {
  try {
    return { row: await cp.create(body, signal), created: true };
  } catch (cause) {
    signal?.throwIfAborted();
    const named = (await cp.list(signal)).find((row) => row.name === body.name);
    const detail = named && (await cp.get(named.id, signal));
    if (detail && ours(detail)) return { row: detail, created: false };
    throw cause;
  }
}

export const sleep = (ms: number, signal?: AbortSignal) =>
  new Promise<void>((resolve, reject) => {
    signal?.throwIfAborted();
    const abort = () => {
      clearTimeout(timer);
      reject(signal!.reason);
    };
    const timer = setTimeout(() => {
      signal?.removeEventListener("abort", abort);
      resolve();
    }, ms);
    signal?.addEventListener("abort", abort, { once: true });
  });

export const failure = (row: Container) =>
  row.last_deploy_attempt_error ||
  row.error_message ||
  `${row.name} failed to deploy.`;

// Polls the detail view until the container settles in the wanted state.
export async function follow(
  cp: Controlplane,
  row: Container,
  until: "running" | "stopped",
  signal?: AbortSignal,
  onChange?: (row: Container) => void,
  interval = POLL_MS,
): Promise<Container> {
  const deadline = Date.now() + FOLLOW_TIMEOUT_MS;
  for (;;) {
    if (row.status === until) return row;
    if (row.status === "failed")
      if (until === "stopped") return row;
      else throw new Error(failure(row));
    if (Date.now() > deadline)
      throw new Error(
        `${row.name} is still ${row.status}. Check it again later.`,
      );
    await sleep(interval, signal);
    row = await cp.get(row.id, signal);
    onChange?.(row);
  }
}
