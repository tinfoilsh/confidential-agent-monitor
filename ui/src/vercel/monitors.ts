import { UnverifiedClient } from "tinfoil/unsafe";
import { OwnerError, sealedOwnerClient, type OwnerApi } from "../owner.js";
import {
  MONITOR_REPO,
  POLL_MS,
  SANDBOX_REPO,
  attachedMonitor,
  createOnce,
  monitorRequest,
  sandboxRequest,
  sleep,
  workload,
  type Container,
  type Controlplane,
  type Workload,
} from "./controlplane";
import {
  diskKey,
  measuredOwner,
  ownerSeed,
  sandboxOwnerSeed,
  signer,
  storageKey,
  toBase64,
} from "./keys";

// The Monitor answers a positively absent store with 428 unless asked to initialize.
const MISSING_STATE_STATUS = 428;
// A sandbox reported running may not have published its Monitor route yet.
const ROUTE_UNAVAILABLE_STATUS = 503;
const ROUTE_WAIT_MS = 2 * 60 * 1000;
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;

export class ForeignResource extends Error {}

// The Monitor's storage holds no state and was not asked to initialize.
export class MissingState extends Error {}

// Resolves with a fetch that EHBP-seals bodies to the Monitor. `verified` is true
// only when attestation proved the Monitor runs exactly `source`.
export type AttestMonitor = (
  target: { url: string; source: string },
  signal: AbortSignal,
) => Promise<{ fetch: typeof fetch; verified: boolean }>;

// Temporary until tinfoil-js verifies registry-published configs: the HPKE key
// comes from the Monitor unattested, so bodies stay sealed and owner-signed but
// the Monitor's identity is unverified. Replace with verification of `source`.
export const attestMonitor: AttestMonitor = async ({ url }, signal) => {
  signal.throwIfAborted();
  const target = new URL(url);
  if (target.protocol !== "https:")
    throw new Error(`Refusing a monitor transport over ${target.protocol}.`);
  const origin = target.origin;
  const client = new UnverifiedClient({ baseURL: origin, keyOrigin: origin });
  await client.ready();
  signal.throwIfAborted();
  return { fetch: ownerRpcOnly(origin, client.fetch), verified: false };
};

// The unverified transport has no origin guard and sends bodyless requests in
// plaintext, so only sealed owner RPC posts may pass.
export const ownerRpcOnly =
  (origin: string, fetch: typeof globalThis.fetch): typeof globalThis.fetch =>
  (input, init) => {
    if (
      String(input) !== `${origin}/owner/rpc` ||
      init?.method !== "POST" ||
      typeof init.body !== "string" ||
      !init.body
    )
      throw new Error(`Refusing to send owner traffic to ${String(input)}.`);
    return fetch(input, init);
  };

// Initialization intent outlives reloads until the first successful unlock or
// enrollment. Keys: a positively created Monitor's container ID, or the fresh
// instance ID of a sandbox requested with a new workspace.
export function initIntents(
  storage: Pick<Storage, "getItem" | "setItem" | "removeItem">,
  account: string,
) {
  const key = (id: string) => `tinfoil-monitor/${account}/initialize/${id}`;
  return {
    has: (id: string) => storage.getItem(key(id)) !== null,
    set: (id: string) => storage.setItem(key(id), "1"),
    clear: (id: string) => storage.removeItem(key(id)),
  };
}
export type Intents = ReturnType<typeof initIntents>;

export const sandboxIdentity = (name: string) => `sandbox-${name}`;

const foreign = (name: string, command: string) =>
  new ForeignResource(
    `${name} has a different owner key, such as one created by the Tinfoil CLI. Use \`tinfoil ${command} ${name}\`.`,
  );

export function ownedMonitor(row: Container, root: Uint8Array): Workload {
  const work = workload(row, MONITOR_REPO);
  const seed = ownerSeed(root);
  const ours = work.env.get("MONITOR_OWNER_PUBLIC_KEY") === measuredOwner(seed);
  seed.fill(0);
  if (!ours) throw foreign(row.name, "monitor open");
  return work;
}

// Only a positive creation reply grants initialization; an adopted row after a
// lost reply or conflict uses the explicit empty-store recovery instead.
export async function createMonitor(options: {
  api: Controlplane;
  root: Uint8Array;
  name: string;
  tag: string;
  intents: Intents;
  signal?: AbortSignal;
}) {
  const seed = ownerSeed(options.root);
  const owner = measuredOwner(seed);
  seed.fill(0);
  const { row, created } = await createOnce(
    options.api,
    monitorRequest(options.name, options.tag, owner),
    (row) => {
      try {
        return !!ownedMonitor(row, options.root);
      } catch {
        return false;
      }
    },
    options.signal,
  );
  if (created) options.intents.set(row.id);
  return row;
}

export type MonitorSession = {
  row: Container;
  client: OwnerApi;
  verified: boolean;
  signal: AbortSignal;
  close(): void;
};

// Prepares the sealed transport (verification is currently stubbed) before sending
// any Monitor secret, then unlocks the owner API.
export async function openMonitor(options: {
  row: Container;
  root: Uint8Array;
  attest: AttestMonitor;
  intents: Intents;
  initialize?: boolean;
  signal: AbortSignal;
  storage?: Storage;
}): Promise<MonitorSession> {
  const { row, root, intents } = options;
  if (row.status !== "running") throw new Error(`${row.name} is not running.`);
  const work = ownedMonitor(row, root);
  const bucket = work.env.get("TINFOIL_STORAGE_BUCKET");
  if (!bucket) throw new Error(`${row.name} has no measured object storage.`);
  const lifetime = new AbortController();
  const signal = AbortSignal.any([options.signal, lifetime.signal]);
  const close = () =>
    lifetime.abort(new DOMException("The monitor was closed.", "AbortError"));
  try {
    const { fetch: sealed, verified } = await options.attest(
      { url: `https://${row.domain}`, source: work.source },
      signal,
    );
    signal.throwIfAborted();
    const seed = ownerSeed(root);
    signal.addEventListener("abort", () => seed.fill(0), { once: true });
    const initialize = !!options.initialize || intents.has(row.id);
    const key = storageKey(root, bucket);
    const client = sealedOwnerClient({
      endpoint: `https://${row.domain}`,
      monitor: bucket,
      sign: signer(seed, signal),
      storageKey: toBase64(key),
      initialize,
      storage: options.storage,
      assets: import.meta.env.BASE_URL,
      fetch: (input, init) => {
        signal.throwIfAborted();
        return sealed(input, {
          ...init,
          signal: init?.signal
            ? AbortSignal.any([init.signal, signal])
            : signal,
        });
      },
    });
    key.fill(0);
    try {
      await client.unlock(undefined, signal);
    } catch (cause) {
      if (
        cause instanceof OwnerError &&
        cause.status === MISSING_STATE_STATUS &&
        !initialize
      )
        throw new MissingState(
          `${row.name} has no stored state yet. If it was never opened, initialize its storage.`,
        );
      throw cause;
    }
    signal.throwIfAborted();
    intents.clear(row.id);
    return { row, client, verified, signal, close };
  } catch (cause) {
    close();
    throw cause;
  }
}

function sandboxOwner(work: Workload, root: Uint8Array, monitorId: string) {
  const { row, env } = work;
  const instanceId = env.get("SANDBOX_INSTANCE_ID") ?? "";
  if (!UUID.test(instanceId) || env.get("NO_MONITOR") === "1")
    throw new Error(`${row.name} has no measured instance bound to a monitor.`);
  if (attachedMonitor(row) !== monitorId)
    throw new Error(`${row.name} is not attached to this monitor.`);
  const seed = sandboxOwnerSeed(root, instanceId);
  if (env.get("SANDBOX_OWNER_PUBLIC_KEY") !== measuredOwner(seed)) {
    seed.fill(0);
    throw foreign(row.name, "sandbox enroll");
  }
  return { seed, instanceId };
}

export type SandboxRequest = {
  name: string;
  workspace?: string;
  instanceId: string;
};

// Keep one request per attempt: a retry must target the same name, workspace and instance.
export async function createSandbox(options: {
  api: Controlplane;
  root: Uint8Array;
  monitorId: string;
  tag: string;
  request: SandboxRequest;
  intents: Intents;
  signal?: AbortSignal;
}) {
  const { root, monitorId, request } = options;
  const seed = sandboxOwnerSeed(root, request.instanceId);
  const owner = measuredOwner(seed);
  seed.fill(0);
  // The instance ID is fresh, so this intent can only reach the sandbox this request
  // creates; a reused workspace already holds a disk and is never initialized.
  if (request.workspace) options.intents.clear(request.instanceId);
  else options.intents.set(request.instanceId);
  const { row } = await createOnce(
    options.api,
    sandboxRequest({ ...request, tag: options.tag, owner, monitorId }),
    (row) => {
      try {
        const { seed, instanceId } = sandboxOwner(
          workload(row, SANDBOX_REPO),
          root,
          monitorId,
        );
        seed.fill(0);
        return instanceId === request.instanceId;
      } catch {
        return false;
      }
    },
    options.signal,
  );
  return row;
}

// Expects the single-container view, which carries the workspace volume.
export async function enrollSandbox(options: {
  client: OwnerApi;
  row: Container;
  root: Uint8Array;
  monitorId: string;
  intents: Intents;
  initialize?: boolean;
  signal?: AbortSignal;
}) {
  const { row, root } = options;
  if (row.status !== "running") throw new Error(`${row.name} is not running.`);
  const work = workload(row, SANDBOX_REPO);
  const volumes = Object.entries(row.volumes ?? {});
  if (
    volumes.length !== 1 ||
    volumes[0][0] !== "workspace" ||
    !UUID.test(volumes[0][1])
  )
    throw new Error(`${row.name} has no unique workspace volume.`);
  const { seed, instanceId } = sandboxOwner(work, root, options.monitorId);
  const disk = diskKey(root, volumes[0][1]);
  const initialize = !!options.initialize || options.intents.has(instanceId);
  try {
    for (const deadline = Date.now() + ROUTE_WAIT_MS; ;) {
      try {
        const view = await options.client.enrollSandbox(
          sandboxIdentity(row.name),
          {
            owner_seed: toBase64(seed),
            disk_key: toBase64(disk),
            initialize,
            source: work.source,
            instance_id: instanceId,
          },
          options.signal,
        );
        options.intents.clear(instanceId);
        return view;
      } catch (cause) {
        if (
          !(cause instanceof OwnerError) ||
          cause.status !== ROUTE_UNAVAILABLE_STATUS ||
          Date.now() > deadline
        )
          throw cause;
      }
      await sleep(POLL_MS, options.signal);
    }
  } finally {
    seed.fill(0);
    disk.fill(0);
  }
}
