import { randomBytes } from "@noble/hashes/utils.js";
import {
  PasskeyKeyError,
  createPasskeyKeyManager,
  decodeWrappedKeyRecord,
  encodeWrappedKeyRecord,
  type PasskeyKeyManager,
} from "@tinfoilsh/passkey-kit";
import {
  PRF_PROFILES,
  b64u,
  isID16,
  manualKEKStorageKey,
  manualRecoveryFile,
  openMK,
  ownerPublicKey,
  parseManualRecoveryFile,
  parseMKPayload,
  sealMK,
  unb64u,
  unwrapManualKEK,
  wrapManualKEK,
  type MKBinding,
  type MKContext,
  type MKPayload,
  type KeySyncTargets,
  type MKResource,
} from "./contract";

// The trusted build chooses the profile; nothing in a URL selects a destination.
export const PROFILE = import.meta.env.DEV ? "development" : "production";
const TERMINAL =
  PROFILE === "development"
    ? {
        terminal: "https://local.tinfoil.sh",
        api_origin: import.meta.env.VITE_DEV_API_ORIGIN as string | undefined,
        dashboard: import.meta.env.VITE_DEV_DASHBOARD_RETURN as
          string | undefined,
      }
    : {
        terminal: "https://terminal.tinfoil.sh",
        api_origin: "https://api.tinfoil.sh",
        dashboard: "https://dash.tinfoil.sh/?tab=sandboxes",
      };
export const TARGETS = {
  ...TERMINAL,
  // The Frontend API key of clerk.tinfoil.sh, supplied for this instance.
  clerk_publishable_key: "pk_live_Y2xlcmsudGluZm9pbC5zaCQ",
  callback: "http://localhost:49152/callback",
  completion: `${TERMINAL.terminal}/cli/complete`,
};
const isOrigin = (value: string | undefined) => {
  try {
    const url = new URL(value ?? "");
    return url.protocol === "https:" && url.origin === value;
  } catch {
    return false;
  }
};

// Why this build cannot run on this page, if it cannot.
export function profileError(origin = location.origin): string | undefined {
  if (origin !== TARGETS.terminal)
    return `This build only runs at ${TARGETS.terminal}.`;
  if (
    !isOrigin(TARGETS.api_origin) ||
    !TARGETS.dashboard?.startsWith("https://")
  )
    return "This build has no trusted API and dashboard configuration.";
}

// Key sync needs the existing terminal/API profile, independently of CLI OAuth configuration.
export function keySyncProfile(): KeySyncTargets {
  if (!isOrigin(TARGETS.api_origin))
    throw new Error("This terminal's API configuration is invalid.");
  return {
    terminal: TARGETS.terminal,
    api_origin: TARGETS.api_origin!,
    callback: TARGETS.callback,
    completion: TARGETS.completion,
  };
}

export const passkeys = () =>
  createPasskeyKeyManager({
    profile: PRF_PROFILES[PROFILE],
    relyingPartyName: "Tinfoil",
    enrollmentAttachment: "any",
  });

// --- controlplane key state -------------------------------------------------

export class ApiError extends Error {
  constructor(
    readonly status: number,
    readonly body: { error?: string; dek_id?: string | null } | null,
  ) {
    super(
      typeof body?.error === "string"
        ? body.error
        : `Request failed (${status})`,
    );
  }
}
export type Api = (
  path: string,
  init?: {
    method?: "GET" | "POST" | "PUT" | "DELETE";
    body?: unknown;
    signal?: AbortSignal;
  },
) => Promise<unknown>;

export type RecoveryInput = {
  recovery_id: string;
  type: "passkey" | "manual";
  credential_id: string | null;
  encrypted_dek: string;
  created_at: string;
};
export type KeyState = {
  revision: number;
  dek_id: string | null;
  encrypted_mk: string | null;
  recovery: RecoveryInput[];
};
type KeyChange = {
  dek_id: string;
  encrypted_mk: string;
  recovery: RecoveryInput[];
};
// A whole state write and the revision it replaces.
type KeyWrite = KeyChange & { expected_revision: number };

const KEY_STATE = "/api/sandboxes/owner-key";
// A timeout or server error may follow a commit; only a 4xx answer is definitive.
const REQUEST_TIMEOUT = 408;
const SERVER_ERROR = 500;
const MERGE_ATTEMPTS = 5;
export const id16 = () => b64u(randomBytes(16));

export async function readKeyState(
  api: Api,
  signal?: AbortSignal,
): Promise<KeyState> {
  const s = (await api(KEY_STATE, { signal })) as KeyState;
  if (
    !Number.isSafeInteger(s?.revision) ||
    s.revision < 0 ||
    (s.dek_id !== null && !isID16(s.dek_id)) ||
    (s.encrypted_mk !== null && typeof s.encrypted_mk !== "string") ||
    (s.dek_id === null) !== (s.encrypted_mk === null) ||
    !Array.isArray(s.recovery)
  )
    throw new Error("The key service returned an invalid key state.");
  return s;
}

const uncertain = (cause: unknown) =>
  !(cause instanceof ApiError) ||
  cause.status === REQUEST_TIMEOUT ||
  cause.status >= SERVER_ERROR;
const conflict = (cause: unknown, ...errors: string[]) =>
  cause instanceof ApiError &&
  cause.status === 409 &&
  errors.includes(cause.body?.error ?? "");

async function putKeyState(
  api: Api,
  write: KeyWrite,
  signal?: AbortSignal,
): Promise<number> {
  const reply = (await api(KEY_STATE, {
    method: "PUT",
    body: write,
    signal,
  })) as {
    revision?: unknown;
  };
  if (reply?.revision !== write.expected_revision + 1)
    throw new Error("The key service returned an unreadable reply.");
  return reply.revision;
}

// Writes a change over the latest state by compare-and-swap and returns the
// revision holding the result. A stale or uncertain write reads again and
// reapplies the change, which returns null once it finds itself applied.
async function writeState(
  api: Api,
  change: (state: KeyState) => Promise<KeyChange | null>,
  signal?: AbortSignal,
  known?: KeyState,
): Promise<number> {
  for (let attempt = 0; attempt < MERGE_ATTEMPTS; attempt++) {
    const state = (attempt === 0 && known) || (await readKeyState(api, signal));
    const next = await change(state);
    if (!next) return state.revision;
    try {
      return await putKeyState(
        api,
        { expected_revision: state.revision, ...next },
        signal,
      );
    } catch (cause) {
      if (
        signal?.aborted ||
        !(uncertain(cause) || conflict(cause, "stale_revision"))
      )
        throw cause;
    }
  }
  throw new Error("Your keys keep changing in another session. Try again.");
}

// --- unlocked MK (memory only) ----------------------------------------------

export type Unlocked = {
  dek: Uint8Array;
  context: MKContext;
  revision: number;
  payload: MKPayload;
};

const order = (resources: MKResource[]) =>
  [...resources].sort((a, b) => (a.key_id < b.key_id ? -1 : 1));

async function open(
  state: KeyState,
  dek: Uint8Array,
  context: MKContext,
): Promise<Unlocked> {
  return {
    dek,
    context,
    revision: state.revision,
    payload: await openMK(state.encrypted_mk!, dek, context),
  };
}

function reopen(state: KeyState, u: Unlocked): Promise<Unlocked> {
  if (state.dek_id !== u.context.dek_id)
    throw new Error(
      "Your keys were replaced elsewhere. Unlock them again to continue.",
    );
  return open(state, u.dek, u.context);
}

export type Delta = (payload: MKPayload) => MKPayload;

// Writes a delta by stable key ID over the latest MK.
export async function updateMK(
  api: Api,
  caller: Unlocked,
  delta: Delta,
  known?: KeyState,
): Promise<Unlocked> {
  let u = caller;
  const revision = await writeState(
    api,
    async (state) => {
      u = await reopen(state, caller);
      const payload = parseMKPayload(delta(u.payload));
      if (JSON.stringify(payload) === JSON.stringify(u.payload)) return null;
      u = { ...u, payload };
      return {
        dek_id: u.context.dek_id,
        encrypted_mk: await sealMK(payload, u.dek, u.context),
        recovery: state.recovery,
      };
    },
    undefined,
    known,
  );
  return { ...u, revision };
}

const sameKey = (a: MKResource, b: MKResource) =>
  a.kind === b.kind &&
  a.attempt_id === b.attempt_id &&
  a.owner_seed === b.owner_seed &&
  a.storage_key === b.storage_key &&
  a.monitor_identity_seed === b.monitor_identity_seed;
const sameBinding = (a: MKBinding, b: MKBinding) =>
  JSON.stringify(a) === JSON.stringify(b);

// A binding is set once; a different one for the same key is a conflict.
function mergedBinding(a: MKBinding | null, b: MKBinding | null) {
  if (a && b && !sameBinding(a, b))
    throw new Error("This key is already bound to another resource.");
  return a ?? b;
}
const maxGeneration = (a: number | null, b: number | null) =>
  a === null || b === null ? a : Math.max(a, b);

// Changes one saved key; a key removed meanwhile fails rather than being skipped.
const updateResource =
  (key_id: string, change: (r: MKResource) => MKResource): Delta =>
  (p) => {
    if (!p.resources.some((r) => r.key_id === key_id))
      throw new Error("The key for this resource is no longer saved.");
    return {
      version: 1,
      resources: p.resources.map((r) => (r.key_id === key_id ? change(r) : r)),
    };
  };

export const addResources =
  (added: MKResource[]): Delta =>
  (p) => {
    const resources = [...p.resources];
    for (const r of added) {
      const at = resources.findIndex((e) => e.key_id === r.key_id);
      if (at < 0) {
        resources.push(r);
        continue;
      }
      const existing = resources[at];
      if (!sameKey(existing, r))
        throw new Error("A saved key conflicts with this one.");
      resources[at] = {
        ...existing,
        min_generation: maxGeneration(
          existing.min_generation,
          r.min_generation,
        ),
        binding: mergedBinding(existing.binding, r.binding),
      };
    }
    return { version: 1, resources: order(resources) };
  };

export const bindResource = (key_id: string, binding: MKBinding): Delta =>
  updateResource(key_id, (r) => ({
    ...r,
    binding: mergedBinding(r.binding, binding),
  }));

// Generation floors only rise; concurrent checkpoints merge by maximum.
export const checkpoint = (key_id: string, generation: number): Delta =>
  updateResource(key_id, (r) => {
    if (r.min_generation === null)
      throw new Error("Only a Monitor key has a generation checkpoint.");
    return { ...r, min_generation: Math.max(r.min_generation, generation) };
  });

export const removeResources =
  (key_ids: string[]): Delta =>
  (p) => ({
    version: 1,
    resources: p.resources.filter((r) => !key_ids.includes(r.key_id)),
  });

// Independent random keys per resource; no storage key derives from an owner seed.
export function newResourceKey(
  kind: MKResource["kind"],
  attempt_id: string,
): MKResource {
  const seed = randomBytes(32);
  return {
    key_id: id16(),
    kind,
    attempt_id,
    owner_seed: b64u(seed),
    owner_public_key: ownerPublicKey(seed),
    storage_key: b64u(randomBytes(32)),
    monitor_identity_seed: kind === "sandbox" ? b64u(randomBytes(32)) : null,
    min_generation: kind === "monitor" ? 0 : null,
    binding: null,
  };
}
export const newAttempt = id16;

// --- manual KEK in IndexedDB --------------------------------------------------

type LocalRecord = {
  version: 1;
  kek: string;
  pending: KeyWrite | null;
};
// One store keyed by the frozen record keys, plus one fence key per API and user,
// so a single transaction can check the fence and write or wipe the records.
const DB_NAME = "tinfoil.manual-kek";
const DB_VERSION = 1;
const STORE = "records";
const RECORD_PREFIX = "tinfoil.manual-kek.v1|";
const EPOCH_PREFIX = "tinfoil.manual-kek.epoch|";
const STORAGE_ERROR =
  "This browser could not use its site storage, so nothing was changed. Allow site storage for this site and try again.";
const SIGNED_OUT = "You signed out in another tab. Sign in again.";

let db: Promise<IDBDatabase> | undefined;
function database() {
  if (db) return db;
  const opening = (db = new Promise<IDBDatabase>((resolve, reject) => {
    const req = indexedDB.open(DB_NAME, DB_VERSION);
    req.onupgradeneeded = () => req.result.createObjectStore(STORE);
    req.onerror = () => reject(req.error);
    req.onsuccess = () => {
      const connection = req.result;
      connection.onversionchange = connection.onclose = () => {
        connection.close();
        if (db === opening) db = undefined;
      };
      resolve(connection);
    };
  }));
  opening.catch(() => {
    if (db === opening) db = undefined;
  });
  return opening;
}

const request = <T>(req: IDBRequest<T>) =>
  new Promise<T>((resolve, reject) => {
    req.onsuccess = () => resolve(req.result);
    req.onerror = () => reject(new Error(STORAGE_ERROR));
  });

// Resolves once the transaction has durably committed. `task` may await only
// this transaction's requests; any failure aborts it, so nothing is written.
// Only an operation's own cancellation keeps its AbortError.
async function transact<T>(
  mode: IDBTransactionMode,
  task: (store: IDBObjectStore) => Promise<T>,
): Promise<T> {
  let tx: IDBTransaction;
  try {
    tx = (await database()).transaction(STORE, mode, { durability: "strict" });
  } catch {
    throw new Error(STORAGE_ERROR);
  }
  const done = new Promise<void>((resolve, reject) => {
    tx.oncomplete = () => resolve();
    tx.onabort = () => reject(new Error(STORAGE_ERROR));
  });
  done.catch(() => {});
  try {
    const result = await task(tx.objectStore(STORE));
    await done;
    return result;
  } catch (cause) {
    try {
      tx.abort();
    } catch {}
    throw cause instanceof DOMException && cause.name !== "AbortError"
      ? new Error(STORAGE_ERROR)
      : cause;
  }
}

const epochKey = (api_origin: string, user_id: string) =>
  `${EPOCH_PREFIX}${api_origin}|${user_id}`;
const userRecords = (api_origin: string, user_id: string) => {
  const prefix = `${RECORD_PREFIX}${api_origin}|${user_id}|`;
  return IDBKeyRange.bound(prefix, `${prefix}\uffff`);
};

// The fence and this user's records exactly as stored, read together.
async function read(
  store: IDBObjectStore,
  api_origin: string,
  user_id: string,
) {
  const range = userRecords(api_origin, user_id);
  const reads = [
    store.get(epochKey(api_origin, user_id)),
    store.getAllKeys(range),
    store.getAll(range),
  ] as const;
  const [epoch, keys, values] = await Promise.all([
    request<string | undefined>(reads[0]),
    request(reads[1]),
    request<string[]>(reads[2]),
  ]);
  return {
    epoch: epoch ?? "",
    stored: new Map(keys.map((key, i) => [key as string, values[i]])),
  };
}
const stored = (api_origin: string, user_id: string) =>
  transact("readonly", (store) => read(store, api_origin, user_id));

function records(stored: ReadonlyMap<string, string>) {
  const found: {
    key: string;
    dek_id: string;
    recovery_id: string;
    record: LocalRecord;
  }[] = [];
  for (const [key, value] of stored) {
    const [dek_id, recovery_id, extra] = key.split("|").slice(3);
    const record = parseRecord(value);
    if (isID16(dek_id) && isID16(recovery_id) && extra === undefined && record)
      found.push({ key, dek_id, recovery_id, record });
  }
  return found;
}

function parseRecord(value: string): LocalRecord | undefined {
  try {
    const r = JSON.parse(value);
    unb64u(r.kek, 32);
    return r.version === 1 ? r : undefined;
  } catch {
    return undefined;
  }
}

const recordValue = (kek: Uint8Array, pending: KeyWrite | null) =>
  JSON.stringify({ version: 1, kek: b64u(kek), pending });

// What one sign-in may write under: the epoch it began in and its Clerk session.
// A completed explicit sign-out replaces the epoch with a nonsecret
// "<random>:<Clerk session id>" naming the session it ended.
export type KekFence = { epoch: string; session: string };
const ended = (epoch: string, fence: KekFence) =>
  epoch !== fence.epoch ||
  (!!fence.session && epoch.endsWith(`:${fence.session}`));

export const kekFence = async (
  api_origin: string,
  user_id: string,
  session = "",
): Promise<KekFence> => ({
  epoch: (await stored(api_origin, user_id)).epoch,
  session,
});

// A sign-out completed since the fence was taken, or ended its Clerk session
// (as after a reload that still carries the old session).
export const fenceEnded = async (
  api_origin: string,
  user_id: string,
  fence: KekFence,
) => ended((await stored(api_origin, user_id)).epoch, fence);

// A record write, checked inside its transaction: the operation must still be
// live and no sign-out may have ended its sign-in.
const write = (
  context: { api_origin: string; user_id: string },
  fence: KekFence,
  signal: AbortSignal | undefined,
  task: (store: IDBObjectStore) => IDBRequest,
) =>
  transact("readwrite", async (store) => {
    const epoch = await request<string | undefined>(
      store.get(epochKey(context.api_origin, context.user_id)),
    );
    signal?.throwIfAborted();
    if (ended(epoch ?? "", fence)) throw new Error(SIGNED_OUT);
    await request(task(store));
  });

// Completes an explicit sign-out in one transaction: while the operation is
// live and this user's records are exactly those it settled and offered
// (`covered`), publishes a new epoch naming the ended Clerk session and deletes
// every record. Returns false when the records changed, so the sign-out must be
// settled and offered again; a sign-in another sign-out already ended has
// nothing left to delete.
export function forgetManualKEKs(
  api_origin: string,
  user_id: string,
  fence: KekFence,
  covered: ReadonlyMap<string, string>,
  live = () => true,
) {
  return transact("readwrite", async (store) => {
    const current = await read(store, api_origin, user_id);
    if (!live()) return false;
    if (ended(current.epoch, fence)) return true;
    if (
      current.stored.size !== covered.size ||
      [...current.stored].some(([key, value]) => covered.get(key) !== value)
    )
      return false;
    store.put(
      `${b64u(randomBytes(16))}:${fence.session}`,
      epochKey(api_origin, user_id),
    );
    store.delete(userRecords(api_origin, user_id));
    return true;
  });
}

// Settles setups and recovery additions whose response was lost before a reload.
export async function reconcilePending(
  api: Api,
  user_id: string,
  state: KeyState,
  fence: KekFence,
  signal?: AbortSignal,
): Promise<KeyState> {
  const origin = TARGETS.api_origin!;
  const context = { api_origin: origin, user_id };
  const current = await stored(origin, user_id);
  // Records left by a later sign-in are not this one's to resend.
  if (ended(current.epoch, fence)) return state;
  for (const { key, dek_id, recovery_id, record } of records(current.stored)) {
    if (!record.pending) continue;
    signal?.throwIfAborted();
    const committed = (s: KeyState) =>
      s.dek_id === dek_id &&
      s.recovery.some((r) => r.recovery_id === recovery_id);
    const kek = unb64u(record.kek, 32);
    // Only a write still at its revision can commit now.
    const retry =
      !committed(state) && state.revision === record.pending.expected_revision;
    if (retry)
      try {
        await putKeyState(api, record.pending, signal);
      } catch (cause) {
        if (uncertain(cause)) continue;
      }
    if (retry) state = await readKeyState(api, signal);
    // A sign-out or account switch meanwhile leaves the record for a later sign-in.
    signal?.throwIfAborted();
    await write(context, fence, signal, (store) =>
      committed(state)
        ? store.put(recordValue(kek, null), key)
        : store.delete(key),
    );
  }
  return state;
}

// Before an explicit sign-out deletes this browser's KEKs, settles pending
// recovery commits by their exact write and returns every cached recovery
// file, so it can be saved first; a click elsewhere is no evidence it was. A
// commit still unknown sets `unresolved`.
export async function settlePending(
  api: Api,
  user_id: string,
  fence: KekFence,
  signal?: AbortSignal,
): Promise<{
  files: RecoveryFile[];
  unresolved: boolean;
  covered: ReadonlyMap<string, string>;
}> {
  const origin = TARGETS.api_origin!;
  let current = await stored(origin, user_id);
  if (current.stored.size && !ended(current.epoch, fence)) {
    try {
      const state = await readKeyState(api, signal);
      await reconcilePending(api, user_id, state, fence, signal);
    } catch (cause) {
      if (signal?.aborted) throw cause;
    }
    current = await stored(origin, user_id);
  }
  // Records left by a later sign-in are neither offered nor deleted here.
  if (ended(current.epoch, fence))
    return { files: [], unresolved: false, covered: new Map() };
  // The offer and the records the wipe may delete come from one read: every
  // clean record is offered and every pending one declared, even if the
  // server read above predates it.
  const files: RecoveryFile[] = [];
  let unresolved = false;
  for (const { dek_id, recovery_id, record } of records(current.stored)) {
    if (record.pending) unresolved = true;
    else files.push(recoveryFile(unb64u(record.kek, 32), dek_id, recovery_id));
  }
  return { files, unresolved, covered: current.stored };
}

// --- recovery -----------------------------------------------------------------

export type RecoveryMethod = "passkey" | "manual";
export type RecoveryFile = { filename: string; text: string };

async function recoveryInput(
  method: RecoveryMethod,
  dek: Uint8Array,
  context: MKContext,
  manager: PasskeyKeyManager,
  signal?: AbortSignal,
): Promise<{ input: RecoveryInput; kek?: Uint8Array }> {
  const recovery_id = id16();
  if (method === "manual") {
    const kek = randomBytes(32);
    return {
      kek,
      input: {
        recovery_id,
        type: "manual",
        credential_id: null,
        encrypted_dek: await wrapManualKEK(kek, dek, context, recovery_id),
        created_at: new Date().toISOString(),
      },
    };
  }
  const { wrappedKey } = await manager.createAndWrapKey({
    // A fresh handle keeps authenticators from replacing an earlier credential.
    user: {
      id: randomBytes(32),
      name: "Tinfoil sandbox keys",
      displayName: "Your Tinfoil sandboxes",
    },
    key: dek,
    signal,
  });
  return {
    input: {
      recovery_id,
      type: "passkey",
      credential_id: wrappedKey.credentialId,
      encrypted_dek: encodeWrappedKeyRecord(wrappedKey),
      created_at: new Date().toISOString(),
    },
  };
}

const recoveryFile = (
  kek: Uint8Array,
  dek_id: string,
  recovery_id: string,
) => ({
  filename: `tinfoil-recovery-key-${new Date().toISOString().slice(0, 10)}.txt`,
  text: manualRecoveryFile({ kek, dek_id, recovery_id }),
});

export class SetupLostError extends Error {
  constructor() {
    super(
      "Your keys were set up in another session first. Unlock them with that passkey or recovery key.",
    );
  }
}

// Writes a change that adds `input`. A manual KEK is durably saved with the
// exact write before the server commit; a pending record lets a reload settle
// a lost response.
async function commitRecovery(
  api: Api,
  context: MKContext,
  input: RecoveryInput,
  kek: Uint8Array | undefined,
  fence: KekFence,
  change: (state: KeyState) => Promise<KeyChange | null>,
  signal?: AbortSignal,
): Promise<number> {
  const key = manualKEKStorageKey(context, input.recovery_id);
  const holds = (s: KeyState) =>
    s.dek_id === context.dek_id &&
    s.recovery.some((r) => r.recovery_id === input.recovery_id);
  try {
    const revision = await writeState(
      api,
      async (state) => {
        const next = await change(state);
        if (!next || holds(state)) return null;
        // Passkey prompts and sealing precede this; a sign-out or account change
        // meanwhile, in this or another tab, stores and sends nothing.
        signal?.throwIfAborted();
        if (kek)
          await write(context, fence, signal, (store) =>
            store.put(
              recordValue(kek, { expected_revision: state.revision, ...next }),
              key,
            ),
          );
        return next;
      },
      signal,
    );
    if (kek)
      await write(context, fence, signal, (store) =>
        store.put(recordValue(kek, null), key),
      ).catch(() => {});
    return revision;
  } catch (cause) {
    if (kek && (cause instanceof SetupLostError || !uncertain(cause)))
      await write(context, fence, signal, (store) => store.delete(key)).catch(
        () => {},
      );
    throw cause;
  }
}

// First setup commits MK and its first recovery together. A competing setup
// that won with another DEK leaves this one with nothing to return.
export async function setupMK({
  api,
  manager,
  user_id,
  state,
  method,
  resources,
  signal,
  fence,
}: {
  api: Api;
  manager: PasskeyKeyManager;
  user_id: string;
  state: KeyState;
  method: RecoveryMethod;
  resources: MKResource[];
  signal?: AbortSignal;
  // The caller's sign-in; its writes are refused once a sign-out ends it.
  fence: KekFence;
}): Promise<{ unlocked: Unlocked; file?: RecoveryFile }> {
  if (state.dek_id !== null) throw new SetupLostError();
  const dek = randomBytes(32);
  const context = { api_origin: TARGETS.api_origin!, user_id, dek_id: id16() };
  const payload: MKPayload = { version: 1, resources: order(resources) };
  const { input, kek } = await recoveryInput(
    method,
    dek,
    context,
    manager,
    signal,
  );
  signal?.throwIfAborted();
  const encrypted_mk = await sealMK(payload, dek, context);
  let unlocked: Unlocked = { dek, context, revision: 0, payload };
  const revision = await commitRecovery(
    api,
    context,
    input,
    kek,
    fence,
    async (s) => {
      if (s.dek_id === null)
        return { dek_id: context.dek_id, encrypted_mk, recovery: [input] };
      if (s.dek_id !== context.dek_id) throw new SetupLostError();
      unlocked = await open(s, dek, context);
      return null;
    },
    signal,
  );
  return {
    unlocked: { ...unlocked, revision },
    file: kek && recoveryFile(kek, context.dek_id, input.recovery_id),
  };
}

export async function addRecovery({
  api,
  manager,
  unlocked,
  method,
  signal,
  fence,
}: {
  api: Api;
  manager: PasskeyKeyManager;
  unlocked: Unlocked;
  method: RecoveryMethod;
  signal?: AbortSignal;
  fence: KekFence;
}): Promise<{ unlocked: Unlocked; file?: RecoveryFile }> {
  const { input, kek } = await recoveryInput(
    method,
    unlocked.dek,
    unlocked.context,
    manager,
    signal,
  );
  let u = unlocked;
  const replaced: string[] = [];
  const revision = await commitRecovery(
    api,
    unlocked.context,
    input,
    kek,
    fence,
    async (s) => {
      u = await reopen(s, unlocked);
      // A new recovery key replaces the old one, so there is only ever one.
      const kept = s.recovery.filter(
        (r) => method === "passkey" || r.type !== "manual",
      );
      for (const r of s.recovery)
        if (!kept.includes(r)) replaced.push(r.recovery_id);
      return {
        dek_id: u.context.dek_id,
        encrypted_mk: s.encrypted_mk!,
        recovery: [...kept, input],
      };
    },
    signal,
  );
  await forgetKEKs(unlocked.context, replaced);
  return {
    unlocked: { ...u, revision },
    file: kek && recoveryFile(kek, unlocked.context.dek_id, input.recovery_id),
  };
}

export async function removeRecovery(
  api: Api,
  unlocked: Unlocked,
  recovery_id: string,
  signal?: AbortSignal,
): Promise<Unlocked> {
  let u = unlocked;
  const revision = await writeState(
    api,
    async (s) => {
      u = await reopen(s, unlocked);
      const recovery = s.recovery.filter((r) => r.recovery_id !== recovery_id);
      if (recovery.length === s.recovery.length) return null;
      if (!recovery.length)
        throw new Error("Keep at least one way to unlock your keys.");
      return {
        dek_id: u.context.dek_id,
        encrypted_mk: s.encrypted_mk!,
        recovery,
      };
    },
    signal,
  );
  await forgetKEKs(unlocked.context, [recovery_id]);
  return { ...u, revision };
}

// A removed recovery's wrapped DEK is gone, so a KEK left behind opens nothing.
const forgetKEKs = (context: MKContext, recovery_ids: string[]) =>
  transact("readwrite", (store) =>
    Promise.all(
      recovery_ids.map((id) =>
        request(store.delete(manualKEKStorageKey(context, id))),
      ),
    ),
  ).catch(() => {});

// Forgets keys that can no longer be opened, as read, so the account can start
// over; registered CLI keys stay.
export const resetKeyState = (
  api: Api,
  state: KeyState,
  signal?: AbortSignal,
) =>
  api(KEY_STATE, {
    method: "DELETE",
    body: { expected_revision: state.revision, dek_id: state.dek_id },
    signal,
  });

const contextOf = (state: KeyState, user_id: string): MKContext => {
  if (!state.dek_id)
    throw new Error("No keys are set up for this account yet.");
  return { api_origin: TARGETS.api_origin!, user_id, dek_id: state.dek_id };
};

// A manual KEK saved in this browser for the current DEK, if any.
export async function unlockSaved(
  state: KeyState,
  user_id: string,
): Promise<Unlocked | undefined> {
  const context = contextOf(state, user_id);
  for (const { dek_id, recovery_id, record } of records(
    (await stored(context.api_origin, user_id)).stored,
  )) {
    const chunk = state.recovery.find((r) => r.recovery_id === recovery_id);
    if (dek_id !== context.dek_id || chunk?.type !== "manual") continue;
    const kek = unb64u(record.kek, 32);
    try {
      const dek = await unwrapManualKEK(
        chunk.encrypted_dek,
        kek,
        context,
        recovery_id,
      );
      return await open(state, dek, context);
    } catch {}
  }
}

// Offers the saved recovery key file again after a reload.
export async function savedRecoveryFile(
  state: KeyState,
  user_id: string,
): Promise<RecoveryFile | undefined> {
  for (const r of records(
    (await stored(TARGETS.api_origin!, user_id)).stored,
  )) {
    if (
      r.dek_id === state.dek_id &&
      state.recovery.some((c) => c.recovery_id === r.recovery_id) &&
      !r.record.pending
    )
      return recoveryFile(unb64u(r.record.kek, 32), r.dek_id, r.recovery_id);
  }
}

export async function unlockFile(
  text: string,
  state: KeyState,
  user_id: string,
): Promise<Unlocked> {
  const context = contextOf(state, user_id);
  const file = parseManualRecoveryFile(text);
  const chunk = state.recovery.find((r) => r.recovery_id === file.recovery_id);
  if (file.dek_id !== context.dek_id || chunk?.type !== "manual")
    throw new Error(
      "This recovery key belongs to keys that are no longer in use.",
    );
  const dek = await unwrapManualKEK(
    chunk.encrypted_dek,
    file.kek,
    context,
    file.recovery_id,
  );
  return open(state, dek, context);
}

export async function unlockPasskey(
  manager: PasskeyKeyManager,
  state: KeyState,
  user_id: string,
  signal?: AbortSignal,
): Promise<Unlocked> {
  const context = contextOf(state, user_id);
  const wrappedKeys = state.recovery
    .filter((r) => r.type === "passkey")
    .map((r) => {
      const wrapped = decodeWrappedKeyRecord(r.encrypted_dek);
      if (wrapped.credentialId !== r.credential_id)
        throw new Error("A saved passkey record is damaged.");
      return wrapped;
    });
  if (!wrappedKeys.length)
    throw new Error("No passkey protects these keys. Use your recovery key.");
  const { key } = await manager.recoverKey({ wrappedKeys, signal });
  return open(state, key, context);
}

// Re-reads after a refresh; the unlocked DEK is reused only for the same DEK ID.
export async function refreshUnlocked(
  u: Unlocked | undefined,
  state: KeyState,
): Promise<Unlocked | undefined> {
  if (!u) return u;
  if (state.dek_id !== u.context.dek_id) return undefined;
  return state.revision === u.revision ? u : open(state, u.dek, u.context);
}

// --- messages -----------------------------------------------------------------

export function passkeyMessage(cause: unknown): string {
  if (cause instanceof PasskeyKeyError) {
    if (cause.category === "timeout")
      return "That took a little too long. Try your passkey again, or use a recovery key.";
    if (cause.category === "operation_in_progress")
      return "There's already a passkey prompt open. Finish that one, then try again.";
    if (cause.category === "cancelled")
      return "The passkey prompt was closed or your device declined it. Try again, or use a recovery key.";
  }
  return cause instanceof Error
    ? cause.message
    : "We couldn't use your passkey. Try again or use a recovery key.";
}
