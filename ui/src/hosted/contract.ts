import { ed25519 } from "@noble/curves/ed25519.js";
import { sha256 } from "@noble/hashes/sha2.js";
import { bytesToHex, concatBytes, utf8ToBytes } from "@noble/hashes/utils.js";
import { KEM_DHKEM_X25519_HKDF_SHA256 } from "@panva/hpke-noble";
import type { PasskeyKeyProfile } from "@tinfoilsh/passkey-kit";
import { AEAD_AES_256_GCM, CipherSuite, KDF_HKDF_SHA256 } from "hpke";

// Wire formats shared with the CLI and Dashboard.

export const PRF_PROFILES: Record<
  "production" | "development",
  PasskeyKeyProfile
> = {
  production: {
    version: 1,
    relyingPartyId: "terminal.tinfoil.sh",
    prfSalt: utf8ToBytes("tinfoil-terminal-dek-v1"),
    hkdfInfo: utf8ToBytes("tinfoil-terminal-kek-v1"),
  },
  development: {
    version: 1,
    relyingPartyId: "local.tinfoil.sh",
    prfSalt: utf8ToBytes("tinfoil-terminal-dek-dev-v1"),
    hkdfInfo: utf8ToBytes("tinfoil-terminal-kek-dev-v1"),
  },
};

const MAX_MK_ENVELOPE = 262144;
// The largest plaintext whose "mk1." envelope fits MAX_MK_ENVELOPE.
const MAX_MK_PLAINTEXT = 196576;
const MAX_MK_RESOURCES = 256;
const MANUAL_WRAPPED_CHARS = 86;
const MAX_KEY_SYNC_PAYLOAD = 8192;
const CONFIRM_ALPHABET = "ABCDEFGHJKLMNPQRSTUVWXYZ";
export const CONFIRMATION_CODE_LENGTH = 6;
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;
const USER = /^user_[A-Za-z0-9]{1,64}$/;
const ACCOUNT = /^(personal|org_[A-Za-z0-9]{1,64})$/;

function fail(
  message = "This record is damaged or uses an unsupported format.",
): never {
  throw new Error(message);
}

export function b64u(bytes: Uint8Array): string {
  let binary = "";
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary)
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=+$/, "");
}

export function unb64u(text: unknown, length?: number): Uint8Array {
  if (
    typeof text !== "string" ||
    !/^[A-Za-z0-9_-]*$/.test(text) ||
    text.length % 4 === 1
  )
    fail();
  const padded =
    text.replace(/-/g, "+").replace(/_/g, "/") +
    "=".repeat((4 - (text.length % 4)) % 4);
  const bytes = Uint8Array.from(atob(padded), (c) => c.charCodeAt(0));
  if (b64u(bytes) !== text || (length !== undefined && bytes.length !== length))
    fail();
  return bytes;
}

const std64 = (bytes: Uint8Array) => btoa(String.fromCharCode(...bytes));
export const ownerPublicKey = (seed: Uint8Array) =>
  "ed25519:" + std64(ed25519.getPublicKey(seed));
export const isID16 = (value: unknown) => {
  try {
    return unb64u(value, 16).length === 16;
  } catch {
    return false;
  }
};

// Exactly these own keys, or nothing.
function exact(value: unknown, keys: string[]): Record<string, unknown> {
  if (!value || typeof value !== "object" || Array.isArray(value)) fail();
  const own = Object.keys(value);
  if (own.length !== keys.length || own.some((key) => !keys.includes(key)))
    fail();
  return value as Record<string, unknown>;
}

function aad(...fields: string[]): Uint8Array<ArrayBuffer> {
  if (fields.some((field) => !/^[\x21-\x7e]+$/.test(field)))
    fail("Invalid authenticated context.");
  return new Uint8Array(utf8ToBytes(fields.join("\0")));
}

// --- MK -----------------------------------------------------------------------

export type MKContext = { api_origin: string; user_id: string; dek_id: string };
export type MKBinding = {
  account: string;
  container_id: string;
  instance_id: string | null;
  volume_id: string | null;
  bucket: string | null;
};
export type MKResource = {
  key_id: string;
  kind: "monitor" | "sandbox";
  attempt_id: string;
  owner_seed: string;
  owner_public_key: string;
  storage_key: string;
  monitor_identity_seed: string | null;
  min_generation: number | null;
  binding: MKBinding | null;
};
export type MKPayload = { version: 1; resources: MKResource[] };

function binding(value: unknown, sandbox: boolean): MKBinding | null {
  if (value === null) return null;
  const b = exact(value, [
    "account",
    "container_id",
    "instance_id",
    "volume_id",
    "bucket",
  ]);
  const uuid = (v: unknown) => typeof v === "string" && UUID.test(v);
  const ok = sandbox
    ? uuid(b.instance_id) && uuid(b.volume_id) && b.bucket === null
    : b.instance_id === null &&
      b.volume_id === null &&
      typeof b.bucket === "string" &&
      /^[\x21-\x7e]{1,512}$/.test(b.bucket);
  if (!ACCOUNT.test(String(b.account)) || !uuid(b.container_id) || !ok) fail();
  return b as MKBinding;
}

function resource(value: unknown): MKResource {
  const r = exact(value, [
    "key_id",
    "kind",
    "attempt_id",
    "owner_seed",
    "owner_public_key",
    "storage_key",
    "monitor_identity_seed",
    "min_generation",
    "binding",
  ]);
  const sandbox = r.kind === "sandbox";
  if (
    !isID16(r.key_id) ||
    !isID16(r.attempt_id) ||
    (!sandbox && r.kind !== "monitor") ||
    r.owner_public_key !== ownerPublicKey(unb64u(r.owner_seed, 32)) ||
    unb64u(r.storage_key, 32).length !== 32 ||
    (sandbox
      ? unb64u(r.monitor_identity_seed, 32).length !== 32 ||
        r.min_generation !== null
      : r.monitor_identity_seed !== null ||
        !Number.isSafeInteger(r.min_generation) ||
        (r.min_generation as number) < 0)
  )
    fail();
  return {
    key_id: r.key_id as string,
    kind: r.kind as MKResource["kind"],
    attempt_id: r.attempt_id as string,
    owner_seed: r.owner_seed as string,
    owner_public_key: r.owner_public_key as string,
    storage_key: r.storage_key as string,
    monitor_identity_seed: r.monitor_identity_seed as string | null,
    min_generation: r.min_generation as number | null,
    binding: binding(r.binding, sandbox),
  };
}

// Canonical order: validate a payload and rebuild it with the frozen field order.
export function parseMKPayload(value: unknown): MKPayload {
  const p = exact(typeof value === "string" ? JSON.parse(value) : value, [
    "version",
    "resources",
  ]);
  if (
    p.version !== 1 ||
    !Array.isArray(p.resources) ||
    p.resources.length > MAX_MK_RESOURCES
  )
    fail();
  const resources = p.resources.map(resource);
  const owners = new Set(resources.map((r) => r.owner_public_key));
  if (
    owners.size !== resources.length ||
    resources.some((r, i) => i > 0 && resources[i - 1].key_id >= r.key_id)
  )
    fail();
  return { version: 1, resources };
}

function contextFields(c: MKContext) {
  if (!USER.test(c.user_id) || !isID16(c.dek_id))
    fail("Invalid key bundle context.");
  return [c.api_origin, c.user_id, c.dek_id];
}
const mkAAD = (c: MKContext) => aad("tinfoil-mk-v1", ...contextFields(c));

const aesKey = (key: Uint8Array, usage: KeyUsage) =>
  crypto.subtle.importKey("raw", new Uint8Array(key), "AES-GCM", false, [
    usage,
  ]);

async function seal(
  prefix: string,
  key: Uint8Array,
  plain: Uint8Array,
  additionalData: Uint8Array<ArrayBuffer>,
) {
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const sealed = await crypto.subtle.encrypt(
    { name: "AES-GCM", iv, additionalData },
    await aesKey(key, "encrypt"),
    new Uint8Array(plain),
  );
  return `${prefix}${b64u(iv)}.${b64u(new Uint8Array(sealed))}`;
}

async function open(
  prefix: string,
  sealed: string,
  maxChars: number,
  key: Uint8Array,
  additionalData: Uint8Array<ArrayBuffer>,
) {
  // Bound the encoded size before decoding allocates.
  if (sealed.length > maxChars) fail();
  const [iv, ciphertext, extra] = sealed.startsWith(prefix)
    ? sealed.slice(prefix.length).split(".")
    : [];
  const nonce = unb64u(iv, 12);
  const body = unb64u(ciphertext);
  if (extra !== undefined) fail();
  try {
    return new Uint8Array(
      await crypto.subtle.decrypt(
        { name: "AES-GCM", iv: new Uint8Array(nonce), additionalData },
        await aesKey(key, "decrypt"),
        new Uint8Array(body),
      ),
    );
  } catch {
    fail("This key does not open this record for this account.");
  }
}

export async function sealMK(
  payload: MKPayload,
  dek: Uint8Array,
  context: MKContext,
): Promise<string> {
  const plain = utf8ToBytes(JSON.stringify(parseMKPayload(payload)));
  if (plain.length > MAX_MK_PLAINTEXT) fail("The key bundle is too large.");
  return seal("mk1.", dek, plain, mkAAD(context));
}

export async function openMK(
  envelope: string,
  dek: Uint8Array,
  context: MKContext,
): Promise<MKPayload> {
  const text = new TextDecoder("utf-8", { fatal: true }).decode(
    await open("mk1.", envelope, MAX_MK_ENVELOPE, dek, mkAAD(context)),
  );
  const payload = parseMKPayload(text);
  // Only the canonical encoding is accepted, as in Go.
  if (JSON.stringify(payload) !== text) fail();
  return payload;
}

// --- manual recovery KEK ----------------------------------------------------

const manualAAD = (c: MKContext, recoveryID: string) => {
  if (!isID16(recoveryID)) fail();
  return aad("tinfoil-manual-kek-v1", ...contextFields(c), recoveryID);
};

export const wrapManualKEK = (
  kek: Uint8Array,
  dek: Uint8Array,
  c: MKContext,
  recoveryID: string,
) => seal("kek1.", kek, dek, manualAAD(c, recoveryID));

export async function unwrapManualKEK(
  wrapped: string,
  kek: Uint8Array,
  c: MKContext,
  recoveryID: string,
) {
  const dek = await open(
    "kek1.",
    wrapped,
    MANUAL_WRAPPED_CHARS,
    kek,
    manualAAD(c, recoveryID),
  );
  if (dek.length !== 32) fail();
  return dek;
}

const FILE_BEGIN = "-----BEGIN TINFOIL RECOVERY KEY-----";
const FILE_END = "-----END TINFOIL RECOVERY KEY-----";
export type ManualRecovery = {
  kek: Uint8Array;
  dek_id: string;
  recovery_id: string;
};

export const manualRecoveryFile = (r: ManualRecovery) =>
  `${FILE_BEGIN}\n${JSON.stringify({ version: 1, kek: b64u(r.kek), dek_id: r.dek_id, recovery_id: r.recovery_id })}\n${FILE_END}\n`;

export function parseManualRecoveryFile(text: string): ManualRecovery {
  const lines = text.trim().split(/\r?\n/);
  if (lines.length !== 3 || lines[0] !== FILE_BEGIN || lines[2] !== FILE_END)
    fail("This file is not a Tinfoil recovery key.");
  const r = exact(JSON.parse(lines[1]), [
    "version",
    "kek",
    "dek_id",
    "recovery_id",
  ]);
  if (r.version !== 1 || !isID16(r.dek_id) || !isID16(r.recovery_id))
    fail("This file is not a Tinfoil recovery key.");
  const recovery = {
    kek: unb64u(r.kek, 32),
    dek_id: r.dek_id as string,
    recovery_id: r.recovery_id as string,
  };
  if (manualRecoveryFile(recovery) !== lines.join("\n") + "\n")
    fail("This file is not a Tinfoil recovery key.");
  return recovery;
}

export const manualKEKStorageKey = (c: MKContext, recoveryID: string) =>
  ["tinfoil.manual-kek.v1", c.api_origin, c.user_id, c.dek_id, recoveryID].join(
    "|",
  );

// --- CLI key sync ----------------------------------------------------------------

export type KeySyncTargets = {
  terminal: string;
  api_origin: string;
  callback: string;
  completion: string;
};
export type KeySyncRequest = {
  hpke_pubkey: Uint8Array;
  request: string;
  user: string;
  account: string;
  expires: number;
};

function fragment(hash: string, keys: string[]): Record<string, string> {
  const params = new URLSearchParams(hash.replace(/^#/, ""));
  const out: Record<string, string> = {};
  for (const [key, value] of params) {
    if (!keys.includes(key) || key in out) fail("This link is not valid.");
    out[key] = value;
  }
  if (Object.keys(out).length !== keys.length || out.v !== "1")
    fail("This link is not valid.");
  return out;
}

export function parseKeySyncLaunch(
  hash: string,
  nowSeconds: number,
): KeySyncRequest {
  const f = fragment(hash, [
    "v",
    "hpke_pubkey",
    "request",
    "user",
    "account",
    "expires",
  ]);
  const expires = Number(f.expires);
  if (
    String(expires) !== f.expires ||
    !Number.isSafeInteger(expires) ||
    expires <= nowSeconds ||
    expires - nowSeconds > 600 ||
    !USER.test(f.user) ||
    !ACCOUNT.test(f.account)
  )
    fail("This key-sync request has expired or is not valid.");
  unb64u(f.request, 32);
  return {
    hpke_pubkey: unb64u(f.hpke_pubkey, 32),
    request: f.request,
    user: f.user,
    account: f.account,
    expires,
  };
}

export function canonicalKeySyncRequest(
  r: KeySyncRequest,
  t: KeySyncTargets,
): Uint8Array {
  const lines = [
    "tinfoil-cli-key-sync-v1",
    `hpke_pubkey=${b64u(r.hpke_pubkey)}`,
    `request=${r.request}`,
    `user=${r.user}`,
    `account=${r.account}`,
    `expires=${r.expires}`,
    `api_origin=${t.api_origin}`,
    `callback=${t.callback}`,
    `completion=${t.completion}`,
  ];
  return utf8ToBytes(lines.map((line) => line + "\n").join(""));
}

export function confirmationCode(canonical: Uint8Array): string {
  const digest = sha256(
    concatBytes(utf8ToBytes("tinfoil-cli-confirm-v1"), canonical),
  );
  let value = BigInt("0x" + bytesToHex(digest.subarray(0, 8))) % 24n ** 6n;
  let code = "";
  for (let i = 0; i < 6; i++, value /= 24n)
    code = CONFIRM_ALPHABET[Number(value % 24n)] + code;
  return `${code.slice(0, 3)}-${code.slice(3)}`;
}

export function confirmationCodeMatches(
  input: string,
  expected: string,
): boolean {
  const typed = input
    .replace(/[ \t-]/g, "")
    .replace(/[a-z]/g, (c) => c.toUpperCase());
  const want = expected.replace("-", "");
  if (
    typed.length !== 6 ||
    [...typed].some((c) => !CONFIRM_ALPHABET.includes(c))
  )
    return false;
  let diff = 0;
  for (let i = 0; i < 6; i++) diff |= typed.charCodeAt(i) ^ want.charCodeAt(i);
  return diff === 0;
}

const keySyncSuite = () =>
  new CipherSuite(
    KEM_DHKEM_X25519_HKDF_SHA256,
    KDF_HKDF_SHA256,
    AEAD_AES_256_GCM,
  );
export const keySyncEnvelopeInfo = (canonical: Uint8Array) =>
  concatBytes(
    utf8ToBytes("tinfoil-cli-key-sync-envelope-v1\0"),
    sha256(canonical),
  );

export type KeySyncEnvelope = {
  user_id: string;
  dek: { dek_id: string; dek: Uint8Array };
};

// Seals keys for the confirmed CLI request; OAuth codes and tokens never enter this handoff.
export async function sealKeySyncEnvelope(
  r: KeySyncRequest,
  t: KeySyncTargets,
  e: KeySyncEnvelope,
): Promise<string> {
  if (
    !USER.test(e.user_id) ||
    e.user_id !== r.user ||
    !e.dek ||
    !isID16(e.dek.dek_id) ||
    e.dek.dek.length !== 32
  )
    fail("Invalid key-sync result.");
  const body = {
    v: 1,
    request: r.request,
    user_id: e.user_id,
    expires: r.expires,
    dek_id: e.dek.dek_id,
    dek: b64u(e.dek.dek),
  };
  const suite = keySyncSuite();
  const { encapsulatedSecret, ciphertext } = await suite.Seal(
    await suite.DeserializePublicKey(r.hpke_pubkey),
    utf8ToBytes(JSON.stringify(body)),
    { info: keySyncEnvelopeInfo(canonicalKeySyncRequest(r, t)) },
  );
  const payload = b64u(concatBytes(encapsulatedSecret, ciphertext));
  if (payload.length > MAX_KEY_SYNC_PAYLOAD)
    fail("The key-sync result is too large.");
  return payload;
}

export const keySyncCallbackURL = (t: KeySyncTargets, payload: string) =>
  `${t.callback}?payload=${payload}`;

export function parseKeySyncCompletion(hash: string) {
  const f = fragment(hash, ["v", "request", "user", "account"]);
  if (!USER.test(f.user) || !ACCOUNT.test(f.account))
    fail("This link is not valid.");
  unb64u(f.request, 32);
  return { request: f.request, user: f.user, account: f.account };
}

// --- /start -------------------------------------------------------------------

export type StartRole = "monitor" | "sandbox";
export type StartRequest = {
  state: string;
  user: string;
  account: string;
  mode: "tmk" | "umk";
  roles: StartRole[];
};

export function parseStartRequest(hash: string): StartRequest {
  const f = fragment(hash, ["v", "state", "user", "account", "mode", "roles"]);
  if (
    !USER.test(f.user) ||
    !ACCOUNT.test(f.account) ||
    !["tmk", "umk"].includes(f.mode) ||
    !["monitor", "sandbox", "monitor,sandbox"].includes(f.roles)
  )
    fail("This setup link is not valid.");
  unb64u(f.state, 32);
  return {
    state: f.state,
    user: f.user,
    account: f.account,
    mode: f.mode as StartRequest["mode"],
    roles: f.roles.split(",") as StartRole[],
  };
}

export function startReturnURL(
  dashboard: string,
  request: StartRequest,
  keys: Record<StartRole, { public_key: string; key_id: string }>,
) {
  const params = new URLSearchParams({
    v: "1",
    state: request.state,
    mode: request.mode,
  });
  for (const role of request.roles) {
    params.set(role, keys[role].public_key);
    params.set(`${role}_key_id`, keys[role].key_id);
  }
  return `${dashboard}#${params}`;
}

export const startErrorURL = (
  dashboard: string,
  state: string,
  error: "cancelled" | "account_mismatch" | "setup_lost" | "unsupported",
) => `${dashboard}#${new URLSearchParams({ v: "1", state, error })}`;
