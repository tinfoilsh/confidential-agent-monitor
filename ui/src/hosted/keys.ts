import { ed25519 } from "@noble/curves/ed25519.js";
import { hkdf } from "@noble/hashes/hkdf.js";
import { sha256 } from "@noble/hashes/sha2.js";
import {
  bytesToHex,
  concatBytes,
  hexToBytes,
  randomBytes,
  utf8ToBytes,
} from "@noble/hashes/utils.js";
import {
  PasskeyKeyError,
  createInsecureBrowserLocalStoragePasskeyKeyStorage,
  createPasskeyKeyManager,
  decodeWrappedKeyRecord,
  encodeWrappedKeyRecord,
  type PasskeyKeyManager,
  type PasskeyKeyProfile,
} from "@tinfoilsh/passkey-kit";

export const DASHBOARD = "https://dash.tinfoil.sh/?tab=sandboxes";

// The owner key, as the dashboard and CLI see it. One per account: an Ed25519
// SSH keypair whose public half every Monitor and sandbox is locked to. The
// private key is encrypted under a random data key, and the data key is
// wrapped by each of the owner's passkeys, like chat's key bundles. Everything
// but the public key is opaque outside this file.
export type OwnerPasskey = { credential_id: string; wrapped_data_key: string };
export type OwnerKey = {
  public_key: string; // "ssh-ed25519 <base64>"
  encrypted_private_key: string;
  passkeys: OwnerPasskey[];
};

// Keep the deployed console profile stable: changing it orphans every wrapped key.
export const PROFILE: PasskeyKeyProfile = {
  version: 1,
  relyingPartyId:
    globalThis.location?.hostname === "localhost" ? "localhost" : "tinfoil.sh",
  prfSalt: utf8ToBytes("tinfoil-console-key-encryption"),
  hkdfInfo: utf8ToBytes("tinfoil-console-kek-v1"),
};

// The passkey's PRF output is cached in this browser, as chat caches it, so
// reopening a Monitor does not prompt again. "Lock" clears it.
export const passkeys = () =>
  createPasskeyKeyManager({
    profile: PROFILE,
    relyingPartyName: "Tinfoil",
    enrollmentAttachment: "any",
    storage:
      createInsecureBrowserLocalStoragePasskeyKeyStorage("tinfoil-console"),
  });

const SSH_PREFIX = new Uint8Array([
  0,
  0,
  0,
  11,
  ...utf8ToBytes("ssh-ed25519"),
  0,
  0,
  0,
  32,
]);
const b64 = (bytes: Uint8Array) => btoa(String.fromCharCode(...bytes));
const unb64 = (text: string) =>
  Uint8Array.from(atob(text), (c) => c.charCodeAt(0));

// authorized_keys line for a 32-byte Ed25519 public key.
export const sshPublicKey = (raw: Uint8Array) =>
  "ssh-ed25519 " + b64(concatBytes(SSH_PREFIX, raw));

// The form Monitors and sandboxes measure as their owner.
export function measuredPublicKey(line: string): string {
  const fields = line.trim().split(/\s+/);
  if (fields[0] !== "ssh-ed25519" || !fields[1])
    throw new Error("The owner key is not an Ed25519 SSH public key.");
  const wire = unb64(fields[1]);
  if (
    wire.length !== SSH_PREFIX.length + 32 ||
    SSH_PREFIX.some((byte, i) => byte !== wire[i])
  )
    throw new Error("The owner key is not an Ed25519 SSH public key.");
  return "ed25519:" + b64(wire.subarray(SSH_PREFIX.length));
}

// The Monitor's encrypted store key is derived from the owner's signing seed,
// so nothing beyond the owner key needs to be kept. Labels are shared with
// deployed Monitors; keep them stable.
export const storageKey = (seed: Uint8Array, bucket: string) =>
  hkdf(sha256, seed, undefined, utf8ToBytes("monitor-storage-v1" + bucket), 32);

// --- private key under the data key (AES-256-GCM) -------------------------

const PRIVATE_KEY_VERSION = "v1";
const subtle = () => globalThis.crypto.subtle;
// WebCrypto wants a plain ArrayBuffer-backed view.
const buf = (bytes: Uint8Array) =>
  new Uint8Array(bytes) as Uint8Array<ArrayBuffer>;

async function aesKey(dataKey: Uint8Array, usage: KeyUsage) {
  if (dataKey.length !== 32) throw new Error("Invalid data key.");
  return subtle().importKey("raw", buf(dataKey), "AES-GCM", false, [usage]);
}

// "v1.<iv hex>.<ciphertext hex>" over the 32-byte Ed25519 seed.
export async function encryptPrivateKey(
  seed: Uint8Array,
  dataKey: Uint8Array,
): Promise<string> {
  const iv = randomBytes(12);
  const key = await aesKey(dataKey, "encrypt");
  const sealed = new Uint8Array(
    await subtle().encrypt({ name: "AES-GCM", iv: buf(iv) }, key, buf(seed)),
  );
  return [PRIVATE_KEY_VERSION, bytesToHex(iv), bytesToHex(sealed)].join(".");
}

export async function decryptPrivateKey(
  encrypted: string,
  dataKey: Uint8Array,
): Promise<Uint8Array> {
  const [version, iv, sealed] = encrypted.split(".");
  if (
    version !== PRIVATE_KEY_VERSION ||
    !/^[0-9a-f]{24}$/.test(iv ?? "") ||
    !/^[0-9a-f]{96}$/.test(sealed ?? "")
  )
    throw new Error("The owner key record is damaged.");
  const key = await aesKey(dataKey, "decrypt");
  try {
    const seed = new Uint8Array(
      await subtle().decrypt(
        { name: "AES-GCM", iv: buf(hexToBytes(iv)) },
        key,
        buf(hexToBytes(sealed)),
      ),
    );
    if (seed.length !== 32) throw new Error();
    return seed;
  } catch {
    throw new Error(
      "This key does not open the owner key. Use the passkey or data key you set up with.",
    );
  }
}

// --- passkey records --------------------------------------------------------

export function passkeyRecord(passkey: OwnerPasskey) {
  const wrapped = decodeWrappedKeyRecord(passkey.wrapped_data_key);
  if (
    wrapped.profile.relyingPartyId !== PROFILE.relyingPartyId ||
    bytesToHex(wrapped.profile.prfSalt) !== bytesToHex(PROFILE.prfSalt) ||
    bytesToHex(wrapped.profile.hkdfInfo) !== bytesToHex(PROFILE.hkdfInfo)
  )
    throw new Error("This key bundle belongs to a different application.");
  if (wrapped.credentialId !== passkey.credential_id)
    throw new Error("The owner key record is damaged.");
  return wrapped;
}

export function validateOwnerKey(record: OwnerKey): OwnerKey {
  measuredPublicKey(record.public_key);
  if (
    typeof record.encrypted_private_key !== "string" ||
    record.encrypted_private_key.length > 1_000
  )
    throw new Error("The owner key record is damaged.");
  if (!Array.isArray(record.passkeys) || record.passkeys.length > 64)
    throw new Error("The owner key record is damaged.");
  record.passkeys.forEach(passkeyRecord);
  return {
    public_key: record.public_key.trim(),
    encrypted_private_key: record.encrypted_private_key,
    passkeys: record.passkeys.map(({ credential_id, wrapped_data_key }) => ({
      credential_id,
      wrapped_data_key,
    })),
  };
}

// --- setup (/start) ---------------------------------------------------------

export type Setup = {
  key: OwnerKey;
  passkey?: OwnerPasskey;
  // Without a passkey the data key itself is what the owner keeps.
  recovery?: { filename: string; text: string };
};

// A fresh keypair and data key. The data key is 32 random bytes; the
// private key never exists outside this tab unencrypted.
async function newOwnerKey() {
  const seed = randomBytes(32);
  const dataKey = randomBytes(32);
  try {
    const key: OwnerKey = {
      public_key: sshPublicKey(ed25519.getPublicKey(seed)),
      encrypted_private_key: await encryptPrivateKey(seed, dataKey),
      passkeys: [],
    };
    return { key, dataKey };
  } finally {
    seed.fill(0);
  }
}

export async function setupPasskey(
  manager: PasskeyKeyManager,
  signal: AbortSignal,
): Promise<Setup> {
  signal.throwIfAborted();
  const { key, dataKey } = await newOwnerKey();
  try {
    const { wrappedKey } = await manager.createAndWrapKey({
      user: {
        // A fresh handle prevents authenticators replacing an earlier credential.
        id: concatBytes(utf8ToBytes("tinfoil-console/"), randomBytes(32)),
        name: "Tinfoil sandbox key",
        displayName: "Your Tinfoil sandboxes",
      },
      key: dataKey,
      signal,
    });
    signal.throwIfAborted();
    const passkey: OwnerPasskey = {
      credential_id: wrappedKey.credentialId,
      wrapped_data_key: encodeWrappedKeyRecord(wrappedKey),
    };
    return { key: { ...key, passkeys: [passkey] }, passkey };
  } finally {
    dataKey.fill(0);
  }
}

// Without a passkey the owner keeps the data key, as chat keeps its
// encryption key: shown once, downloadable, never stored by this page.
export async function setupLocal(): Promise<Setup> {
  const { key, dataKey } = await newOwnerKey();
  try {
    const text = [
      "-----BEGIN TINFOIL SANDBOX DATA KEY-----",
      bytesToHex(dataKey),
      "-----END TINFOIL SANDBOX DATA KEY-----",
      "",
    ].join("\n");
    return {
      key,
      recovery: {
        filename: `tinfoil-sandbox-key-${new Date().toISOString().slice(0, 10)}.pem`,
        text,
      },
    };
  } finally {
    dataKey.fill(0);
  }
}

export function parseDataKey(text: string): Uint8Array {
  const hex = text
    .split("\n")
    .map((line) => line.trim())
    .filter((line) => line && !line.startsWith("-----"))
    .join("");
  if (!/^[0-9a-f]{64}$/i.test(hex))
    throw new Error("This file is not a Tinfoil sandbox data key.");
  return hexToBytes(hex.toLowerCase());
}

// Back to the dashboard. Everything rides in the fragment, which browsers
// never send to a server, and the dashboard's one-time state comes back with
// it so a link made elsewhere cannot plant a key.
export const RETURN_PARAMS = {
  publicKey: "owner_key",
  privateKey: "owner_key_private",
  credentialId: "owner_key_credential",
  dataKey: "owner_key_wrapped",
  state: "owner_key_state",
} as const;

export function dashboardURL(setup: Setup, state: string): string {
  const url = new URL(DASHBOARD);
  const params = new URLSearchParams({
    [RETURN_PARAMS.publicKey]: setup.key.public_key,
    [RETURN_PARAMS.privateKey]: setup.key.encrypted_private_key,
    [RETURN_PARAMS.state]: state,
  });
  if (setup.passkey) {
    params.set(RETURN_PARAMS.credentialId, setup.passkey.credential_id);
    params.set(RETURN_PARAMS.dataKey, setup.passkey.wrapped_data_key);
  }
  url.hash = params.toString();
  return url.href;
}

// The state the dashboard sent along with /start, if any.
export const setupState = (url: URL) =>
  new URLSearchParams(url.hash.slice(1)).get("state") ??
  url.searchParams.get("state") ??
  "";

// --- opening a Monitor ------------------------------------------------------

// Recovers the owner's signing seed: a passkey unwraps the data key, or the
// owner supplies the data key file; either decrypts the private key.
export async function recoverOwnerSeed(
  record: OwnerKey,
  manager: PasskeyKeyManager,
  signal: AbortSignal,
  dataKeyFile?: string,
): Promise<Uint8Array> {
  signal.throwIfAborted();
  let dataKey: Uint8Array | undefined;
  try {
    if (dataKeyFile) dataKey = parseDataKey(dataKeyFile);
    else if (record.passkeys.length) {
      dataKey = (
        await manager.recoverKey({
          wrappedKeys: record.passkeys.map(passkeyRecord),
          signal,
        })
      ).key;
    } else
      throw new Error(
        "Choose the data key file you saved when setting up this key.",
      );
    signal.throwIfAborted();
    return await decryptPrivateKey(record.encrypted_private_key, dataKey);
  } catch (cause) {
    manager.clearLocalState();
    throw cause;
  } finally {
    dataKey?.fill(0);
  }
}

export const unavailablePasskey = (cause: unknown) =>
  cause instanceof PasskeyKeyError &&
  (cause.category === "unsupported" || cause.category === "cancelled");

export function passkeyMessage(cause: unknown): string {
  if (cause instanceof PasskeyKeyError) {
    if (cause.category === "timeout")
      return "That took a little too long. Try your passkey again, or continue with a data key.";
    if (cause.category === "operation_in_progress")
      return "There's already a passkey prompt open. Finish that one, then try again.";
  }
  return "We couldn't finish setting up your passkey. You can try again or use a data key instead.";
}
