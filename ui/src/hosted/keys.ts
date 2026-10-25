import { ed25519 } from "@noble/curves/ed25519.js";
import { hkdf } from "@noble/hashes/hkdf.js";
import { sha256 } from "@noble/hashes/sha2.js";
import {
  bytesToHex,
  concatBytes,
  randomBytes,
  utf8ToBytes,
} from "@noble/hashes/utils.js";
import {
  PasskeyKeyError,
  createInsecureBrowserLocalStoragePasskeyKeyStorage,
  createPasskeyKeyManager,
  type PasskeyKeyManager,
  type PasskeyKeyProfile,
  type PasskeyUser,
  type WrappedKey,
} from "@tinfoilsh/passkey-kit";

const KEY_BYTES = 32;
const KEY_ID_BYTES = 16;
const HANDLE_PREFIX = utf8ToBytes("tinfoil-console/");
const HANDLE_BYTES = 32;
const KEY_ID = /^[0-9a-f]{32}$/;
const KEK_IV = /^[0-9a-f]{24}$/;
const WRAPPED_KEY = /^[0-9a-f]{96}$/;
// WebAuthn credential IDs are at most 1023 bytes, unpadded base64url here.
const CREDENTIAL_ID = /^[A-Za-z0-9_-]{1,1364}$/;

// The console's own profile: Chat passkeys and bundles cannot unlock it.
export const PROFILE: PasskeyKeyProfile = {
  version: 1,
  relyingPartyId:
    globalThis.location?.hostname === "localhost" ? "localhost" : "tinfoil.sh",
  prfSalt: utf8ToBytes("tinfoil-console-key-encryption"),
  hkdfInfo: utf8ToBytes("tinfoil-console-kek-v1"),
};

export const toBase64 = (bytes: Uint8Array) =>
  btoa(String.fromCharCode(...bytes));

export function passkeys(userId: string): PasskeyKeyManager {
  return createPasskeyKeyManager({
    profile: PROFILE,
    relyingPartyName: "Tinfoil Console",
    // The browser offers both built-in passkeys and security keys.
    enrollmentAttachment: "any",
    storage: createInsecureBrowserLocalStoragePasskeyKeyStorage(
      `tinfoil-console/${userId}`,
    ),
  });
}

export const keyId = (key: Uint8Array) =>
  bytesToHex(
    hkdf(
      sha256,
      key,
      undefined,
      utf8ToBytes("tinfoil-key-id-v1"),
      KEY_ID_BYTES,
    ),
  );

const UNREADABLE =
  "This browser is not letting the console read its site storage, where your console key is saved. Allow site data for this site and reload.";
const DAMAGED =
  "The console key saved in this browser is damaged, so it cannot be unlocked here. It has not been replaced.";
const UNSAVED =
  "This browser could not save your console key. Its storage may be full or blocked.";
const UNCOORDINATED =
  "This browser cannot coordinate saving the console key between tabs. Use a current browser.";
const RACED =
  "Another tab just set up the console key for this account. Unlock again with that passkey.";
const STALE = "Your console key changed in another tab. Lock and unlock again.";

type Bundle = { credential_id: string; kek_iv: string; encrypted_keys: string };
export type KeyRecord = { key_id: string; bundles: Record<string, Bundle> };

const matches = (pattern: RegExp, value: unknown) =>
  typeof value === "string" && pattern.test(value);

const validRecord = (record: KeyRecord | null) =>
  !!record &&
  typeof record === "object" &&
  matches(KEY_ID, record.key_id) &&
  !!record.bundles &&
  typeof record.bundles === "object" &&
  !Array.isArray(record.bundles) &&
  Object.keys(record.bundles).length > 0 &&
  Object.entries(record.bundles).every(
    ([id, bundle]) =>
      matches(CREDENTIAL_ID, id) &&
      bundle?.credential_id === id &&
      matches(KEK_IV, bundle.kek_iv) &&
      matches(WRAPPED_KEY, bundle.encrypted_keys),
  );

// This browser's record of one account's console key: its ID and passkey-wrapped
// bundles, kept apart from passkey-kit's PRF cache so Lock does not remove it.
export function keyStore(
  userId: string,
  storage?: Storage,
  locks: LockManager | undefined = globalThis.navigator?.locks,
) {
  const name = `tinfoil-console/${userId}/key`;
  // Reading window.localStorage itself throws when site data is blocked.
  const area = () => storage ?? globalThis.localStorage;
  const load = () => {
    try {
      return area().getItem(name);
    } catch {
      throw new Error(UNREADABLE);
    }
  };
  // A missing record is the only empty state; anything unreadable is an error.
  const read = (): KeyRecord | null => {
    const text = load();
    if (text === null) return null;
    let record: KeyRecord | null = null;
    try {
      record = JSON.parse(text);
    } catch {}
    if (!validRecord(record)) throw new Error(DAMAGED);
    return record;
  };
  // Re-reads under a cross-tab lock, so a write never drops another tab's key or
  // bundles, and confirms the saved value before reporting success.
  const update = async (
    change: (current: KeyRecord | null) => KeyRecord,
    signal?: AbortSignal,
  ) => {
    if (!locks) throw new Error(UNCOORDINATED);
    await locks.request(name, { signal }, async () => {
      signal?.throwIfAborted();
      const text = JSON.stringify(change(read()));
      try {
        area().setItem(name, text);
      } catch {
        throw new Error(UNSAVED);
      }
      if (load() !== text) throw new Error(UNSAVED);
    });
  };
  return { read, update, canSave: !!locks };
}
export type KeyStore = ReturnType<typeof keyStore>;

const bundleBody = (key: WrappedKey): Bundle => ({
  credential_id: key.credentialId,
  kek_iv: key.kekIvHex,
  encrypted_keys: key.wrappedKeyHex,
});

export type Unlock = {
  store: KeyStore;
  manager: PasskeyKeyManager;
  user: Omit<PasskeyUser, "id">;
  // Without interaction only the cached PRF output is tried; ceremonies need a user gesture.
  interactive: boolean;
  signal?: AbortSignal;
};

// Returns the console key, or null when unlocking needs a passkey prompt. A key
// is created only when this browser holds no record for the account.
export async function unlockConsole(
  options: Unlock,
): Promise<Uint8Array | null> {
  const { store, manager, interactive, signal } = options;
  signal?.throwIfAborted();
  const record = store.read();
  if (!record) return interactive ? create(options) : null;
  const wrappedKeys = Object.values(record.bundles).map(
    (bundle): WrappedKey => ({
      profile: PROFILE,
      credentialId: bundle.credential_id,
      kekIvHex: bundle.kek_iv,
      wrappedKeyHex: bundle.encrypted_keys,
    }),
  );
  let key: Uint8Array | null;
  try {
    key =
      (await manager.recoverKeyFromCache({ wrappedKeys }))?.key ??
      (interactive
        ? (await manager.recoverKey({ wrappedKeys, signal })).key
        : null);
  } catch (cause) {
    if (cause instanceof PasskeyKeyError && cause.category === "invalid_input")
      throw new Error(DAMAGED);
    throw cause;
  }
  if (key && keyId(key) !== record.key_id) {
    key.fill(0);
    manager.clearLocalState();
    throw new Error("The unlocked key is not your current console key.");
  }
  return key;
}

// Authenticators overwrite a credential with the same RP and user handle, so each enrollment gets a fresh one.
const enrollee = (user: Omit<PasskeyUser, "id">): PasskeyUser => ({
  ...user,
  id: concatBytes(HANDLE_PREFIX, randomBytes(HANDLE_BYTES)),
});

// The record is checked again after the prompt: a key saved meanwhile by
// another tab is never replaced.
async function create({ store, manager, user, signal }: Unlock) {
  if (!store.canSave) throw new Error(UNCOORDINATED);
  const key = randomBytes(KEY_BYTES);
  try {
    const { wrappedKey } = await manager.createAndWrapKey({
      user: enrollee(user),
      key,
      signal,
    });
    signal?.throwIfAborted();
    const id = keyId(key);
    await store.update((current) => {
      if (current) throw new Error(RACED);
      return {
        key_id: id,
        bundles: { [wrappedKey.credentialId]: bundleBody(wrappedKey) },
      };
    }, signal);
    return key.slice();
  } finally {
    key.fill(0);
  }
}

// Protects the unlocked console key with another passkey, merged into the
// latest record for the same key.
export async function addPasskey(
  options: Omit<Unlock, "interactive"> & { key: Uint8Array },
) {
  const { store, manager, user, key, signal } = options;
  signal?.throwIfAborted();
  const id = keyId(key);
  if (store.read()?.key_id !== id) throw new Error(STALE);
  if (!store.canSave) throw new Error(UNCOORDINATED);
  const { wrappedKey } = await manager.createAndWrapKey({
    user: enrollee(user),
    key,
    signal,
  });
  signal?.throwIfAborted();
  await store.update((current) => {
    if (current?.key_id !== id) throw new Error(STALE);
    return {
      key_id: id,
      bundles: {
        ...current.bundles,
        [wrappedKey.credentialId]: bundleBody(wrappedKey),
      },
    };
  }, signal);
}

// The page cannot tell a cancelled request from one no authenticator could
// complete, so the text covers both and tells setup apart from unlocking.
export function passkeyMessage(cause: unknown): string {
  if (!(cause instanceof PasskeyKeyError))
    return cause instanceof Error ? cause.message : String(cause);
  const creating = cause.operation === "createAndWrapKey";
  switch (cause.category) {
    case "unsupported":
      return "This passkey or browser doesn't support the encryption the console needs. Use a passkey or security key that does, such as a recent YubiKey, iCloud Keychain or Google Password Manager.";
    case "timeout":
      return "The passkey request timed out. Please try again.";
    case "operation_in_progress":
      return "Another passkey prompt is already open.";
    case "cancelled":
      return creating
        ? "Passkey setup did not finish: the request was cancelled or could not be completed. To use a security key, insert it, choose it when the browser asks, and approve each prompt."
        : "The console key was not unlocked: the request was cancelled, or no passkey or security key here matches one saved in this browser. Insert the security key you set up and try again.";
    case "operation_failed":
      return creating
        ? "Creating the passkey failed. Try again, or use a different passkey or security key."
        : "Unlocking with this passkey failed. Try again, or use a different passkey or security key.";
  }
  return cause.message;
}

const derive = (ikm: Uint8Array, label: string, context = "") =>
  hkdf(sha256, ikm, undefined, utf8ToBytes(label + context), KEY_BYTES);

// Each context is a measured value that survives release updates.
export const monitorRoot = (accountKey: Uint8Array) =>
  derive(accountKey, "tinfoil-monitor-v1");
export const ownerSeed = (root: Uint8Array) => derive(root, "owner-v1");
export const storageKey = (root: Uint8Array, bucket: string) =>
  derive(root, "monitor-storage-v1", bucket);
export const sandboxOwnerSeed = (root: Uint8Array, instanceId: string) =>
  derive(root, "sandbox-owner-v1", instanceId);
export const diskKey = (root: Uint8Array, volumeId: string) =>
  derive(root, "workspace-v1", volumeId);

// The measured format Monitor and sandbox parse for their owner key.
export const measuredOwner = (seed: Uint8Array) =>
  "ed25519:" + toBase64(ed25519.getPublicKey(seed));

export const signer =
  (seed: Uint8Array, signal: AbortSignal) => async (message: Uint8Array) => {
    signal.throwIfAborted();
    return ed25519.sign(message, seed);
  };
