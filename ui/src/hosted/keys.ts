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
  createPasskeyKeyManager,
  decodeWrappedKeyRecord,
  encodeWrappedKeyRecord,
  type PasskeyKeyManager,
  type PasskeyKeyProfile,
} from "@tinfoilsh/passkey-kit";

export const DASHBOARD = "https://dash.tinfoil.sh/?tab=sandboxes";

// Keep the deployed console profile and owner-key derivation stable.
export const PROFILE: PasskeyKeyProfile = {
  version: 1,
  relyingPartyId:
    globalThis.location?.hostname === "localhost" ? "localhost" : "tinfoil.sh",
  prfSalt: utf8ToBytes("tinfoil-console-key-encryption"),
  hkdfInfo: utf8ToBytes("tinfoil-console-kek-v1"),
};

export const passkeys = () =>
  createPasskeyKeyManager({
    profile: PROFILE,
    relyingPartyName: "Tinfoil",
    enrollmentAttachment: "any",
  });

const derive = (key: Uint8Array, label: string, length = 32) =>
  hkdf(sha256, key, undefined, utf8ToBytes(label), length);

export const publicKey = (key: Uint8Array) => {
  const root = derive(key, "tinfoil-monitor-v1");
  const seed = derive(root, "owner-v1");
  try {
    return (
      "ed25519:" + btoa(String.fromCharCode(...ed25519.getPublicKey(seed)))
    );
  } finally {
    root.fill(0);
    seed.fill(0);
  }
};

// These labels are shared with the deployed console and its encrypted stores.
export function monitorKeys(key: Uint8Array, bucket: string) {
  const root = derive(key, "tinfoil-monitor-v1");
  try {
    return {
      seed: derive(root, "owner-v1"),
      storage: derive(root, "monitor-storage-v1" + bucket),
    };
  } finally {
    root.fill(0);
  }
}

export function keyBundle(json: string) {
  const record = JSON.parse(json);
  if (record?.type === "local") {
    if (
      record.version !== 1 ||
      !/^[0-9a-f]{32}$/.test(record.keyId) ||
      Object.keys(record).sort().join() !== "keyId,type,version"
    )
      throw new Error("The monitor link has an invalid local key reference.");
    return { type: "local" as const, keyId: record.keyId as string };
  }
  const wrapped = decodeWrappedKeyRecord(json);
  if (
    wrapped.profile.relyingPartyId !== PROFILE.relyingPartyId ||
    bytesToHex(wrapped.profile.prfSalt) !== bytesToHex(PROFILE.prfSalt) ||
    bytesToHex(wrapped.profile.hkdfInfo) !== bytesToHex(PROFILE.hkdfInfo)
  )
    throw new Error("This key bundle belongs to a different application.");
  return { type: "passkey" as const, wrapped };
}

export async function recoverMonitorKey(
  bundle: string,
  manager: PasskeyKeyManager,
  signal: AbortSignal,
  recovery?: string,
  storage?: Pick<Storage, "getItem">,
): Promise<Uint8Array> {
  signal.throwIfAborted();
  const descriptor = keyBundle(bundle);
  let key: Uint8Array | undefined;
  try {
    if (descriptor.type === "passkey") {
      key = (
        await manager.recoverKey({ wrappedKeys: [descriptor.wrapped], signal })
      ).key;
    } else {
      let json = recovery;
      if (!json) {
        try {
          json =
            (storage ?? globalThis.localStorage).getItem(
              `tinfoil-console/local/${descriptor.keyId}`,
            ) ?? undefined;
        } catch {}
      }
      if (!json)
        throw new Error(
          "Choose the key bundle you saved when setting up this monitor.",
        );
      const record = JSON.parse(json);
      if (
        record.version !== 1 ||
        record.type !== "local" ||
        record.keyId !== descriptor.keyId ||
        typeof record.keyHex !== "string" ||
        !/^[0-9a-f]{64}$/.test(record.keyHex)
      )
        throw new Error("This file is not the key bundle for this monitor.");
      key = hexToBytes(record.keyHex);
      if (
        bytesToHex(derive(key, "tinfoil-key-id-v1", 16)) !== descriptor.keyId ||
        publicKey(key) !== record.pubkey
      )
        throw new Error("This file is not the key bundle for this monitor.");
    }
    signal.throwIfAborted();
    if (key.length !== 32) throw new Error("Invalid monitor key.");
    return key;
  } catch (cause) {
    key?.fill(0);
    throw cause;
  } finally {
    manager.clearLocalState();
  }
}

export type Setup = {
  pubkey: string;
  // The dashboard receives a passkey-kit record or a reference to a local key.
  // An unprotected private key must never go in the redirect URL.
  bundle: string;
  recovery?: { filename: string; json: string; savedLocally: boolean };
};

export async function setupPasskey(
  manager: PasskeyKeyManager,
  signal: AbortSignal,
): Promise<Setup> {
  signal.throwIfAborted();
  const key = randomBytes(32);
  try {
    const { wrappedKey } = await manager.createAndWrapKey({
      user: {
        // A fresh handle prevents authenticators replacing an earlier credential.
        id: concatBytes(utf8ToBytes("tinfoil-console/"), randomBytes(32)),
        name: "Tinfoil sandbox key",
        displayName: "Your Tinfoil sandboxes",
      },
      key,
      signal,
    });
    signal.throwIfAborted();
    return {
      pubkey: publicKey(key),
      bundle: encodeWrappedKeyRecord(wrappedKey),
    };
  } finally {
    key.fill(0);
    manager.clearLocalState();
  }
}

export function setupLocal(storage?: Storage): Setup {
  const key = randomBytes(32);
  try {
    const id = derive(key, "tinfoil-key-id-v1", 16);
    const keyId = bytesToHex(id);
    id.fill(0);
    const pubkey = publicKey(key);
    const bundle = { version: 1, type: "local", keyId };
    const json = JSON.stringify(
      { ...bundle, pubkey, keyHex: bytesToHex(key) },
      null,
      2,
    );
    let savedLocally = false;
    try {
      const area = storage ?? globalThis.localStorage;
      const name = `tinfoil-console/local/${keyId}`;
      area.setItem(name, json);
      savedLocally = area.getItem(name) === json;
    } catch {
      // A recovery download still works when the browser blocks site storage.
    }
    return {
      pubkey,
      bundle: JSON.stringify(bundle),
      recovery: { filename: `tinfoil-key-${keyId}.json`, json, savedLocally },
    };
  } finally {
    key.fill(0);
  }
}

export function dashboardURL(setup: Setup): string {
  const url = new URL(DASHBOARD);
  url.hash = new URLSearchParams({
    pubkey: setup.pubkey,
    bundle: setup.bundle,
  }).toString();
  return url.href;
}

export const unavailablePasskey = (cause: unknown) =>
  cause instanceof PasskeyKeyError &&
  (cause.category === "unsupported" || cause.category === "cancelled");

export function passkeyMessage(cause: unknown): string {
  if (cause instanceof PasskeyKeyError) {
    if (cause.category === "timeout")
      return "That took a little too long. Try your passkey again, or continue with a local key.";
    if (cause.category === "operation_in_progress")
      return "There's already a passkey prompt open. Finish that one, then try again.";
  }
  return "We couldn't finish setting up your passkey. You can try again or use a local key instead.";
}
