// A signed-in account for `bun run dev --mode hosted` on plain http://127.0.0.1:5173:
// no Clerk, no WebAuthn. VITE_DEV_ACCOUNT names the user (an email). The console
// key is "wrapped" as plain hex in localStorage, which is fine for a dev server
// that only talks to local Monitors through ui/dev/local.ts.
import type { Clerk } from "@clerk/clerk-js/no-rhc";
import type { PasskeyKeyManager, WrappedKey } from "@tinfoilsh/passkey-kit";
import { sha256 } from "@noble/hashes/sha2.js";
import { bytesToHex, hexToBytes, utf8ToBytes } from "@noble/hashes/utils.js";
import { PROFILE, keyId } from "../src/hosted/keys";
import { ownerRpcOnly, type AttestMonitor } from "../src/hosted/monitors";

const USER = "user_dev";
export const devToken = () =>
  "dev." +
  btoa(JSON.stringify({ sub: USER }))
    .replaceAll("+", "-")
    .replaceAll("/", "_")
    .replace(/=+$/, "") +
  ".dev";

export function devClerk(email: string): Clerk {
  const clerk = {
    user: {
      id: USER,
      fullName: "Dev User",
      primaryEmailAddress: { emailAddress: email },
    },
    session: { id: "sess_dev", getToken: async () => devToken() },
    organization: undefined,
    addListener: () => () => {},
    signOut: async () => location.reload(),
    mountSignIn: () => {},
    unmountSignIn: () => {},
  };
  return clerk as unknown as Clerk;
}

// The key record is validated against the real shapes (24-hex IV, 96-hex
// wrapped key = key + GCM tag), so the plain key is padded to match.
const IV = "00".repeat(12);
const TAG = "00".repeat(16);
const unwrap = (wrapped: WrappedKey[]) =>
  wrapped.length ? hexToBytes(wrapped[0].wrappedKeyHex.slice(0, 64)) : null;

// One fixed console key for the dev account, written on every load so there is
// never a passkey ceremony and a stale or damaged record cannot lock it out.
export const DEV_KEY = sha256(utf8ToBytes("tinfoil-dev-console-key"));
export function installDevKey() {
  localStorage.setItem(
    `tinfoil-console/${USER}/key`,
    JSON.stringify({
      key_id: keyId(DEV_KEY),
      bundles: {
        dev: {
          credential_id: "dev",
          kek_iv: IV,
          encrypted_keys: bytesToHex(DEV_KEY) + TAG,
        },
      },
    }),
  );
}

export function devPasskeys(): PasskeyKeyManager {
  const manager = {
    capability: async () => ({ supported: true }),
    createAndWrapKey: async ({ key }: { key: Uint8Array }) => {
      const credentialId = "dev-" + Math.random().toString(36).slice(2, 10);
      return {
        credentialId,
        authenticatorAttachment: null,
        wrappedKey: {
          profile: PROFILE,
          credentialId,
          kekIvHex: IV,
          wrappedKeyHex: bytesToHex(key) + TAG,
        },
      };
    },
    recoverKey: async ({ wrappedKeys }: { wrappedKeys: WrappedKey[] }) => ({
      credentialId: wrappedKeys[0]?.credentialId ?? "",
      key: unwrap(wrappedKeys)!,
      authenticatorAttachment: null,
    }),
    recoverKeyFromCache: async ({
      wrappedKeys,
    }: {
      wrappedKeys: WrappedKey[];
    }) => {
      const key = unwrap(wrappedKeys);
      return key
        ? {
            credentialId: wrappedKeys[0].credentialId,
            key,
            authenticatorAttachment: null,
          }
        : null;
    },
    evaluateCredential: async () => {
      throw new Error("not in dev");
    },
    wrapKeyWithPRFResult: async () => {
      throw new Error("not in dev");
    },
    unwrapKeyWithPRFResult: async () => {
      throw new Error("not in dev");
    },
    rewrapKeyFromCache: async () => null,
    clearLocalState: () => {},
    cancelActiveCeremony: () => {},
  };
  return manager as unknown as PasskeyKeyManager;
}

// Local Monitors sit behind the plain-http dev server, which relays owner RPC;
// the console builds https URLs from the row's domain.
export const devAttest: AttestMonitor = async ({ url }) => ({
  fetch: ownerRpcOnly(url, (input, init) =>
    fetch(String(input).replace(/^https:/, "http:"), init),
  ),
  verified: false,
});
