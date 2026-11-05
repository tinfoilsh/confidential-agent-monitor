// Deliberately fake authentication and passkeys, imported only by Vite's local
// serve entry. Wrapped DEKs contain plaintext. Never use this for real keys.
import type { Clerk } from "@clerk/clerk-js/no-rhc";
import type { PasskeyKeyManager, WrappedKey } from "@tinfoilsh/passkey-kit";
import { bytesToHex, hexToBytes } from "@noble/hashes/utils.js";
import { USER } from "./fixtures";
import { PRF_PROFILES } from "../src/terminal/contract";

export function devClerk(): Clerk {
  return {
    user: {
      id: USER,
      primaryEmailAddress: { emailAddress: "daniel@local.test" },
    },
    session: {
      id: `sess_dev_${crypto.randomUUID()}`,
      getToken: async () => "local-development-only",
    },
    organization: undefined,
    addListener: () => () => {},
    // This UI fixture is always signed in; sign-out resets the preview, not auth.
    signOut: async () => location.reload(),
    redirectToSignIn: () => location.reload(),
    setActive: async () => {},
  } as unknown as Clerk;
}

export function devPasskeys(): PasskeyKeyManager {
  const recover = (wrappedKeys: WrappedKey[]) => {
    const record = wrappedKeys[0];
    if (!record) throw new Error("No local development passkey.");
    return {
      credentialId: record.credentialId,
      key: hexToBytes(record.wrappedKeyHex.slice(0, 64)),
      authenticatorAttachment: null,
    };
  };
  return {
    capability: async () => ({ supported: true }),
    createAndWrapKey: async ({ key }: { key: Uint8Array }) => {
      const credentialId = `dev-${crypto.randomUUID()}`;
      return {
        credentialId,
        authenticatorAttachment: null,
        wrappedKey: {
          profile: PRF_PROFILES.development,
          credentialId,
          kekIvHex: "00".repeat(12),
          wrappedKeyHex: bytesToHex(key) + "00".repeat(16),
        },
      };
    },
    recoverKey: async ({ wrappedKeys }: { wrappedKeys: WrappedKey[] }) =>
      recover(wrappedKeys),
    recoverKeyFromCache: async ({
      wrappedKeys,
    }: {
      wrappedKeys: WrappedKey[];
    }) => (wrappedKeys.length ? recover(wrappedKeys) : null),
    rewrapKeyFromCache: async () => null,
    clearLocalState: () => {},
    cancelActiveCeremony: () => {},
  } as unknown as PasskeyKeyManager;
}
