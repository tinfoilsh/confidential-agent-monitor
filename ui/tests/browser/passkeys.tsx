import type { Clerk } from "@clerk/clerk-js/no-rhc";
import { encodeWrappedKeyRecord, wrapKey } from "@tinfoilsh/passkey-kit";
import { Show, createSignal } from "solid-js";
import { render } from "solid-js/web";
import { AuthScreen } from "../../src/components";
import { KeyGate } from "../../src/hosted/KeyPanel";
import { PRF_PROFILES, b64u, sealMK } from "../../src/hosted/contract";
import * as keys from "../../src/hosted/keys";
import { createSession } from "../../src/hosted/session";
import "../../src/dashboard.css";

keys.TARGETS.api_origin = "https://api.example.com";
const USER = "user_first";
const PRF = new Uint8Array(32).fill(7);
const DEK = new Uint8Array(32).fill(8);
const CREDENTIAL = b64u(new Uint8Array(32).fill(9));
const DEK_ID = b64u(new Uint8Array(16).fill(10));
const RECOVERY_ID = b64u(new Uint8Array(16).fill(11));
const resource = keys.newResourceKey("sandbox", keys.newAttempt());
// Resource keys change across page loads, so a cached unlock must open the
// latest server envelope rather than returning an old in-memory payload.
const payload = { version: 1 as const, resources: [resource] };
const states = new Map<string, keys.KeyState>();
async function stateFor(user: string) {
  let state = states.get(user);
  if (!state) {
    const wrapped = await wrapKey(
      PRF_PROFILES[keys.PROFILE],
      CREDENTIAL,
      PRF,
      DEK,
    );
    state = {
      revision: 1,
      dek_id: DEK_ID,
      encrypted_mk: await sealMK(payload, DEK, {
        api_origin: keys.TARGETS.api_origin!,
        user_id: user,
        dek_id: DEK_ID,
      }),
      recovery: [
        {
          recovery_id: RECOVERY_ID,
          type: "passkey",
          credential_id: CREDENTIAL,
          encrypted_dek: encodeWrappedKeyRecord(wrapped),
          created_at: new Date().toISOString(),
        },
      ],
    };
    states.set(user, state);
  }
  return state;
}

let notify = () => {};
const clerk = {
  user: { id: USER } as { id: string } | undefined,
  organization: null,
  session: { id: "session_first", getToken: async () => "test-token" },
  addListener(listener: () => void) {
    notify = listener;
    return () => {};
  },
  async signOut() {
    clerk.user = undefined;
    notify();
  },
};
globalThis.fetch = async (input) => {
  const url = new URL(String(input));
  if (url.origin !== keys.TARGETS.api_origin)
    throw new Error(`Unexpected request: ${url}`);
  if (url.pathname === "/api/sandboxes/owner-key")
    return Response.json(await stateFor(clerk.user!.id));
  if (url.pathname === "/api/containers") return Response.json([]);
  throw new Error(`Unexpected request: ${url}`);
};

const [prompts, setPrompts] = createSignal(0);
let release: (() => void) | undefined;
let hold = false;
let wrongPRF = false;
Object.defineProperty(navigator.credentials, "get", {
  value: async () => {
    setPrompts(prompts() + 1);
    if (hold)
      await new Promise<void>((resolve) => {
        release = resolve;
      });
    return {
      id: CREDENTIAL,
      rawId: new Uint8Array(32).fill(9).buffer,
      type: "public-key",
      authenticatorAttachment: "platform",
      getClientExtensionResults: () => ({
        prf: {
          results: { first: (wrongPRF ? new Uint8Array(32) : PRF).buffer },
        },
      }),
    };
  },
});
const session = createSession(clerk as unknown as Clerk);
const manager = keys.passkeys();
render(
  () => (
    <>
      <output aria-label="Passkey prompts">{prompts()}</output>
      <Show when={session.user()} fallback={<p>Signed out</p>}>
        <KeyGate session={session} manager={manager}>
          <AuthScreen title="Keys unlocked">
            <output aria-label="Key owner">
              {session.unlocked()?.context.user_id}
            </output>
            <output aria-label="Key payload">
              {JSON.stringify(session.unlocked()?.payload)}
            </output>
          </AuthScreen>
        </KeyGate>
      </Show>
    </>
  ),
  document.getElementById("fixture")!,
);

const fixture = {
  payload,
  prf: b64u(PRF),
  async signOut() {
    const prepared = await session.prepareLogout();
    return session.logout(prepared);
  },
  async switchUser(user: string) {
    clerk.user = { id: user };
    clerk.session.id = `session_${user}`;
    notify();
    await session.refresh();
  },
  async invalidate(kind: "recovery" | "dek") {
    const state = await stateFor(clerk.user!.id);
    if (kind === "recovery") state.recovery = [];
    else state.dek_id = keys.id16();
    state.revision++;
    await session.refresh();
  },
  hold() {
    hold = true;
  },
  resumeNewPrompts() {
    hold = false;
  },
  release() {
    hold = false;
    release?.();
  },
  wrongPRF() {
    wrongPRF = true;
  },
  async manualRecovery() {
    const user = clerk.user!.id;
    const state = {
      revision: 0,
      dek_id: null,
      encrypted_mk: null,
      recovery: [],
    };
    const api: keys.Api = async (_path, init) => {
      if (init?.method !== "PUT") return state;
      Object.assign(state, init.body);
      state.revision++;
      return { revision: state.revision };
    };
    const fence = await keys.kekFence(
      keys.TARGETS.api_origin!,
      user,
      clerk.session.id,
    );
    const { unlocked, file } = await keys.setupMK({
      api,
      manager: keys.passkeys(),
      user_id: user,
      state,
      method: "manual",
      resources: [resource],
      fence,
    });
    const restored = await keys.unlockSaved(state, user, fence);
    const download = await keys.savedRecoveryFile(state, user);
    return {
      original: unlocked.payload,
      restored: restored?.payload,
      file,
      download,
    };
  },
  // This unmounted caller ignores cancellation, exercising the storage fence
  // independently of the component's abort handling.
  async lateUnlock() {
    const user = clerk.user!.id;
    const state = await stateFor(user);
    const fence = await keys.kekFence(
      keys.TARGETS.api_origin!,
      user,
      clerk.session.id,
    );
    try {
      await keys.unlockPasskey(keys.passkeys(), state, user, {
        remember: true,
        fence,
      });
      return "unlocked";
    } catch {
      return "rejected";
    }
  },
};
declare global {
  interface Window {
    passkeyFixture: typeof fixture;
  }
}
window.passkeyFixture = fixture;
