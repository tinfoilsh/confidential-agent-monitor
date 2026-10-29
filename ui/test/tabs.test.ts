import { afterEach, beforeEach, expect, mock, test } from "bun:test";
import type { Clerk } from "@clerk/clerk-js/no-rhc";
import * as keys from "../src/hosted/keys";
import { createSession, type Session } from "../src/hosted/session";
import {
  fail,
  hold as holdTransaction,
  isolate,
  kekRecords,
  put,
  transactions,
} from "./idb";

isolate();
const USER = "user_2fixtureA";
const ORIGIN = keys.TARGETS.api_origin!;
const json = (value: unknown) => JSON.parse(JSON.stringify(value));
const Channel = globalThis.BroadcastChannel;
// Delivers nothing, as when the notification is lost or late.
class SilentChannel {
  onmessage = null;
  postMessage() {}
  close() {}
}

// One key service and one IndexedDB shared by two tabs of the same user.
let state: keys.KeyState;
let receipts: Map<string, { content: string; revision: number }>;
let held: (() => void)[];
let hold: boolean;
let offline: Set<string>;
// A tab whose next key-state read returns its snapshot only once released.
let pausedRead:
  { tab: string; entered: () => void; held: Promise<void> } | undefined;
let tabs: Session[];

beforeEach(() => {
  state = {
    revision: 0,
    dek_id: null,
    encrypted_mk: null,
    recovery: [],
    umk: [],
  };
  receipts = new Map();
  held = [];
  hold = false;
  offline = new Set();
  pausedRead = undefined;
  tabs = [];
  Object.assign(globalThis, {
    document: {
      visibilityState: "hidden",
      addEventListener() {},
      removeEventListener() {},
    },
  });
  globalThis.fetch = (async (url: string, init: RequestInit = {}) => {
    const tab = new Headers(init.headers).get("Authorization")!.slice(7);
    if (offline.has(tab)) throw new TypeError("offline");
    if (url.endsWith("/api/sandboxes/owner-key")) {
      const snapshot = json(state);
      if (pausedRead?.tab === tab) {
        const paused = pausedRead;
        pausedRead = undefined;
        paused.entered();
        await paused.held;
      }
      return Response.json(snapshot);
    }
    if (!url.endsWith("/mutations")) return Response.json([]);
    const { mutation_id, ...rest } = JSON.parse(String(init.body));
    let receipt = receipts.get(mutation_id);
    if (!receipt) {
      if (rest.expected_revision !== state.revision)
        return Response.json(
          {
            error: "stale_revision",
            revision: state.revision,
            dek_id: state.dek_id,
          },
          { status: 409 },
        );
      const at = new Date().toISOString();
      if (rest.op === "initialize")
        Object.assign(state, {
          dek_id: rest.dek_id,
          encrypted_mk: rest.encrypted_mk,
          recovery: [{ ...rest.recovery, created_at: at }],
        });
      if (rest.op === "add_recovery")
        state.recovery.push({ ...rest.recovery, created_at: at });
      state.revision++;
      receipt = { content: JSON.stringify(rest), revision: state.revision };
      receipts.set(mutation_id, receipt);
    }
    const reply = Response.json({
      mutation_id,
      revision: receipt.revision,
      replayed: false,
    });
    if (!hold) return reply;
    // Committed; the reply waits until released or the tab aborts it.
    return new Promise((resolve, reject) => {
      held.push(() => resolve(reply));
      init.signal?.addEventListener("abort", () => reject(init.signal!.reason));
    });
  }) as typeof fetch;
});
afterEach(() => {
  tabs.forEach((tab) => tab.dispose());
  globalThis.BroadcastChannel = Channel;
});

// Tabs of one browser share its Clerk session unless a new sign-in made another.
function tab(name: string, clerkSession = "sess_1") {
  let listener: () => void = () => {};
  const clerk = {
    user: { id: USER, primaryEmailAddress: null },
    organization: null,
    session: { id: clerkSession, getToken: async () => name },
    addListener: (callback: () => void) => ((listener = callback), () => {}),
    signOut: mock(async () => {}),
  };
  const session = createSession(clerk as unknown as Clerk);
  tabs.push(session);
  return {
    session,
    clerk,
    // Clerk ends this tab's session some time after another tab signed out.
    signedOut: () => {
      (clerk as { user: unknown }).user = null;
      listener();
    },
    // Clerk replaces this tab's session (a new sign-in) without a page reload.
    replaceSession: (id: string) => {
      clerk.session = { id, getToken: async () => name };
      listener();
    },
    switchAccount: () => {
      (clerk as { organization: unknown }).organization = { id: "org_2other" };
      listener();
    },
  };
}
const manualSetup = async (session: Session) => {
  const scope = session.bind();
  return keys.setupMK({
    api: scope.api,
    manager: {} as never,
    user_id: scope.user,
    state: json(state),
    method: "manual",
    resources: [keys.newResourceKey("monitor", keys.newAttempt())],
    signal: scope.signal,
    // As KeyPanel does: writes run under this sign-in's fence.
    fence: await scope.fence,
  });
};
const manualRecovery = async (session: Session, unlocked: keys.Unlocked) => {
  const scope = session.bind();
  return keys.addRecovery({
    api: scope.api,
    manager: {} as never,
    unlocked,
    method: "manual",
    signal: scope.signal,
    fence: await scope.fence,
  });
};
const settled = (work: Promise<unknown>) =>
  work.then(
    () => "returned",
    () => "refused",
  );

test("the auditor's interleaving: a setup committed in another tab after prepare is offered, not wiped", async () => {
  const a = tab("tab-a");
  const b = tab("tab-b");
  await a.session.refresh();
  const prepared = await a.session.prepareLogout();
  expect(prepared).toMatchObject({ files: [], unresolved: false });
  hold = true;
  const setup = settled(manualSetup(b.session));
  while (!state.dek_id) await Bun.sleep(1);
  expect(await kekRecords()).toHaveLength(1);
  // The wipe sees records it never offered and refuses.
  expect(await a.session.logout(prepared)).toBe(false);
  expect(await kekRecords()).toHaveLength(1);
  hold = false;
  const again = await a.session.prepareLogout();
  expect(again.unresolved).toBe(false);
  expect(again.files).toHaveLength(1);
  const opened = await keys.unlockFile(again.files[0].text, json(state), USER);
  expect(opened.context.dek_id).toBe(state.dek_id!);
  expect(await a.session.logout(again)).toBe(true);
  expect(await kekRecords()).toEqual([]);
  // Tab B's late reply or Clerk's later sign-out cannot recreate the record.
  held.forEach((release) => release());
  expect(await setup).toBe("returned");
  b.signedOut();
  expect(await kekRecords()).toEqual([]);
});

test("a recovery key added in another tab between prepare and confirm is offered before the wipe", async () => {
  const a = tab("tab-a");
  const b = tab("tab-b");
  const { unlocked } = await manualSetup(b.session);
  await a.session.refresh();
  const prepared = await a.session.prepareLogout();
  expect(prepared.files).toHaveLength(1);
  await manualRecovery(b.session, unlocked);
  expect(await a.session.logout(prepared)).toBe(false);
  const again = await a.session.prepareLogout();
  expect(again.files).toHaveLength(2);
  expect(await a.session.logout(again)).toBe(true);
  expect(await kekRecords()).toEqual([]);
});

test("a record another tab settles after the offer makes the sign-out offer again", async () => {
  const a = tab("tab-a");
  const b = tab("tab-b");
  await Promise.all([a.session.refresh(), b.session.refresh()]);
  hold = true;
  void settled(manualSetup(b.session));
  while (!state.dek_id) await Bun.sleep(1);
  hold = false;
  // Tab A cannot reach the service, so the commit is unresolved there.
  offline.add("tab-a");
  const prepared = await a.session.prepareLogout();
  expect(prepared).toMatchObject({ files: [], unresolved: true });
  // Tab B's background refresh settles it before tab A's "Sign out anyway".
  await b.session.refresh();
  expect(await a.session.logout(prepared)).toBe(false);
  offline.delete("tab-a");
  const again = await a.session.prepareLogout();
  expect(again).toMatchObject({ unresolved: false });
  expect(again.files).toHaveLength(1);
  expect(await a.session.logout(again)).toBe(true);
  expect(await kekRecords()).toEqual([]);
});

test("a write another tab began before the wipe is refused after it, so no KEK returns", async () => {
  const a = tab("tab-a");
  const b = tab("tab-b");
  await Promise.all([a.session.refresh(), b.session.refresh()]);
  const prepared = await a.session.prepareLogout();
  // Tab A's wipe transaction queues first, tab B's record write behind it.
  const release = await holdTransaction();
  const requested = transactions.readwrite;
  const signingOut = a.session.logout(prepared);
  while (transactions.readwrite === requested) await Bun.sleep(1);
  const setup = settled(manualSetup(b.session));
  while (transactions.readwrite === requested + 1) await Bun.sleep(1);
  await release();
  expect(await signingOut).toBe(true);
  expect(await setup).toBe("refused");
  expect(await kekRecords()).toEqual([]);
  expect(state.dek_id).toBeNull();
});

test("a reconciliation reply another tab receives after the wipe does not recreate the record", async () => {
  const a = tab("tab-a");
  const b = tab("tab-b");
  hold = true;
  const setup = settled(manualSetup(b.session));
  while (!state.dek_id) await Bun.sleep(1);
  const prepared = await a.session.prepareLogout();
  expect(prepared.files).toHaveLength(1);
  expect(await a.session.logout(prepared)).toBe(true);
  // The reply to tab B's commit arrives only now.
  held.forEach((release) => release());
  expect(await setup).toBe("returned");
  expect(await kekRecords()).toEqual([]);
});

test("another tab drops its unlocked keys and admits no key action after a completed sign-out", async () => {
  const a = tab("tab-a");
  const b = tab("tab-b");
  const { unlocked } = await manualSetup(b.session);
  b.session.setUnlocked(unlocked);
  const prepared = await a.session.prepareLogout();
  expect(await a.session.logout(prepared)).toBe(true);
  // The notification only prompts tab B to read the fence sooner.
  while (b.session.unlocked()) await Bun.sleep(1);
  expect(b.session.keyState().error).toMatch(/signed out/);
  expect(b.session.bind().live()).toBe(false);
  expect(await settled(manualSetup(b.session))).toBe("refused");
  expect(await kekRecords()).toEqual([]);
});

test("a cancelled sign-out resumes key actions and its old offer cannot wipe later records", async () => {
  const a = tab("tab-a");
  const prepared = await a.session.prepareLogout();
  a.session.cancelLogout();
  expect(await settled(manualSetup(a.session))).toBe("returned");
  expect(await a.session.logout(prepared)).toBe(false);
  expect(await kekRecords()).toHaveLength(1);
});

test("one user's sign-out never deletes another user's records or this user's for another API", async () => {
  const a = tab("tab-a");
  const id = keys.newAttempt;
  const others = [
    `tinfoil.manual-kek.v1|${ORIGIN}|user_2other|${id()}|${id()}`,
    `tinfoil.manual-kek.v1|https://api.example|${USER}|${id()}|${id()}`,
    `tinfoil.manual-kek.epoch|${ORIGIN}|user_2other`,
  ];
  for (const key of others) await put(key, "{}");
  await manualSetup(a.session);
  const prepared = await a.session.prepareLogout();
  expect(prepared.files).toHaveLength(1);
  expect(await a.session.logout(prepared)).toBe(true);
  expect(await kekRecords()).toEqual(others.slice(0, 2).sort());
});

test("the sign-out fence and the wipe commit together, or nothing changes", async () => {
  const a = tab("tab-a");
  await manualSetup(a.session);
  // Storage fails the record deletion after the new fence was written.
  fail("delete", "UnknownError", (key) => key instanceof IDBKeyRange);
  const prepared = await a.session.prepareLogout();
  await expect(a.session.logout(prepared)).rejects.toThrow(
    /could not use its site storage/,
  );
  expect(await kekRecords()).toHaveLength(1);
  expect(a.clerk.signOut).not.toHaveBeenCalled();
  expect(
    await keys.fenceEnded(ORIGIN, USER, await a.session.bind().fence),
  ).toBe(false);
});

for (const [change, apply] of [
  ["its account changed", (t: ReturnType<typeof tab>) => t.switchAccount()],
  [
    "its tab began signing out",
    (t: ReturnType<typeof tab>) => void t.session.prepareLogout(),
  ],
] as const)
  test(`a write queued behind another transaction is refused once ${change}`, async () => {
    const b = tab("tab-b");
    await b.session.refresh();
    const release = await holdTransaction();
    const requested = transactions.readwrite;
    const setup = settled(manualSetup(b.session));
    while (transactions.readwrite === requested) await Bun.sleep(1);
    apply(b);
    await release();
    expect(await setup).toBe("refused");
    expect(await kekRecords()).toEqual([]);
    expect(state.dek_id).toBeNull();
  });

test("an old tab cannot start a key action after another tab's wipe, before any notification or Clerk sign-out", async () => {
  globalThis.BroadcastChannel = SilentChannel as never;
  const a = tab("tab-a");
  const b = tab("tab-b");
  await Promise.all([a.session.refresh(), b.session.refresh()]);
  const prepared = await a.session.prepareLogout();
  expect(await a.session.logout(prepared)).toBe(true);
  // Nothing has reached tab B; storage alone refuses its writes.
  expect(await settled(manualSetup(b.session))).toBe("refused");
  // Neither cancelling nor preparing a sign-out there revives the ended sign-in,
  // and its sign-out offers nothing from another sign-in.
  b.session.cancelLogout();
  expect(await b.session.prepareLogout()).toMatchObject({
    files: [],
    unresolved: false,
  });
  b.session.cancelLogout();
  expect(await settled(manualSetup(b.session))).toBe("refused");
  await b.session.refresh();
  expect(b.session.keyState().error).toMatch(/signed out/);
  expect(b.session.bind().live()).toBe(false);
  expect(await kekRecords()).toEqual([]);
  expect(state.dek_id).toBeNull();
});

test("a reload with the ended Clerk session stays signed out; a new sign-in may write", async () => {
  const a = tab("tab-a");
  const prepared = await a.session.prepareLogout();
  expect(await a.session.logout(prepared)).toBe(true);
  const reloaded = tab("tab-c", "sess_1");
  await reloaded.session.refresh();
  expect(reloaded.session.keyState().error).toMatch(/signed out/);
  expect(reloaded.session.bind().live()).toBe(false);
  expect(await settled(manualSetup(reloaded.session))).toBe("refused");
  expect(await kekRecords()).toEqual([]);
  const fresh = tab("tab-d", "sess_2");
  await fresh.session.refresh();
  expect(fresh.session.bind().live()).toBe(true);
  expect(await settled(manualSetup(fresh.session))).toBe("returned");
  expect(await kekRecords()).toHaveLength(1);
  // The ended sign-in's sign-out neither offers nor deletes the new one's key.
  const stale = await reloaded.session.prepareLogout();
  expect(stale).toMatchObject({ files: [], unresolved: false });
  expect(await reloaded.session.logout(stale)).toBe(true);
  expect(await kekRecords()).toHaveLength(1);
});

test("an account switch does not revive a sign-in that another tab's sign-out ended", async () => {
  globalThis.BroadcastChannel = SilentChannel as never;
  const a = tab("tab-a");
  const b = tab("tab-b");
  await Promise.all([a.session.refresh(), b.session.refresh()]);
  // Tab A signed in again before signing out, so its fence names that session.
  a.replaceSession("sess_2");
  const prepared = await a.session.prepareLogout();
  expect(await a.session.logout(prepared)).toBe(true);
  b.switchAccount();
  expect(await settled(manualSetup(b.session))).toBe("refused");
  await b.session.refresh();
  expect(b.session.bind().live()).toBe(false);
  expect(await kekRecords()).toEqual([]);
});

test("a recovery committed in another tab after the sign-out's server read is offered, not silently covered", async () => {
  const a = tab("tab-a");
  const b = tab("tab-b");
  const { unlocked } = await manualSetup(b.session);
  await Promise.all([a.session.refresh(), b.session.refresh()]);
  let entered!: () => void;
  let release!: () => void;
  const reading = new Promise<void>((resolve) => (entered = resolve));
  pausedRead = {
    tab: "tab-a",
    entered,
    held: new Promise<void>((resolve) => (release = resolve)),
  };
  const preparing = a.session.prepareLogout();
  await reading;
  await manualRecovery(b.session, unlocked);
  expect(state.recovery).toHaveLength(2);
  release();
  const prepared = await preparing;
  expect(prepared.unresolved).toBe(false);
  expect(prepared.files).toHaveLength(2);
  for (const file of prepared.files)
    expect(
      (await keys.unlockFile(file.text, json(state), USER)).context.dek_id,
    ).toBe(state.dek_id!);
  expect(await a.session.logout(prepared)).toBe(true);
  expect(await kekRecords()).toEqual([]);
});

test("a new Clerk session in the same tab is a new sign-in for the same user and account", async () => {
  const a = tab("tab-a");
  const b = tab("tab-b");
  await Promise.all([a.session.refresh(), b.session.refresh()]);
  // Replacing a live session cancels what the old one started.
  const before = a.session.bind();
  expect(before.live()).toBe(true);
  a.replaceSession("sess_2");
  expect(before.live()).toBe(false);
  expect(before.signal.aborted).toBe(true);
  // Any completed sign-out in this browser fences other tabs' sign-ins too.
  const prepared = await a.session.prepareLogout();
  expect(await a.session.logout(prepared)).toBe(true);
  expect(await settled(manualSetup(b.session))).toBe("refused");
  // Changing to the session that just ended is no new sign-in.
  b.replaceSession("sess_2");
  expect(await settled(manualSetup(b.session))).toBe("refused");
  await b.session.refresh();
  expect(b.session.bind().live()).toBe(false);
  b.replaceSession("sess_3");
  await b.session.refresh();
  expect(b.session.bind().live()).toBe(true);
  expect(await settled(manualSetup(b.session))).toBe("returned");
  expect(await kekRecords()).toHaveLength(1);
});

test("a setup result arriving after another tab's sign-out is refused, shows no file and keeps no record", async () => {
  globalThis.BroadcastChannel = SilentChannel as never;
  const a = tab("tab-a");
  const b = tab("tab-b");
  await Promise.all([a.session.refresh(), b.session.refresh()]);
  hold = true;
  // As SetupKeys does: accept the unlocked keys, then show the file.
  let shown: keys.RecoveryFile | undefined;
  const accepting = settled(
    (async () => {
      const scope = b.session.bind();
      const { unlocked, file } = await manualSetup(b.session);
      await scope.setUnlocked(unlocked);
      shown = file;
    })(),
  );
  while (!state.dek_id) await Bun.sleep(1);
  const prepared = await a.session.prepareLogout();
  expect(prepared.files).toHaveLength(1);
  expect(await a.session.logout(prepared)).toBe(true);
  held.forEach((release) => release());
  expect(await accepting).toBe("refused");
  expect(shown).toBeUndefined();
  expect(b.session.unlocked()).toBeUndefined();
  expect(b.session.keyState().error).toMatch(/signed out/);
  expect(await kekRecords()).toEqual([]);
});

test("an account switch while the final fence check waits refuses the late result", async () => {
  const b = tab("tab-b");
  await b.session.refresh();
  const { unlocked } = await manualSetup(b.session);
  const scope = b.session.bind();
  const release = await holdTransaction();
  const accepting = settled(scope.setUnlocked(unlocked));
  b.switchAccount();
  await release();
  expect(await accepting).toBe("refused");
  expect(b.session.unlocked()).toBeUndefined();
});
