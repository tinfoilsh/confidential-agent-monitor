import { describe, expect, mock, test } from "bun:test";
import {
  blocked,
  fail,
  hold,
  isolate,
  kekRecords,
  put,
  stored,
  transactions,
} from "./idb";
import type { Clerk } from "@clerk/clerk-js/no-rhc";
import { wrapKey, type PasskeyKeyManager } from "@tinfoilsh/passkey-kit";
import {
  PRF_PROFILES,
  b64u,
  manualKEKStorageKey,
} from "../src/hosted/contract";
import * as keys from "../src/hosted/keys";
import { createSession } from "../src/hosted/session";

isolate();

const EMPTY = {
  revision: 0,
  dek_id: null,
  encrypted_mk: null,
  recovery: [],
  umk: [],
};
const row = (id: string, name: string) => ({
  id,
  name,
  repo: "tinfoilsh/confidential-agent-monitor",
  status: "running",
  domain: `${name}.example`,
  owner_key_mode: "tmk",
  owner_public_key: null,
});
const A = row("0b8a3c52-61f4-4d3e-8d2a-6f1e9c4b7a10", "monitor-a");
const B = row("1b8a3c52-61f4-4d3e-8d2a-6f1e9c4b7a10", "monitor-b");

Object.assign(globalThis, {
  document: {
    visibilityState: "hidden",
    addEventListener() {},
    removeEventListener() {},
  },
});

test("switching accounts cancels and discards the previous account's reads", async () => {
  let listener: () => void = () => {};
  const clerk = {
    user: {
      id: "user_2fixtureA",
      primaryEmailAddress: { emailAddress: "a@example.com" },
    },
    organization: { id: "org_A" },
    session: { getToken: async () => "token" },
    addListener: (callback: () => void) => ((listener = callback), () => {}),
  } as unknown as Clerk;
  const held: {
    url: string;
    signal: AbortSignal;
    resolve: (r: Response) => void;
  }[] = [];
  let failInventory = false;
  globalThis.fetch = (async (url: string, init: RequestInit) => {
    if (url.endsWith("/api/sandboxes/owner-key")) return Response.json(EMPTY);
    if (failInventory) return new Response("unavailable", { status: 503 });
    return new Promise<Response>((resolve) =>
      held.push({ url, signal: init.signal!, resolve }),
    );
  }) as typeof fetch;

  const session = createSession(clerk);
  try {
    const first = session.refresh();
    await Bun.sleep(0);
    session.setUnlocked({} as never);
    const before = session.bind();
    (clerk as { organization: unknown }).organization = { id: "org_B" };
    listener();
    // An action begun for org_A cannot store or write its late results.
    expect(before.live()).toBe(false);
    expect(before.signal.aborted).toBe(true);
    expect(() => before.setUnlocked({} as never)).toThrow(/account changed/);
    await expect(before.update((p) => p)).rejects.toThrow();
    await expect(before.fresh()).rejects.toThrow(/account changed/);
    expect(held[0].signal.aborted).toBe(true);
    expect(session.unlocked()).toBeUndefined();
    held[0].resolve(Response.json([A]));
    await first;
    expect(session.inventory().value).toBeUndefined();
    await Bun.sleep(0);
    held.at(-1)!.resolve(Response.json([B]));
    await session.refresh();
    expect(session.account()).toBe("org_B");
    expect(session.inventory().value?.map((r) => r.name)).toEqual([
      "monitor-b",
    ]);

    // A failed read keeps the last list and reports it as stale, never empty.
    failInventory = true;
    await session.refresh();
    expect(session.inventory().value?.map((r) => r.name)).toEqual([
      "monitor-b",
    ]);
    expect(session.inventory().error).toBeTruthy();
  } finally {
    session.dispose();
  }
});

test("malformed rows make inventory unavailable and a token for another account is refused", async () => {
  const clerk = {
    user: { id: "user_2fixtureA", primaryEmailAddress: null },
    organization: { id: "org_A" },
    session: {
      // Clerk switched accounts while this token was being issued.
      getToken: async () => {
        if (switching)
          (clerk as { organization: unknown }).organization = { id: "org_B" };
        return "token";
      },
    },
    addListener: () => () => {},
  } as unknown as Clerk;
  let switching = false;
  let rows: unknown[] = [A, { ...B, owner_key_mode: "other" }];
  globalThis.fetch = (async (url: string) =>
    url.endsWith("/api/sandboxes/owner-key")
      ? Response.json(EMPTY)
      : Response.json(rows)) as typeof fetch;
  const session = createSession(clerk);
  try {
    await session.refresh();
    expect(session.inventory().value).toBeUndefined();
    expect(session.inventory().error).toMatch(/could not be read/);
    rows = [A];
    const scope = session.bind();
    switching = true;
    await expect(scope.api("/api/containers")).rejects.toThrow(
      /account changed/,
    );
  } finally {
    session.dispose();
  }
});

describe("sign-out", () => {
  const USER = "user_2fixtureA";
  const id = (fill: number) => b64u(new Uint8Array(16).fill(fill));
  const context = {
    api_origin: "https://api.tinfoil.sh",
    user_id: USER,
    dek_id: id(1),
  };
  const pendingKey = manualKEKStorageKey(context, id(2));
  const settledKey = manualKEKStorageKey(context, id(3));
  const committed = {
    revision: 1,
    dek_id: id(1),
    encrypted_mk: "mk1.x",
    recovery: [2, 3].map((n) => ({
      recovery_id: id(n),
      type: "manual",
      credential_id: null,
      encrypted_dek: "kek1.x",
      created_at: "2026-10-29T00:00:00Z",
    })),
    umk: [],
  };
  const pending = async () =>
    JSON.parse((await stored()).get(pendingKey)!).pending;
  const record = (pending: boolean) =>
    JSON.stringify({
      version: 1,
      kek: b64u(new Uint8Array(32).fill(4)),
      pending: pending
        ? { mutation_id: id(5), request: { op: "initialize" } }
        : null,
    });

  let server: keys.KeyState = { ...EMPTY };
  const serverState = async () => Response.json(server);
  // The first key-state read (the background refresh) fails, so only sign-out settles.
  async function signedIn(
    keyState: () => Promise<Response>,
    records: Record<string, string> = {
      [pendingKey]: record(true),
      [settledKey]: record(false),
    },
  ) {
    server = { ...EMPTY };
    let reads = 0;
    for (const [key, value] of Object.entries(records)) await put(key, value);
    let listener: () => void = () => {};
    const signOut = mock(async () => {});
    const clerk = {
      user: { id: USER, primaryEmailAddress: null },
      organization: null,
      session: { getToken: async () => "token" },
      addListener: (callback: () => void) => ((listener = callback), () => {}),
      signOut,
    } as unknown as Clerk;
    const posts: keys.Mutation[] = [];
    let hold = false;
    globalThis.fetch = (async (url: string, init: RequestInit) => {
      if (url.endsWith("/api/sandboxes/owner-key"))
        return reads++ ? keyState() : new Response("starting", { status: 503 });
      if (!url.endsWith("/mutations")) return Response.json([]);
      // Commits an initialize, then answers or holds the reply until aborted.
      const m = JSON.parse(String(init.body)) as keys.Mutation;
      posts.push(m);
      if (m.op === "initialize")
        Object.assign(server, {
          revision: 1,
          dek_id: m.dek_id,
          encrypted_mk: m.encrypted_mk,
          recovery: [{ ...m.recovery, created_at: "2026-10-29T00:00:00Z" }],
        });
      if (hold)
        return new Promise((_, reject) =>
          init.signal!.addEventListener("abort", () =>
            reject(init.signal!.reason),
          ),
        );
      return Response.json({
        mutation_id: m.mutation_id,
        revision: 1,
        replayed: false,
      });
    }) as typeof fetch;
    return {
      clerk,
      signOut,
      posts,
      holdReplies: () => (hold = true),
      switchUser: () => {
        (clerk as { user: unknown }).user = { id: "user_2fixtureB" };
        listener();
      },
    };
  }

  test("a committed pending setup and the cached recovery key are offered, then sign-out deletes every KEK", async () => {
    const f = await signedIn(async () => Response.json(committed));
    const session = createSession(f.clerk);
    try {
      await session.refresh();
      session.setUnlocked({} as never);
      const prepared = await session.prepareLogout();
      expect(prepared.unresolved).toBe(false);
      expect(prepared.files.map((file) => file.text).sort()).toEqual(
        [expect.stringContaining(id(2)), expect.stringContaining(id(3))].sort(),
      );
      expect(await kekRecords()).toHaveLength(2);
      await session.logout(prepared);
      expect(await kekRecords()).toEqual([]);
      expect(session.unlocked()).toBeUndefined();
      expect(f.signOut).toHaveBeenCalled();
    } finally {
      session.dispose();
    }
  });

  test("an unreachable key service is reported as unresolved and nothing is deleted yet", async () => {
    const f = await signedIn(async () => new Response("down", { status: 503 }));
    const session = createSession(f.clerk);
    try {
      await session.refresh();
      const prepared = await session.prepareLogout();
      expect(prepared.unresolved).toBe(true);
      expect(prepared.files.map((file) => file.text)).toEqual([
        expect.stringContaining(id(3)),
      ]);
      expect(await pending()).not.toBeNull();
      expect(f.signOut).not.toHaveBeenCalled();
    } finally {
      session.dispose();
    }
  });

  test("a user change while settling exports no recovery file", async () => {
    let release: (() => void) | undefined;
    const f = await signedIn(
      () =>
        new Promise(
          (resolve) => (release = () => resolve(Response.json(committed))),
        ),
    );
    const session = createSession(f.clerk);
    try {
      await session.refresh();
      const preparing = session.prepareLogout();
      while (!release) await Bun.sleep(1);
      f.switchUser();
      release!();
      const prepared = await preparing;
      expect(prepared.live()).toBe(false);
      expect(prepared.files).toEqual([]);
      expect(await pending()).not.toBeNull();
    } finally {
      session.dispose();
    }
  });

  test("a lost reply settled by a background refresh is still offered at sign-out", async () => {
    const f = await signedIn(async () => Response.json(committed), {
      [pendingKey]: record(true),
    });
    const session = createSession(f.clerk);
    try {
      await session.refresh();
      await session.refresh();
      expect(await pending()).toBeNull();
      const prepared = await session.prepareLogout();
      expect(prepared.files.map((file) => file.text)).toEqual([
        expect.stringContaining(id(2)),
      ]);
      await session.logout(prepared);
      expect(await kekRecords()).toEqual([]);
    } finally {
      session.dispose();
    }
  });

  test("a sign-out with nothing cached offers nothing and clears at once", async () => {
    const f = await signedIn(async () => Response.json(committed), {});
    const session = createSession(f.clerk);
    try {
      await session.refresh();
      session.setUnlocked({} as never);
      const prepared = await session.prepareLogout();
      expect(prepared).toMatchObject({ files: [], unresolved: false });
      await session.logout(prepared);
      expect(session.unlocked()).toBeUndefined();
      expect(f.signOut).toHaveBeenCalled();
    } finally {
      session.dispose();
    }
  });

  test("a user change after settlement leaves the offer stale and deletes nothing", async () => {
    const f = await signedIn(async () => Response.json(committed));
    const session = createSession(f.clerk);
    try {
      await session.refresh();
      const prepared = await session.prepareLogout();
      expect(prepared.files).toHaveLength(2);
      f.switchUser();
      expect(prepared.live()).toBe(false);
      await session.logout(prepared);
      await session.logout(undefined);
      expect(await kekRecords()).toHaveLength(2);
      expect(f.signOut).not.toHaveBeenCalled();
    } finally {
      session.dispose();
    }
  });

  test("an admitted manual setup whose reply is cut off by sign-out is settled and offered", async () => {
    const f = await signedIn(serverState, {});
    f.holdReplies();
    const session = createSession(f.clerk);
    try {
      await session.refresh();
      const scope = session.bind();
      const running = keys.setupMK({
        api: scope.api,
        manager: {} as never,
        user_id: scope.user,
        state: { ...EMPTY },
        method: "manual",
        resources: [],
        signal: scope.signal,
        fence: await scope.fence,
      });
      const cut = running.then(
        () => "returned",
        () => "refused",
      );
      while (!f.posts.length) await Bun.sleep(1);
      const prepared = await session.prepareLogout();
      expect(await cut).toBe("refused");
      expect(prepared.unresolved).toBe(false);
      expect(prepared.files).toHaveLength(1);
      expect(prepared.files[0].text).toContain(server.recovery[0].recovery_id);
      await session.logout(prepared);
      expect(await kekRecords()).toEqual([]);
    } finally {
      session.dispose();
    }
  });

  test("key actions running or started during sign-out store and send nothing until it is cancelled", async () => {
    const f = await signedIn(serverState, {});
    const session = createSession(f.clerk);
    try {
      await session.refresh();
      let release!: () => void;
      const prompt = new Promise<void>((resolve) => (release = resolve));
      const passkey = {
        async createAndWrapKey({ key }: { key: Uint8Array }) {
          await prompt;
          const credentialId = id(6);
          return {
            credentialId,
            authenticatorAttachment: null,
            wrappedKey: await wrapKey(
              PRF_PROFILES.production,
              credentialId,
              new Uint8Array(32),
              key,
            ),
          };
        },
      } as unknown as PasskeyKeyManager;
      const start = async (
        manager: PasskeyKeyManager,
        method: keys.RecoveryMethod,
      ) => {
        const scope = session.bind();
        return keys.setupMK({
          api: scope.api,
          manager,
          user_id: scope.user,
          state: { ...EMPTY },
          method,
          resources: [],
          signal: scope.signal,
          fence: await scope.fence,
        });
      };
      const outcome = (setup: Promise<unknown>) =>
        setup.then(
          () => "stored",
          () => "refused",
        );
      const prompting = outcome(start(passkey, "passkey"));
      const sealing = outcome(start({} as never, "manual"));
      const prepared = await session.prepareLogout();
      release();
      expect(await prompting).toBe("refused");
      expect(await sealing).toBe("refused");
      // The confirmation is open: a new setup is refused before any write.
      expect(session.bind().live()).toBe(false);
      await expect(start({} as never, "manual")).rejects.toThrow();
      expect(f.posts).toEqual([]);
      expect(await kekRecords()).toEqual([]);
      expect(prepared).toMatchObject({ files: [], unresolved: false });
      // Staying signed in resumes key actions; the old offer cannot sign out.
      session.cancelLogout();
      expect(prepared.live()).toBe(false);
      expect(session.bind().live()).toBe(true);
      await session.logout(prepared);
      expect(f.signOut).not.toHaveBeenCalled();
    } finally {
      session.dispose();
    }
  });

  test("a user who replaces this one while the wipe commits is not signed out", async () => {
    const f = await signedIn(async () => Response.json(committed));
    const session = createSession(f.clerk);
    const { delete: remove } = IDBObjectStore.prototype;
    try {
      await session.refresh();
      const prepared = await session.prepareLogout();
      // The switch lands after the wipe request succeeds, before its transaction completes.
      IDBObjectStore.prototype.delete = function (key) {
        const req = remove.call(this, key);
        req.addEventListener("success", f.switchUser, { once: true });
        return req;
      };
      expect(await session.logout(prepared)).toBe(false);
      expect(await kekRecords()).toEqual([]);
      expect(f.signOut).not.toHaveBeenCalled();
      expect(session.user()?.id).toBe("user_2fixtureB");
      expect(session.bind().live()).toBe(true);
    } finally {
      IDBObjectStore.prototype.delete = remove;
      session.dispose();
    }
  });

  test("a user change while the wipe waits for its turn deletes nothing", async () => {
    const f = await signedIn(async () => Response.json(committed));
    const session = createSession(f.clerk);
    try {
      await session.refresh();
      const prepared = await session.prepareLogout();
      const release = await hold();
      const requested = transactions.readwrite;
      const signingOut = session.logout(prepared);
      while (transactions.readwrite === requested) await Bun.sleep(1);
      f.switchUser();
      await release();
      expect(await signingOut).toBe(false);
      expect(await kekRecords()).toHaveLength(2);
      expect(f.signOut).not.toHaveBeenCalled();
    } finally {
      session.dispose();
    }
  });

  test("a notification that cannot be sent does not stop the sign-out", async () => {
    const f = await signedIn(async () => Response.json(committed));
    const Channel = globalThis.BroadcastChannel;
    globalThis.BroadcastChannel = class extends Channel {
      postMessage() {
        throw new DOMException("closed", "InvalidStateError");
      }
    };
    const session = createSession(f.clerk);
    globalThis.BroadcastChannel = Channel;
    try {
      await session.refresh();
      const prepared = await session.prepareLogout();
      expect(await session.logout(prepared)).toBe(true);
      expect(await kekRecords()).toEqual([]);
      expect(f.signOut).toHaveBeenCalled();
    } finally {
      session.dispose();
    }
  });

  test("a storage failure is shown in plain words and leaves the user signed in", async () => {
    const f = await signedIn(async () => Response.json(committed));
    const session = createSession(f.clerk);
    try {
      await session.refresh();
      fail("getAll", "UnknownError");
      await expect(session.prepareLogout()).rejects.toThrow(
        /could not use its site storage/,
      );
      expect(session.bind().live()).toBe(true);
      expect(await kekRecords()).toHaveLength(2);
      expect(f.signOut).not.toHaveBeenCalled();
    } finally {
      session.dispose();
    }
  });

  test("blocked site storage is reported with the key state", async () => {
    const f = await signedIn(async () => Response.json(committed), {});
    await blocked();
    const session = createSession(f.clerk);
    try {
      await session.refresh();
      await session.refresh();
      expect(session.keyState().error).toMatch(
        /could not use its site storage/,
      );
      expect(session.inventory().value).toEqual([]);
    } finally {
      session.dispose();
    }
  });
});
