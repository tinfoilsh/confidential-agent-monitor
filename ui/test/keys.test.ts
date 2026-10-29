import { beforeEach, describe, expect, test } from "bun:test";
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
import {
  unwrapKey,
  wrapKey,
  type PasskeyKeyManager,
} from "@tinfoilsh/passkey-kit";
import {
  PRF_PROFILES,
  b64u,
  manualKEKStorageKey,
} from "../src/hosted/contract";
import * as keys from "../src/hosted/keys";

isolate();
const USER = "user_2fixtureA";
const ORIGIN = keys.TARGETS.api_origin!;
const fence = () => keys.kekFence(ORIGIN, USER, "sess_1");
const json = (value: unknown) => JSON.parse(JSON.stringify(value));

// The frozen key-state contract: receipts replay before the stale check.
class Controlplane {
  revision = 0;
  dek_id: string | null = null;
  encrypted_mk: string | null = null;
  recovery: (keys.RecoveryInput & { created_at: string })[] = [];
  umk: keys.KeyState["umk"] = [];
  receipts = new Map<string, { content: string; revision: number }>();
  bodies: string[] = [];
  // Commits, then loses this many replies the way lose() does.
  dropReplies = 0;
  lose: (reply: unknown) => unknown = () => {
    throw new TypeError("reply lost");
  };
  // Fails this many mutations before they reach the database.
  unreachable = 0;
  beforeSend?: (body: keys.Mutation) => Promise<void>;

  api: keys.Api = async (path, init = {}) => {
    if (this.unreachable > 0 && init.method === "POST") {
      this.unreachable--;
      throw new TypeError("network");
    }
    if (path === "/api/sandboxes/owner-key")
      return json({
        revision: this.revision,
        dek_id: this.dek_id,
        encrypted_mk: this.encrypted_mk,
        recovery: this.recovery,
        umk: this.umk,
      });
    const body = json(init.body) as keys.Mutation;
    await this.beforeSend?.(body);
    this.bodies.push(JSON.stringify(body));
    const result = this.mutate(body);
    if (this.dropReplies > 0) {
      this.dropReplies--;
      return this.lose(result);
    }
    return result;
  };

  mutate(m: keys.Mutation) {
    const { mutation_id, ...rest } = m;
    const content = JSON.stringify(rest);
    const receipt = this.receipts.get(mutation_id);
    if (receipt) {
      if (receipt.content !== content)
        throw new keys.ApiError(409, { error: "mutation_id_reused" });
      return { mutation_id, revision: receipt.revision, replayed: true };
    }
    if (m.expected_revision !== this.revision)
      throw new keys.ApiError(409, {
        error: "stale_revision",
        revision: this.revision,
        dek_id: this.dek_id,
      } as keys.ApiError["body"]);
    if (m.expected_dek_id !== this.dek_id)
      throw new keys.ApiError(409, {
        error: "dek_mismatch",
        dek_id: this.dek_id,
      });
    const at = new Date().toISOString();
    if (m.op === "initialize") {
      this.dek_id = m.dek_id;
      this.encrypted_mk = m.encrypted_mk;
      this.recovery = [{ ...m.recovery, created_at: at }];
    } else if (m.op === "update_mk") this.encrypted_mk = m.encrypted_mk;
    else if (m.op === "add_recovery")
      this.recovery.push({ ...m.recovery, created_at: at });
    else if (m.op === "remove_recovery") {
      if (this.recovery.length === 1)
        throw new keys.ApiError(409, { error: "last_recovery" });
      this.recovery = this.recovery.filter(
        (r) => r.recovery_id !== m.recovery_id,
      );
    } else if (m.op === "register_umk")
      this.umk.push(...m.umk.map((e) => ({ ...e, registered_at: at })));
    this.revision++;
    this.receipts.set(mutation_id, { content, revision: this.revision });
    return { mutation_id, revision: this.revision, replayed: false };
  }

  state = () => keys.readKeyState(this.api);
}

// An authenticator with a fixed PRF output per credential.
function authenticator(): PasskeyKeyManager {
  const prf = new Map<string, Uint8Array>();
  const profile = PRF_PROFILES.production;
  return {
    async createAndWrapKey({ key }) {
      const credentialId = b64u(crypto.getRandomValues(new Uint8Array(16)));
      prf.set(credentialId, crypto.getRandomValues(new Uint8Array(32)));
      const wrappedKey = await wrapKey(
        profile,
        credentialId,
        prf.get(credentialId)!,
        key,
      );
      return { credentialId, wrappedKey, authenticatorAttachment: null };
    },
    async recoverKey({ wrappedKeys }) {
      const wrapped = wrappedKeys.find((w) => prf.has(w.credentialId))!;
      const key = await unwrapKey(
        profile,
        prf.get(wrapped.credentialId)!,
        wrapped,
      );
      return {
        credentialId: wrapped.credentialId,
        key,
        authenticatorAttachment: null,
      };
    },
  } as PasskeyKeyManager;
}

let server: Controlplane, manager: PasskeyKeyManager;
beforeEach(() => {
  server = new Controlplane();
  manager = authenticator();
});

const setup = async (method: keys.RecoveryMethod = "manual") =>
  keys.setupMK({
    api: server.api,
    manager,
    user_id: USER,
    state: await server.state(),
    method,
    resources: [
      keys.newResourceKey("monitor", keys.newAttempt()),
      keys.newResourceKey("sandbox", keys.newAttempt()),
    ],
    fence: await fence(),
  });
const pending = async () => {
  const [key] = await kekRecords();
  return JSON.parse((await stored()).get(key)!).pending;
};

describe("first setup and recovery", () => {
  test("commits the manual KEK and exact mutation before sending; the file and saved record open the same MK", async () => {
    // Read by another connection, as another tab would.
    server.beforeSend = async (body) => {
      expect((await pending()).request).toEqual(body);
    };
    const { unlocked, file } = await setup();
    const state = await server.state();
    const saved = await keys.unlockSaved(state, USER);
    const fromFile = await keys.unlockFile(file!.text, state, USER);
    expect(saved!.payload).toEqual(unlocked.payload);
    expect(fromFile.payload).toEqual(unlocked.payload);
    expect((await keys.savedRecoveryFile(state, USER))!.text).toBe(file!.text);
    // Only the KEK is stored; DEK and private keys never leave memory.
    const secrets = [
      b64u(unlocked.dek),
      ...unlocked.payload.resources.flatMap((r) => [
        r.owner_seed,
        r.storage_key,
      ]),
    ];
    for (const text of [
      ...(await stored()).values(),
      ...server.bodies,
      file!.text,
    ])
      for (const secret of secrets) expect(text).not.toContain(secret);
  });

  for (const [storage, inject] of [
    ["full", () => fail("put", "QuotaExceededError")],
    ["aborted", () => fail("put", "abort")],
    ["blocked", blocked],
  ] as const)
    test(`${storage} site storage stops setup before anything reaches the server`, async () => {
      const sign_in = await fence();
      await inject();
      await expect(
        keys.setupMK({
          api: server.api,
          manager,
          user_id: USER,
          state: await server.state(),
          method: "manual",
          resources: [],
          fence: sign_in,
        }),
      ).rejects.toThrow(/could not use its site storage/);
      expect(server.bodies).toEqual([]);
      expect(server.revision).toBe(0);
    });

  test("a commit waits for an earlier transaction and is sent only after its record commits", async () => {
    const sign_in = await fence();
    const release = await hold();
    const requested = transactions.readwrite;
    const setting = keys.setupMK({
      api: server.api,
      manager,
      user_id: USER,
      state: await server.state(),
      method: "manual",
      resources: [],
      fence: sign_in,
    });
    while (transactions.readwrite === requested) await Bun.sleep(1);
    await Bun.sleep(20);
    expect(server.bodies).toEqual([]);
    await release();
    await setting;
    expect(server.revision).toBe(1);
  });

  test("a lost commit reply is reconciled after reload with the same KEK", async () => {
    server.dropReplies = 4;
    await expect(setup()).rejects.toThrow("reply lost");
    expect(await pending()).not.toBeNull();
    const state = await keys.reconcilePending(
      server.api,
      USER,
      await server.state(),
      await fence(),
    );
    expect(await pending()).toBeNull();
    expect(server.revision).toBe(1);
    expect(await keys.unlockSaved(state, USER)).toBeDefined();
  });

  test("a setup that never reached the server is resent exactly after reload", async () => {
    server.unreachable = 4;
    await expect(setup()).rejects.toThrow("network");
    const state = await keys.reconcilePending(
      server.api,
      USER,
      await server.state(),
      await fence(),
    );
    expect(state.dek_id).not.toBeNull();
    expect(await keys.unlockSaved(state, USER)).toBeDefined();
  });

  test("a losing first setup fails and keeps neither its KEK nor its keys", async () => {
    const stale = await server.state();
    await setup("passkey");
    await expect(
      keys.setupMK({
        api: server.api,
        manager,
        user_id: USER,
        state: stale,
        method: "manual",
        resources: [keys.newResourceKey("sandbox", keys.newAttempt())],
        fence: await fence(),
      }),
    ).rejects.toBeInstanceOf(keys.SetupLostError);
    expect(await kekRecords()).toEqual([]);
    expect(server.revision).toBe(1);
  });

  test("a passkey added later wraps the same DEK", async () => {
    const { unlocked } = await setup();
    const added = await keys.addRecovery({
      api: server.api,
      manager,
      unlocked,
      method: "passkey",
      fence: await fence(),
    });
    const state = await server.state();
    const viaPasskey = await keys.unlockPasskey(manager, state, USER);
    expect(viaPasskey.dek).toEqual(unlocked.dek);
    expect(viaPasskey.payload).toEqual(unlocked.payload);
    const manual = state.recovery.find((r) => r.type === "manual")!;
    await keys.removeRecovery(server.api, added.unlocked, manual.recovery_id);
    expect(await kekRecords()).toEqual([]);
    const last = (await server.state()).recovery[0].recovery_id;
    await expect(
      keys.removeRecovery(server.api, viaPasskey, last),
    ).rejects.toThrow();
  });

  test("UMK registration needs no MK and first setup preserves it", async () => {
    await keys.registerUMK(server.api, await server.state(), [
      {
        kind: "monitor",
        public_key: keys.newResourceKey("monitor", "x").owner_public_key,
      },
    ]);
    expect(server.dek_id).toBeNull();
    await setup("passkey");
    expect(server.umk).toHaveLength(1);
    expect(await kekRecords()).toEqual([]);
  });

  for (const [reply, lose] of [
    [
      "a server error",
      () => {
        throw new keys.ApiError(500, { error: "commit outcome unavailable" });
      },
    ],
    [
      "a malformed receipt",
      (reply: unknown) => ({ ...(reply as object), revision: 7 }),
    ],
  ] as const)
    test(`a commit answered by ${reply} keeps its KEK pending`, async () => {
      server.lose = lose;
      server.dropReplies = 4;
      await expect(setup()).rejects.toThrow();
      expect(server.revision).toBe(1);
      expect((await pending()).request.op).toBe("initialize");
      const state = await keys.reconcilePending(
        server.api,
        USER,
        await server.state(),
        await fence(),
      );
      expect(await keys.unlockSaved(state, USER)).toBeDefined();
    });

  test("logout forgets only the current user's manual KEKs for this API", async () => {
    await setup();
    const others = [
      `tinfoil.manual-kek.v1|${ORIGIN}|user_other|a|b`,
      `tinfoil.manual-kek.v1|https://api.example|${USER}|a|b`,
    ];
    for (const key of others) await put(key, "{}");
    const sign_in = await fence();
    const { covered } = await keys.settlePending(server.api, USER, sign_in);
    expect(await keys.forgetManualKEKs(ORIGIN, USER, sign_in, covered)).toBe(
      true,
    );
    const left = await stored();
    expect([...left.keys()].sort()).toEqual(
      [`tinfoil.manual-kek.epoch|${ORIGIN}|${USER}`, ...others].sort(),
    );
    expect(left.get(`tinfoil.manual-kek.epoch|${ORIGIN}|${USER}`)).toEndWith(
      ":sess_1",
    );
  });

  test("the sign-out fence and the wipe commit together or not at all", async () => {
    await setup();
    const before = await stored();
    const sign_in = await fence();
    const { covered } = await keys.settlePending(server.api, USER, sign_in);
    // The deletion is made, then its transaction aborts before committing.
    fail("delete", "abort", (key) => key instanceof IDBKeyRange);
    await expect(
      keys.forgetManualKEKs(ORIGIN, USER, sign_in, covered),
    ).rejects.toThrow(/could not use its site storage/);
    expect(await stored()).toEqual(before);
    expect(await keys.fenceEnded(ORIGIN, USER, sign_in)).toBe(false);
  });

  test("a storage read failure is reported, not taken as an empty cache", async () => {
    await setup();
    const state = await server.state();
    const sign_in = await fence();
    fail("getAll", "UnknownError");
    for (const read of [
      () => keys.unlockSaved(state, USER),
      () => keys.savedRecoveryFile(state, USER),
      () => keys.settlePending(server.api, USER, sign_in),
    ])
      await expect(read()).rejects.toThrow(/could not use its site storage/);
  });
});

describe("MK updates", () => {
  const unlockedPair = async () => {
    await setup();
    const state = await server.state();
    return [
      (await keys.unlockSaved(state, USER))!,
      (await keys.unlockSaved(state, USER))!,
    ];
  };

  test("concurrent additions keep both keys and generation floors merge by maximum", async () => {
    let [a, b] = await unlockedPair();
    const monitor = a.payload.resources.find((r) => r.kind === "monitor")!;
    const one = keys.newResourceKey("sandbox", keys.newAttempt());
    const two = keys.newResourceKey("sandbox", keys.newAttempt());
    a = await keys.updateMK(server.api, a, keys.addResources([one]));
    b = await keys.updateMK(server.api, b, keys.addResources([two]));
    a = await keys.updateMK(server.api, a, keys.checkpoint(monitor.key_id, 5));
    b = await keys.updateMK(server.api, b, keys.checkpoint(monitor.key_id, 3));
    const ids = b.payload.resources.map((r) => r.key_id);
    expect(ids).toContain(one.key_id);
    expect(ids).toContain(two.key_id);
    expect([...ids].sort()).toEqual(ids);
    expect(
      b.payload.resources.find((r) => r.key_id === monitor.key_id)!
        .min_generation,
    ).toBe(5);
    const replaced = { ...one, storage_key: two.storage_key };
    await expect(
      keys.updateMK(server.api, b, keys.addResources([replaced])),
    ).rejects.toThrow(/conflicts/);
  });

  test("a binding is set once and never replaced", async () => {
    let [a] = await unlockedPair();
    const sandbox = a.payload.resources.find((r) => r.kind === "sandbox")!;
    const binding = {
      account: "personal",
      container_id: "0b8a3c52-61f4-4d3e-8d2a-6f1e9c4b7a10",
      instance_id: "1b8a3c52-61f4-4d3e-8d2a-6f1e9c4b7a10",
      volume_id: "2b8a3c52-61f4-4d3e-8d2a-6f1e9c4b7a10",
      bucket: null,
    };
    a = await keys.updateMK(
      server.api,
      a,
      keys.bindResource(sandbox.key_id, binding),
    );
    const other = {
      ...binding,
      volume_id: "3b8a3c52-61f4-4d3e-8d2a-6f1e9c4b7a10",
    };
    await expect(
      keys.updateMK(server.api, a, keys.bindResource(sandbox.key_id, other)),
    ).rejects.toThrow(/already bound/);
  });

  test("an uncertain update is resent exactly before the next write", async () => {
    let [a] = await unlockedPair();
    const one = keys.newResourceKey("sandbox", keys.newAttempt());
    server.dropReplies = 4;
    await expect(
      keys.updateMK(server.api, a, keys.addResources([one])),
    ).rejects.toThrow();
    expect(a.pending).toBeDefined();
    const two = keys.newResourceKey("sandbox", keys.newAttempt());
    a = await keys.updateMK(server.api, a, keys.addResources([two]));
    expect(server.revision).toBe(3);
    expect(a.payload.resources.map((r) => r.key_id)).toEqual(
      expect.arrayContaining([one.key_id, two.key_id]),
    );
  });

  test("an uncertain write after a stale reload stays pending on the caller's object", async () => {
    const [a, b] = await unlockedPair();
    await keys.updateMK(
      server.api,
      b,
      keys.addResources([keys.newResourceKey("sandbox", keys.newAttempt())]),
    );
    const mine = keys.newResourceKey("sandbox", keys.newAttempt());
    const api: keys.Api = async (path, init) => {
      if (init?.method === "POST" && server.revision === 2)
        server.dropReplies = 4;
      return server.api(path, init);
    };
    await expect(
      keys.updateMK(api, a, keys.addResources([mine])),
    ).rejects.toThrow("reply lost");
    const pending = a.pending!;
    expect(pending.expected_revision).toBe(2);
    const next = await keys.updateMK(server.api, a, (p) => p);
    expect(
      server.bodies.filter((body) => body === JSON.stringify(pending)).length,
    ).toBeGreaterThan(1);
    expect(server.revision).toBe(3);
    expect(next.payload.resources.map((r) => r.key_id)).toContain(mine.key_id);
    expect(a.pending).toBeUndefined();
  });

  test("a pending write rejected for a reason other than staleness is surfaced", async () => {
    const [a] = await unlockedPair();
    a.pending = {
      ...JSON.parse(server.bodies[0]),
      op: "update_mk",
      encrypted_mk: "mk1.x",
    };
    await expect(keys.updateMK(server.api, a, (p) => p)).rejects.toThrow(
      "mutation_id_reused",
    );
    expect(a.pending).toBeUndefined();
  });

  test("bindings and checkpoints fail when their key was removed meanwhile", async () => {
    const [a, b] = await unlockedPair();
    const monitor = a.payload.resources.find((r) => r.kind === "monitor")!;
    const sandbox = a.payload.resources.find((r) => r.kind === "sandbox")!;
    await keys.updateMK(
      server.api,
      b,
      keys.removeResources([monitor.key_id, sandbox.key_id]),
    );
    const revision = server.revision;
    await expect(
      keys.updateMK(
        server.api,
        a,
        keys.bindResource(sandbox.key_id, {
          account: "personal",
          container_id: "0b8a3c52-61f4-4d3e-8d2a-6f1e9c4b7a10",
          instance_id: "1b8a3c52-61f4-4d3e-8d2a-6f1e9c4b7a10",
          volume_id: "2b8a3c52-61f4-4d3e-8d2a-6f1e9c4b7a10",
          bucket: null,
        }),
      ),
    ).rejects.toThrow(/no longer saved/);
    await expect(
      keys.updateMK(server.api, a, keys.checkpoint(monitor.key_id, 4)),
    ).rejects.toThrow(/no longer saved/);
    expect(server.revision).toBe(revision);
    expect(() => keys.checkpoint(sandbox.key_id, 1)(b.payload)).toThrow(
      /Monitor/,
    );
  });

  test("re-adding a saved key keeps the higher generation and refuses another binding", async () => {
    const [a] = await unlockedPair();
    const monitor = a.payload.resources.find((r) => r.kind === "monitor")!;
    const raised = keys.addResources([{ ...monitor, min_generation: 9 }])(
      a.payload,
    );
    expect(
      raised.resources.find((r) => r.key_id === monitor.key_id)!.min_generation,
    ).toBe(9);
    expect(
      keys
        .addResources([monitor])(raised)
        .resources.find((r) => r.key_id === monitor.key_id)!.min_generation,
    ).toBe(9);
    const binding = {
      account: "personal",
      container_id: "0b8a3c52-61f4-4d3e-8d2a-6f1e9c4b7a10",
      instance_id: null,
      volume_id: null,
      bucket: "s3://b",
    };
    const bound = keys.addResources([{ ...monitor, binding }])(a.payload);
    expect(
      bound.resources.find((r) => r.key_id === monitor.key_id)!.binding,
    ).toEqual(binding);
    expect(() =>
      keys.addResources([
        { ...monitor, binding: { ...binding, bucket: "s3://c" } },
      ])(bound),
    ).toThrow(/already bound/);
  });

  test("a refreshed key state reuses the DEK only for the same DEK ID", async () => {
    const [a] = await unlockedPair();
    const state = await server.state();
    expect(await keys.refreshUnlocked(a, state)).toBe(a);
    expect(
      await keys.refreshUnlocked(a, {
        ...state,
        dek_id: b64u(new Uint8Array(16)),
      }),
    ).toBeUndefined();
  });
});

test("the saved KEK record is keyed by API, user, DEK and recovery", async () => {
  const { unlocked } = await setup();
  const state = await server.state();
  const key = manualKEKStorageKey(
    unlocked.context,
    state.recovery[0].recovery_id,
  );
  expect(await kekRecords()).toEqual([key]);
});

test("the fixed profile refuses other origins and key sync needs no OAuth client configuration", () => {
  expect(keys.profileError("https://terminal.tinfoil.sh")).toBeUndefined();
  expect(keys.profileError("https://local.tinfoil.sh")).toMatch(/only runs/);
  expect(keys.keySyncProfile()).toEqual({
    terminal: "https://terminal.tinfoil.sh",
    api_origin: "https://api.tinfoil.sh",
    callback: "http://localhost:49152/callback",
    completion: "https://terminal.tinfoil.sh/cli/complete",
  });
});

test("explicit logout removes even an unresolved KEK, and a late write stores nothing", async () => {
  server.unreachable = 4;
  await expect(setup()).rejects.toThrow();
  expect(await kekRecords()).toHaveLength(1);
  const sign_in = await fence();
  const offline: keys.Api = async () => {
    throw new TypeError("offline");
  };
  const { covered, unresolved } = await keys.settlePending(
    offline,
    USER,
    sign_in,
  );
  expect(unresolved).toBe(true);
  expect(await keys.forgetManualKEKs(ORIGIN, USER, sign_in, covered)).toBe(
    true,
  );
  expect(await kekRecords()).toEqual([]);
  // A passkey prompt that resolves after sign-out neither saves nor commits.
  const signOut = new AbortController();
  const slow = {
    ...manager,
    createAndWrapKey: async (
      input: Parameters<PasskeyKeyManager["createAndWrapKey"]>[0],
    ) => {
      const created = await manager.createAndWrapKey(input);
      signOut.abort();
      return created;
    },
  } as PasskeyKeyManager;
  const bodies = server.bodies.length;
  for (const method of ["passkey", "manual"] as const)
    await expect(
      keys.setupMK({
        api: server.api,
        manager: method === "passkey" ? slow : manager,
        user_id: USER,
        state: await server.state(),
        method,
        resources: [],
        signal: signOut.signal,
        fence: await fence(),
      }),
    ).rejects.toThrow();
  // A write still running under the ended sign-in is refused in its transaction.
  await expect(
    keys.setupMK({
      api: server.api,
      manager,
      user_id: USER,
      state: await server.state(),
      method: "manual",
      resources: [],
      fence: sign_in,
    }),
  ).rejects.toThrow(/signed out in another tab/);
  expect(await kekRecords()).toEqual([]);
  expect(server.bodies.length).toBe(bodies);
});

test("a different DEK drops unlocked keys even with a pending write", async () => {
  const { unlocked } = await setup();
  unlocked.pending = JSON.parse(server.bodies[0]);
  const state = await server.state();
  expect(await keys.refreshUnlocked(unlocked, state)).toBe(unlocked);
  expect(
    await keys.refreshUnlocked(unlocked, {
      ...state,
      dek_id: b64u(new Uint8Array(16)),
    }),
  ).toBeUndefined();
});

describe("sign-out with an unresolved recovery commit", () => {
  test("a commit whose reply never arrived is settled exactly and its file offered before the wipe", async () => {
    // The initialize commits but its reply is still outstanding at sign-out.
    server.lose = () => new Promise(() => {});
    server.dropReplies = 1;
    void setup();
    while (server.revision === 0) await Bun.sleep(1);
    const sent = server.bodies.length;
    const sign_in = await fence();
    const { files, unresolved, covered } = await keys.settlePending(
      server.api,
      USER,
      sign_in,
    );
    expect(unresolved).toBe(false);
    // The committed DEK and recovery IDs settle it without another write.
    expect(server.bodies.length).toBe(sent);
    expect(server.revision).toBe(1);
    const state = await server.state();
    expect(
      (await keys.unlockFile(files[0].text, state, USER)).context.dek_id,
    ).toBe(state.dek_id!);
    await keys.forgetManualKEKs(ORIGIN, USER, sign_in, covered);
    expect(await kekRecords()).toEqual([]);
  });

  test("an outcome that stays unknown is reported and the key kept until an explicit wipe", async () => {
    server.dropReplies = 4;
    await expect(setup()).rejects.toThrow("reply lost");
    const offline: keys.Api = async () => {
      throw new TypeError("offline");
    };
    const sign_in = await fence();
    const settled = await keys.settlePending(offline, USER, sign_in);
    expect(settled).toMatchObject({ files: [], unresolved: true });
    expect(await pending()).not.toBeNull();
    await keys.forgetManualKEKs(ORIGIN, USER, sign_in, settled.covered);
    expect(await kekRecords()).toEqual([]);
  });

  test("a canceled settle exports nothing and leaves the pending record", async () => {
    server.dropReplies = 4;
    await expect(setup()).rejects.toThrow();
    const switched = new AbortController();
    switched.abort();
    await expect(
      keys.settlePending(server.api, USER, await fence(), switched.signal),
    ).rejects.toThrow();
    expect(await pending()).not.toBeNull();
    expect(
      await keys.settlePending(
        server.api,
        "user_2other",
        await keys.kekFence(ORIGIN, "user_2other"),
      ),
    ).toMatchObject({
      files: [],
      unresolved: false,
    });
  });

  test("an ended sign-in resends nothing pending; the current one settles it exactly", async () => {
    const ended = await fence();
    expect(await keys.forgetManualKEKs(ORIGIN, USER, ended, new Map())).toBe(
      true,
    );
    const current = await keys.kekFence(ORIGIN, USER, "sess_2");
    server.unreachable = 4;
    await expect(
      keys.setupMK({
        api: server.api,
        manager,
        user_id: USER,
        state: await server.state(),
        method: "manual",
        resources: [],
        fence: current,
      }),
    ).rejects.toThrow("network");
    const stale = await server.state();
    const canceled = new AbortController();
    canceled.abort();
    expect(await keys.reconcilePending(server.api, USER, stale, ended)).toBe(
      stale,
    );
    await expect(
      keys.reconcilePending(server.api, USER, stale, current, canceled.signal),
    ).rejects.toThrow();
    expect(server.bodies).toEqual([]);
    const { request } = await pending();
    const state = await keys.reconcilePending(server.api, USER, stale, current);
    expect(server.bodies.map((body) => JSON.parse(body))).toEqual([request]);
    expect(state.dek_id).not.toBeNull();
    expect(await pending()).toBeNull();
  });

  test("a setup that never committed is discarded and offers nothing", async () => {
    await setup("passkey");
    server.unreachable = 4;
    await expect(
      keys.setupMK({
        api: server.api,
        manager,
        user_id: USER,
        state: {
          ...(await server.state()),
          revision: 0,
          dek_id: null,
          encrypted_mk: null,
        },
        method: "manual",
        resources: [],
        fence: await fence(),
      }),
    ).rejects.toThrow("network");
    expect(await kekRecords()).toHaveLength(1);
    expect(
      await keys.settlePending(server.api, USER, await fence()),
    ).toMatchObject({
      files: [],
      unresolved: false,
    });
    expect(await kekRecords()).toEqual([]);
  });
});
