import { afterEach, expect, mock, test } from "bun:test";
import type { Clerk } from "@clerk/clerk-js/no-rhc";

class ApiError extends Error {
  constructor(
    readonly status: number,
    readonly body: { error: string },
  ) {
    super(body.error);
  }
}

mock.module("../src/hosted/keys", () => ({
  TARGETS: { api_origin: "https://api.example" },
  ApiError,
  kekFence: async () => ({ epoch: "test", session: "session_test" }),
  fenceEnded: async () => false,
  readKeyState: (api: (path: string) => Promise<unknown>) => api("/keys"),
  reconcilePending: async (_api: unknown, _id: string, state: unknown) => state,
  refreshUnlocked: async (unlocked: unknown) => unlocked,
}));

const { createSession } = await import("../src/hosted/session");
const originalFetch = globalThis.fetch;
const originalAdd = globalThis.addEventListener;
const originalRemove = globalThis.removeEventListener;
const originalDocument = globalThis.document;
const dispose: (() => void)[] = [];

afterEach(() => {
  for (const stop of dispose.splice(0)) stop();
  globalThis.fetch = originalFetch;
  globalThis.addEventListener = originalAdd;
  globalThis.removeEventListener = originalRemove;
  globalThis.document = originalDocument;
});

function deferred<T>() {
  let resolve!: (value: T) => void;
  const promise = new Promise<T>((done) => {
    resolve = done;
  });
  return { promise, resolve };
}

function setup() {
  globalThis.addEventListener = () => {};
  globalThis.removeEventListener = () => {};
  globalThis.document = {
    addEventListener() {},
    removeEventListener() {},
    visibilityState: "hidden",
  } as unknown as Document;
  let sync = () => {};
  const clerk = {
    user: { id: "user_test" },
    organization: null,
    session: { id: "session_test", getToken: async () => "token" },
    addListener(listener: () => void) {
      sync = listener;
      return () => {};
    },
  };
  const session = createSession(clerk as unknown as Clerk);
  dispose.push(() => session.dispose());
  return { session, clerk, sync: () => sync() };
}

const keyState = {
  revision: 0,
  dek_id: null,
  encrypted_mk: null,
  recovery: [],
};
const monitor = {
  id: "11111111-1111-4111-8111-111111111111",
  name: "monitor",
  repo: "tinfoilsh/confidential-agent-monitor",
  status: "running",
  domain: "monitor.example",
  owner_key_mode: "tmk",
  owner_public_key: "ed25519:test",
};

test("resource and key reads report loading until their responses settle", async () => {
  const inventory = deferred<Response>();
  const keys = deferred<Response>();
  globalThis.fetch = mock((input) =>
    String(input).endsWith("/keys") ? keys.promise : inventory.promise,
  ) as typeof fetch;
  const { session } = setup();
  expect(session.inventory().loading).toBe(true);
  expect(session.inventory().error).toBeUndefined();
  expect(session.keyState().loading).toBe(true);
  inventory.resolve(Response.json([monitor]));
  keys.resolve(Response.json(keyState));
  await session.refresh();
  expect(session.inventory().loading).toBe(false);
  expect(session.inventory().value?.[0].name).toBe("monitor");
  expect(session.keyState().loading).toBe(false);
  expect(session.keyState().error).toBeUndefined();
});

test("a genuine failure is shown only after settling and clears during retry", async () => {
  globalThis.fetch = mock(async (input) =>
    String(input).endsWith("/keys")
      ? Response.json(keyState)
      : Response.json({ error: "Service unavailable" }, { status: 503 }),
  ) as typeof fetch;
  const { session } = setup();
  await session.refresh();
  expect(session.inventory().loading).toBe(false);
  expect(session.inventory().error).toBe("Service unavailable");
  const retry = deferred<Response>();
  globalThis.fetch = mock((input) =>
    String(input).endsWith("/keys")
      ? Promise.resolve(Response.json(keyState))
      : retry.promise,
  ) as typeof fetch;
  const done = session.refresh();
  expect(session.inventory().loading).toBe(true);
  expect(session.inventory().error).toBeUndefined();
  retry.resolve(Response.json([monitor]));
  await done;
  expect(session.inventory().loading).toBe(false);
  expect(session.inventory().error).toBeUndefined();
});

test("an old account's late result cannot replace the new account's loading state", async () => {
  const previous = deferred<Response>();
  const next = deferred<Response>();
  let calls = 0;
  globalThis.fetch = mock((input) =>
    String(input).endsWith("/keys")
      ? Promise.resolve(Response.json(keyState))
      : ++calls === 1
        ? previous.promise
        : next.promise,
  ) as typeof fetch;
  const { session, clerk, sync } = setup();
  const first = session.refresh();
  // Let the first account's token and fetch start before switching accounts.
  await Promise.resolve();
  await Promise.resolve();
  clerk.user = { id: "user_next" };
  sync();
  const second = session.refresh();
  previous.resolve(Response.json([monitor]));
  await first;
  expect(session.inventory().loading).toBe(true);
  expect(session.inventory().value).toBeUndefined();
  next.resolve(Response.json([]));
  await second;
  expect(session.inventory().loading).toBe(false);
  expect(session.inventory().value).toEqual([]);
});
