import { expect, test } from "bun:test";
import type { Session } from "../src/terminal/session";
import { rows } from "../dev/fixtures";
import { hold, previewSession, scenarioOf } from "../dev/scenarios";

const unlocked = { fixture: true };
const base = {
  inventory: () => ({ value: rows, loading: false }),
  keyState: () => ({ value: { revision: 1 } }),
  unlocked: () => unlocked,
} as unknown as Session;

test("loading scenarios are render-only and never clear real keys or inventory", () => {
  expect(previewSession(base, "keys-loading").unlocked()).toBeUndefined();
  expect(previewSession(base, "keys-loading").keyState()).toEqual({
    loading: true,
  });
  expect(previewSession(base, "inventory-loading").inventory()).toEqual({
    loading: true,
  });
  expect(base.unlocked()).toBe(unlocked);
  expect(base.inventory().value).toBe(rows);
});

test("booting/stopped scenarios change only the rendered Monitor row", () => {
  const booting = previewSession(base, "monitor-booting").inventory().value!;
  const stopped = previewSession(base, "monitor-stopped").inventory().value!;
  expect(booting[0].status).toBe("pending");
  expect(stopped[0].status).toBe("stopped");
  expect(booting[1]).toBe(rows[1]);
  expect(rows[0].status).toBe("running");
  expect(scenarioOf("unrecognized")).toBeUndefined();
  expect(previewSession(base)).toBe(base);
});

test("the locked preview opens only after the real unlock action completes", async () => {
  let completed = false;
  const source = {
    ...base,
    bind: () => ({
      setUnlocked: async () => {
        completed = true;
      },
    }),
  } as unknown as Session;
  const locked = previewSession(source, "monitor-locked");
  expect(locked.unlocked()).toBeUndefined();
  await locked.bind().setUnlocked(base.unlocked());
  expect(completed).toBe(true);
  expect(locked.unlocked()).toBe(base.unlocked());
});

test("pending preview work is cancelled rather than becoming a late result", async () => {
  const abort = new AbortController();
  const pending = hold(abort.signal);
  abort.abort(new Error("cancelled"));
  await expect(pending).rejects.toThrow("cancelled");
});
