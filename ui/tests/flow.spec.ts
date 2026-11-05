import { expect, test } from "bun:test";
import { createFullFlow, delay } from "../dev/flow";

test("the full flow loads inventory but keeps boot pending until Monitor selection", async () => {
  const flow = createFullFlow();
  expect(flow.inventoryLoading()).toBe(true);
  expect(flow.booting()).toBe(true);
  await delay(1300);
  expect(flow.inventoryLoading()).toBe(false);
  expect(flow.booting()).toBe(true);
  const abort = new AbortController();
  const starting = flow.start(abort.signal);
  abort.abort(new Error("cancelled"));
  await expect(starting).rejects.toThrow("cancelled");
  expect(flow.booting()).toBe(true);
});

test("delayed preview stages abort without waiting for their timer", async () => {
  const abort = new AbortController();
  const pending = delay(60_000, abort.signal);
  abort.abort(new Error("left preview"));
  await expect(pending).rejects.toThrow("left preview");
});
