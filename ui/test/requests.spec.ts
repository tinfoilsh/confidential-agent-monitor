import { expect, test } from "bun:test";
import { createComputed, createRoot, createSignal } from "solid-js";
import { createRequestLog } from "../src/requests";
import { ordered, type RequestRecord } from "../src/owner.js";

const record = (
  id: string,
  state: RequestRecord["state"],
  expires?: number,
): RequestRecord => ({
  id,
  state,
  time: new Date(0).toISOString(),
  expires: expires === undefined ? undefined : new Date(expires).toISOString(),
  facts: { principal: { name: "agent" }, account: "api" },
});

test("clock ticks preserve the log and index until a deadline changes state", () => {
  createRoot((dispose) => {
    try {
      const source = Array.from({ length: 10000 }, (_, i) =>
        record(String(i), i < 100 ? "pending" : "allowed", 100000),
      );
      const [now, setNow] = createSignal(0);
      const log = createRequestLog(() => source, now);
      let updates = 0;
      createComputed(() => {
        log.records();
        updates++;
      });
      const index = log.byId();
      for (let time = 1000; time < 100000; time += 1000) setNow(time);
      expect(log.records()).toBe(source);
      expect(log.byId()).toBe(index);
      expect(log.pendingCount()).toBe(100);
      expect(updates).toBe(1);
      setNow(100000);
      expect(log.pendingCount()).toBe(0);
      expect(log.byId().get("0")?.state).toBe("expired");
      expect(log.byId().get("9999")).toBe(source[9999]);
      expect(source[0].state).toBe("pending");
      expect(updates).toBe(2);
      const expired = log.records();
      setNow(101000);
      expect(log.records()).toBe(expired);
      expect(updates).toBe(2);
    } finally {
      dispose();
    }
  });
});

test("expiry handles unordered, equal, absent and invalid deadlines and clock corrections", () => {
  createRoot((dispose) => {
    try {
      const source = [
        record("later", "pending", 5000),
        record("first", "pending", 1000),
        record("same", "pending", 1000),
        record("no-deadline", "pending"),
        { ...record("invalid", "pending"), expires: "invalid" },
        record("finished", "approved", 0),
      ];
      const [now, setNow] = createSignal(0);
      const log = createRequestLog(() => source, now);
      expect(log.pendingCount()).toBe(5);
      setNow(1000);
      expect(log.pendingCount()).toBe(3);
      expect(log.byId().get("first")?.state).toBe("expired");
      expect(log.byId().get("same")?.state).toBe("expired");
      setNow(6000);
      expect(log.pendingCount()).toBe(2);
      expect(log.byId().get("finished")).toBe(source[5]);
      setNow(0);
      expect(log.pendingCount()).toBe(5);
      expect(log.records()).toBe(source);
    } finally {
      dispose();
    }
  });
});

test("polls and optimistic decisions update the index even with the same expiry count", () => {
  createRoot((dispose) => {
    try {
      const [source, setSource] = createSignal([
        record("a", "pending", 1000),
        record("b", "pending", 3000),
      ]);
      const [now, setNow] = createSignal(2000);
      const log = createRequestLog(source, now);
      expect(log.pendingCount()).toBe(1);
      setSource([record("a", "pending", 3000), record("b", "pending", 1000)]);
      expect(log.pendingCount()).toBe(1);
      expect(log.byId().get("a")?.state).toBe("pending");
      expect(log.byId().get("b")?.state).toBe("expired");
      const decision = {
        ...source()[0],
        state: "approved" as const,
        savingDecision: true,
      };
      setSource([decision, source()[1]]);
      expect(log.pendingCount()).toBe(0);
      expect(log.byId().get("a")).toBe(decision);
      setNow(4000);
      expect(log.byId().get("a")).toBe(decision);
      setSource([]);
      expect(log.records()).toEqual([]);
      expect(log.byId().size).toBe(0);
      expect(log.pendingCount()).toBe(0);
    } finally {
      dispose();
    }
  });
});

test("ordering preserves history order within priorities and honors dismissed requests", () => {
  const history = [
    record("allowed", "allowed"),
    record("dismissed", "expired"),
    record("later", "pending", 2000),
    record("expired", "expired"),
    record("sooner", "pending", 1000),
    record("approved", "approved"),
  ];
  expect(ordered(history, ["dismissed"]).map((r) => r.id)).toEqual([
    "sooner",
    "later",
    "expired",
    "allowed",
    "dismissed",
    "approved",
  ]);
  expect(history[0].id).toBe("allowed");
});
