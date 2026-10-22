import { expect, test } from "bun:test";
import { createComputed, createRoot, createSignal } from "solid-js";
import { createRequestLog } from "../src/requests";
import {
  decisions,
  edits,
  ordered,
  previewChanges,
  reviewStatus,
  tinfoilSetup,
  type RequestRecord,
  type View,
} from "../src/owner.js";

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

test("Tinfoil setup uses connection names for private inference and MCP URLs", () => {
  const view = {
    config: {
      accounts: {
        bob: {
          connections: {
            "": { tinfoil: {} },
            websearch: { "tinfoil-mcp": {} },
            other: { mcp: {} },
          },
        },
        team: { connections: { inference: { tinfoil: {} } } },
      },
    },
  } as unknown as View;
  expect(tinfoilSetup(view, "bob")).toEqual([
    { connection: "bob", mcp: false, url: "https://bob.monitor/v1" },
    {
      connection: "bob-websearch",
      mcp: true,
      url: "https://bob-websearch.monitor/mcp",
    },
  ]);
  expect(tinfoilSetup(view, "team")).toEqual([
    {
      connection: "team-inference",
      mcp: false,
      url: "https://team-inference.monitor/v1",
    },
  ]);
  expect(tinfoilSetup(view, "missing")).toEqual([]);
});

test("reviewing attested MCP tools saves the pin under its connector kind", () => {
  const pin = {
    instructions: "Search public pages",
    tools: [{ name: "search", inputSchema: { type: "object" } }],
  };
  const view = {
    config: {
      accounts: {
        bob: {
          connections: {
            "": { tinfoil: { enclave: "inference.tinfoil.sh" } },
            websearch: {
              "tinfoil-mcp": { url: "https://websearch.tinfoil.sh/mcp" },
            },
          },
        },
      },
    },
    status: { "bob-websearch": { details: { pin } } },
  } as unknown as View;
  const before = structuredClone(view);
  const approved = previewChanges(
    { ...view },
    edits.approveTools(view, "bob", "websearch"),
  );
  expect(approved.config.accounts?.bob.connections?.websearch).toEqual({
    "tinfoil-mcp": { url: "https://websearch.tinfoil.sh/mcp", pin },
  });
  expect(approved.config.accounts?.bob.connections?.[""]).toEqual(
    before.config.accounts?.bob.connections?.[""],
  );
  expect(view).toEqual(before);
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

test("Tinfoil review stays in activity and enters the owner's inbox only on handoff", () => {
  createRoot((dispose) => {
    try {
      const reviewing: RequestRecord = {
        ...record("review", "pending", 5000),
        reviewer: "tinfoil",
      };
      const human = record("human", "pending", 4000);
      const [source, setSource] = createSignal([reviewing, human]);
      const [now, setNow] = createSignal(0);
      const log = createRequestLog(source, now);
      expect(log.pendingCount()).toBe(1);
      expect(log.records()).toHaveLength(2);
      expect(decisions(reviewing).once).toBe(true);
      expect(reviewStatus(reviewing)).toBe("Tinfoil is reviewing");
      expect(ordered(log.records())[0].id).toBe("human");
      const handedBack: RequestRecord = {
        ...reviewing,
        reviewer: "",
        reviews: [
          {
            by: "tinfoil",
            decision: "escalate",
            reason: "Need context",
            time: new Date(0).toISOString(),
          },
        ],
      };
      setSource([handedBack, human]);
      expect(log.pendingCount()).toBe(2);
      expect(decisions(handedBack).once).toBe(true);
      expect(reviewStatus(handedBack)).toBe("Tinfoil needs your decision");
      expect(
        reviewStatus({
          ...handedBack,
          state: "approved",
          savingDecision: true,
        }),
      ).toBe("Approved by you");
      setNow(5000);
      expect(log.pendingCount()).toBe(0);
      expect(log.byId().get("review")?.state).toBe("expired");
      expect(
        reviewStatus({
          ...reviewing,
          state: "approved",
          reviews: [{ by: "tinfoil", decision: "once", time: "" }],
        }),
      ).toBe("Approved by Tinfoil");
    } finally {
      dispose();
    }
  });
});

test("removing the review connection returns delegated agents to the owner", () => {
  const view = {
    config: {
      reviewer: {
        connection: "inference",
        model: "test",
        instructions: "Review",
      },
      accounts: { inference: { connections: { "": { tinfoil: {} } } } },
      identities: { worker: { reviewer: "tinfoil" }, other: {} },
    },
  } as unknown as View;
  previewChanges(view, edits.removeAccount(view, "inference"));
  expect(view.config.reviewer).toBeUndefined();
  expect(view.config.identities?.worker.reviewer).toBeUndefined();
  expect(view.config.identities?.other.reviewer).toBeUndefined();
});
