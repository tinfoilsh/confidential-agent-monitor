import { afterEach, expect, mock, test } from "bun:test";

let options: Record<string, unknown>;
let allowed = true;
let ownerKey = "01".repeat(32);
mock.module("tinfoil", () => ({
  SecureClient: class {
    constructor(value: Record<string, unknown>) {
      options = value;
    }
    async ready({ signal }: { signal?: AbortSignal } = {}) {
      signal?.throwIfAborted();
      if (!allowed) throw new Error("fresh verification required");
    }
    async refresh() {}
    inspect() {
      return {
        verification: {
          cryptoMaterialData: (id: string) =>
            id === "host-ssh"
              ? "302a300506032b6570032100" + "02".repeat(32)
              : "302a300506032b656e032100" + ownerKey,
        },
      };
    }
  },
}));
mock.module("../src/terminal/templates", () => ({ TEMPLATES: {} }));
const { attestMonitor } = await import("../src/terminal/connection");
const target = {
  url: "https://monitor.example",
  reference: "acme/monitor@release-1@sha256:" + "a".repeat(64),
  registry: "https://registry.tinfoil.sh/scopes/" + "0".repeat(32),
};
afterEach(() => {
  allowed = true;
  ownerKey = "01".repeat(32);
});

test("uses registry trust and exact config pins for Monitor attestation", async () => {
  await attestMonitor(target, new AbortController().signal);
  expect(options.configRepo).toBe(target.reference);
  expect(options.verification).toEqual({ configScopes: [target.registry] });
});

test("requires fresh admission before returning a key for another owner session", async () => {
  const signal = new AbortController();
  const monitor = await attestMonitor(target, signal.signal);
  expect(await monitor.sessionKey()).toEqual(new Uint8Array(32).fill(1));
  ownerKey = "03".repeat(32);
  allowed = false;
  await expect(
    Promise.resolve().then(() => monitor.sessionKey()),
  ).rejects.toThrow("fresh verification required");
  allowed = true;
  expect(await monitor.sessionKey()).toEqual(new Uint8Array(32).fill(3));
  signal.abort(new Error("account changed"));
  await expect(
    Promise.resolve().then(() => monitor.sessionKey()),
  ).rejects.toThrow("account changed");
});
