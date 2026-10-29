import { describe, expect, test } from "bun:test";
import { ed25519 } from "@noble/curves/ed25519.js";
import { sha256 } from "@noble/hashes/sha2.js";
import { bytesToHex, concatBytes, utf8ToBytes } from "@noble/hashes/utils.js";
import {
  unb64u,
  type MKBinding,
  type MKResource,
} from "../src/hosted/contract";
import * as keys from "../src/hosted/keys";
import { openMonitor, type AttestMonitor } from "../src/hosted/monitors";
import { connectSandbox } from "../src/hosted/sandboxes";
import type { Container, Scope } from "../src/hosted/session";

const USER = "user_2fixtureA";
const MONITOR_ID = "0b8a3c52-61f4-4d3e-8d2a-6f1e9c4b7a10";
const SANDBOX_ID = "1b8a3c52-61f4-4d3e-8d2a-6f1e9c4b7a10";
const INSTANCE = "2b8a3c52-61f4-4d3e-8d2a-6f1e9c4b7a10";
const VOLUME = "3b8a3c52-61f4-4d3e-8d2a-6f1e9c4b7a10";
const HOST_KEY = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIBoot1";
const bucket = (account: string) =>
  `s3://agents?prefix=containers%2F${bytesToHex(sha256(utf8ToBytes(`org:${account}`)))}%2Fobj%2F&region=us-east-1`;
const env = (values: Record<string, string>) =>
  `containers:\n  - env:\n${Object.entries(values)
    .map(([k, v]) => `      - ${k}: "${v}"\n`)
    .join("")}`;

function fixture(
  binding: Partial<Record<"monitor" | "sandbox", MKBinding>> = {},
) {
  const monitor: MKResource = {
    ...keys.newResourceKey("monitor", keys.newAttempt()),
    binding: binding.monitor ?? null,
  };
  const sandbox: MKResource = {
    ...keys.newResourceKey("sandbox", keys.newAttempt()),
    binding: binding.sandbox ?? null,
  };
  const rows: Record<string, Container> = {
    [MONITOR_ID]: {
      id: MONITOR_ID,
      name: "monitor",
      repo: "tinfoilsh/confidential-agent-monitor",
      status: "running",
      domain: "monitor.example",
      clerk_user_id: USER,
      owner_key_mode: "tmk",
      owner_public_key: monitor.owner_public_key,
      config: env({ TINFOIL_STORAGE_BUCKET: bucket("org_A") }),
    },
    [SANDBOX_ID]: {
      id: SANDBOX_ID,
      name: "dev",
      repo: "tinfoilsh/confidential-agent-sandbox",
      status: "running",
      domain: "dev.example",
      clerk_user_id: USER,
      owner_key_mode: "tmk",
      owner_public_key: sandbox.owner_public_key,
      config: env({ SANDBOX_INSTANCE_ID: INSTANCE }),
      volumes: { workspace: VOLUME },
      network_policy: { egress: [{ container_id: MONITOR_ID }] },
    },
  };
  const updates: string[] = [];
  let resources = [monitor, sandbox];
  const scope = {
    user: USER,
    account: "org_A",
    signal: new AbortController().signal,
    live: () => true,
    unlocked: () => ({ payload: { version: 1, resources } }) as keys.Unlocked,
    fresh: async () => Object.values(rows),
    api: async (path: string) =>
      path === "/api/volumes"
        ? {
            volumes: [
              {
                id: rows[SANDBOX_ID].volumes?.workspace,
                container_id: SANDBOX_ID,
                slot: "workspace",
                size_bytes: 8_000_000_000,
              },
            ],
          }
        : rows[path.split("/").pop()!],
    update: async (delta: keys.Delta) => {
      updates.push(delta.toString());
      resources = delta({ version: 1, resources }).resources;
    },
  } as unknown as Scope;
  return { monitor, sandbox, rows, scope, updates, resources: () => resources };
}

// An attested Monitor that checks each signed owner request and records it.
function monitorServer(
  owner: MKResource,
  state: "present" | "absent",
  attested: () => string = () => HOST_KEY,
  reported = HOST_KEY,
) {
  const calls: { path: string; body: string }[] = [];
  let generation = 0;
  const attest: AttestMonitor = async ({ authorize }) => ({
    hostKey: attested,
    fetch: async (_input, init) => {
      const { request, signature } = JSON.parse(String(init!.body));
      const bytes = unb64u(request);
      const public_key = ed25519.getPublicKey(unb64u(owner.owner_seed, 32));
      const signed = concatBytes(
        utf8ToBytes("tinfoil owner request v2\0"),
        bytes,
      );
      if (!ed25519.verify(unb64u(signature, 64), signed, public_key))
        return new Response("invalid_signature", { status: 401 });
      const r = JSON.parse(new TextDecoder().decode(bytes));
      const body = new TextDecoder().decode(unb64u(r.body));
      calls.push({ path: r.path, body });
      const view = {
        generation,
        host_key: `${reported}\n`,
        config: { identities: {} },
      };
      if (r.path === "/healthz") return Response.json({ locked: true, state });
      if (r.path === "/unlock") {
        generation = 3;
        return Response.json({
          ...view,
          generation,
          initialized: state === "absent",
        });
      }
      if (r.path === "/requests") return Response.json([]);
      void authorize;
      return Response.json(view);
    },
  });
  return { attest, calls };
}

const open = (scope: Scope, attest: AttestMonitor) =>
  openMonitor({
    scope,
    id: MONITOR_ID,
    signal: new AbortController().signal,
    onCheckpoint: () => {},
    attest,
  });

describe("Monitor first open", () => {
  test("reads signed status before the state key, binds first and saves the newer generation", async () => {
    const f = fixture();
    const server = monitorServer(f.monitor, "absent");
    const opened = await open(f.scope, server.attest);
    expect(server.calls.map((c) => c.path)).toEqual([
      "/healthz",
      "/unlock",
      "/",
      "/requests",
    ]);
    const key = btoa(String.fromCharCode(...unb64u(f.monitor.storage_key, 32)));
    expect(
      server.calls.filter((c) => c.body.includes(key)).map((c) => c.path),
    ).toEqual(["/unlock"]);
    expect(opened.snapshot.view.generation).toBe(3);
    await Bun.sleep(0);
    const saved = f.resources().find((r) => r.key_id === f.monitor.key_id)!;
    expect(saved.binding?.bucket).toBe(bucket("org_A"));
    expect(saved.min_generation).toBe(3);
  });

  test("missing state below a saved generation is refused before the state key is sent", async () => {
    const f = fixture({
      monitor: {
        account: "org_A",
        container_id: MONITOR_ID,
        instance_id: null,
        volume_id: null,
        bucket: bucket("org_A"),
      },
    });
    f.monitor.min_generation = 2;
    const server = monitorServer(f.monitor, "absent");
    await expect(open(f.scope, server.attest)).rejects.toThrow(/missing/);
    expect(server.calls.map((c) => c.path)).toEqual(["/healthz"]);
  });

  test("the SSH pin follows the SDK's current verified boot and must match the Monitor's view", async () => {
    const f = fixture();
    let boot = HOST_KEY;
    const server = monitorServer(
      f.monitor,
      "present",
      () => boot,
      `${HOST_KEY}2`,
    );
    const attest: AttestMonitor = async (target, signal) => {
      const attested = await server.attest(target, signal);
      boot = `${HOST_KEY}2`;
      return attested;
    };
    const opened = await open(f.scope, attest);
    expect(opened.hostKey()).toBe(`${HOST_KEY}2`);
    const stale = fixture();
    const other = monitorServer(
      stale.monitor,
      "present",
      () => HOST_KEY,
      `${HOST_KEY}2`,
    );
    await expect(open(stale.scope, other.attest)).rejects.toThrow(/restarted/);
  });

  test("a changed bucket, another account's binding or a failed refresh never reaches the Monitor", async () => {
    const cases = [
      fixture({
        monitor: {
          account: "org_A",
          container_id: MONITOR_ID,
          instance_id: null,
          volume_id: null,
          bucket: bucket("org_B"),
        },
      }),
      fixture({
        monitor: {
          account: "org_B",
          container_id: MONITOR_ID,
          instance_id: null,
          volume_id: null,
          bucket: bucket("org_A"),
        },
      }),
    ];
    const failed = fixture();
    (failed.scope as { fresh: () => Promise<never> }).fresh = async () => {
      throw new Error("Your resources could not be refreshed. Try again.");
    };
    for (const f of [...cases, failed]) {
      let attested = false;
      const attest: AttestMonitor = async () => {
        attested = true;
        throw new Error("unreachable");
      };
      await expect(open(f.scope, attest)).rejects.toThrow();
      expect(attested).toBe(false);
      expect(f.updates).toEqual([]);
    }
  });
});

describe("sandbox binding", () => {
  const opened = (f: ReturnType<typeof fixture>) => {
    const relayed: unknown[] = [];
    return {
      relayed,
      monitor: {
        scope: f.scope,
        row: f.rows[MONITOR_ID],
        hostKey: () => HOST_KEY,
        client: { call: async (...args: unknown[]) => relayed.push(args) },
      } as never,
    };
  };
  const saved = {
    account: "org_A",
    container_id: SANDBOX_ID,
    instance_id: INSTANCE,
    volume_id: VOLUME,
    bucket: null,
  };

  test("a substituted workspace volume or another account's binding sends no sandbox request", async () => {
    for (const binding of [saved, { ...saved, account: "org_B" }]) {
      const f = fixture({ sandbox: binding });
      if (binding === saved)
        f.rows[SANDBOX_ID].volumes = {
          workspace: "4b8a3c52-61f4-4d3e-8d2a-6f1e9c4b7a10",
        };
      const { monitor, relayed } = opened(f);
      await expect(connectSandbox({ monitor, id: SANDBOX_ID })).rejects.toThrow(
        /no longer matches/,
      );
      expect(relayed).toEqual([]);
      expect(f.updates).toEqual([]);
    }
  });

  test("an unbound key is bound to the current instance and volume first", async () => {
    const f = fixture();
    const { monitor } = opened(f);
    await expect(connectSandbox({ monitor, id: SANDBOX_ID })).rejects.toThrow();
    expect(
      f.resources().find((r) => r.key_id === f.sandbox.key_id)!.binding,
    ).toEqual(saved);
  });
});
