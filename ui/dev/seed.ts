// Seeds the dev console (bun run dev --mode hosted with VITE_DEV_ACCOUNT) the
// way a person would, but from the dev account's fixed key, so the browser
// opens a Monitor that already has sandboxes, a trusted device, connections and
// a saved rule. Run `bun dev/seed.ts` with the dev server up. Idempotent: an
// existing Monitor named `monitor` is reused and its state reset.
import { readFileSync } from "node:fs";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { DEV_KEY, devAttest as attest, devToken } from "./account";
import * as cp from "../src/hosted/controlplane";
import {
  createMonitor,
  createSandbox,
  initIntents,
  openMonitor,
  sandboxIdentity,
} from "../src/hosted/monitors";
import { onboarded, sourceChanges } from "../src/owner";

const base = process.env.VITE_API_BASE_URL || "http://127.0.0.1:5173";
const root = fileURLToPath(new URL("../..", import.meta.url));
const pub = (file: string) =>
  readFileSync(join(root, ".dev", file), "utf8").trim();
const MONITOR = "monitor";
const SANDBOXES = [
  { name: "danielbox1", key: pub("sandbox_ed25519.pub") },
  { name: "danielbox2", key: pub("sandbox2_ed25519.pub") },
];
const DEVICE = pub("id_ed25519.pub");

// owner.ts keeps a little session state in web storage.
const memory = new Map<string, string>();
(globalThis as any).localStorage ??= {
  getItem: (k: string) => memory.get(k) ?? null,
  setItem: (k: string, v: string) => void memory.set(k, v),
  removeItem: (k: string) => void memory.delete(k),
};
(globalThis as any).sessionStorage ??= globalThis.localStorage;

const api = cp.controlplane(async () => devToken(), undefined, base);
const intents = initIntents(globalThis.localStorage, "user_dev");
const signal = new AbortController().signal;
const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms));
const log = (s: string) => console.log("seed:", s);

const untilRunning = async (id: string) => {
  for (let i = 0; i < 120; i++) {
    const row = await api.get(id);
    if (row.status === "running") return row;
    if (row.status === "failed") throw new Error(row.error_message || "failed");
    await sleep(500);
  }
  throw new Error(`${id} did not start`);
};

let rows = await api.list();
let monitor = rows.find(
  (r) => r.name === MONITOR && r.repo === cp.MONITOR_REPO,
);
if (!monitor) {
  log("creating Monitor");
  monitor = await createMonitor({
    api,
    root: DEV_KEY,
    name: MONITOR,
    tag: "dev",
    intents,
    signal,
  });
} else if (monitor.status !== "running") await api.start(monitor.id);
monitor = await untilRunning(monitor.id);
log(`Monitor ${monitor.id} running`);

for (const s of SANDBOXES) {
  let row = rows.find((r) => r.name === s.name);
  if (!row) {
    log(`creating sandbox ${s.name}`);
    row = await createSandbox({
      api,
      root: DEV_KEY,
      monitorId: monitor.id,
      tag: "dev",
      request: { name: s.name, instanceId: crypto.randomUUID() },
      intents,
      signal,
    });
  } else if (row.status !== "running") await api.start(row.id);
  await untilRunning(row.id);
}
rows = await api.list();

const session = await openMonitor({
  row: monitor,
  root: DEV_KEY,
  attest,
  intents,
  initialize: true,
  signal,
});
const { client } = session;
let view = await client.unlock(undefined, signal);
log(`Monitor open, generation ${view.generation}`);

if (!onboarded(view)) {
  view = await client.onboard(view, "known_only", undefined, {
    allowPaidInference: true,
    tinfoilApiKey: "tfm_tinfoil_dev_placeholder",
  });
  log("onboarded");
}

// Identities: two sandboxes and one trusted device.
const identities: Record<string, unknown> = {
  "device-laptop": { key: DEVICE, routes: true, accounts: {} },
};
for (const s of SANDBOXES)
  identities[sandboxIdentity(s.name)] = {
    key: s.key,
    accounts: {
      tinfoil: { level: "allow" },
      ...(s.name === "danielbox1" ? { network: { level: "ask" } } : {}),
    },
  };
view = await client.edit(sourceChanges({ identities }), signal);
log(`seeded ${Object.keys(identities).length} identities`);
session.close();
log("done — reload the console");
