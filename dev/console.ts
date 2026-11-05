// bun dev/console.ts — isolated local account + real Monitor + hot-reloaded UI.
import { spawn, type ChildProcess } from "node:child_process";
import { existsSync } from "node:fs";
import { mkdir, writeFile } from "node:fs/promises";
import { fileURLToPath, pathToFileURL } from "node:url";
import { join } from "node:path";
import {
  edits,
  onboarded,
  ownerClient,
  sourceChanges,
} from "../ui/src/monitor/owner";
import {
  BACKEND,
  DEVICE_ID,
  identities,
  ORIGIN,
  STORAGE_KEY,
} from "../ui/dev/fixtures";

const root = fileURLToPath(new URL("../", import.meta.url));
const ui = join(root, "ui");
const directory = join(root, ".dev/console");
const children = new Set<ChildProcess>();
function start(args: string[], cwd = root) {
  const child = spawn(args[0]!, args.slice(1), {
    cwd,
    stdio: "inherit",
    detached: true,
  });
  children.add(child);
  const done = new Promise<number>((resolve, reject) => {
    child.once("error", reject);
    child.once("exit", (code) => resolve(code ?? 1));
  }).finally(() => children.delete(child));
  // A failed start must not become an unhandled rejection during readiness.
  done.catch(() => {});
  return { child, done };
}
function stop() {
  for (const child of children)
    if (child.pid) {
      try {
        process.kill(-child.pid, "SIGTERM");
      } catch {}
    }
}
for (const signal of ["SIGINT", "SIGTERM"] as const)
  process.on(signal, () => {
    stop();
    process.exit(signal === "SIGINT" ? 130 : 143);
  });
process.on("exit", stop);

try {
  // Never reuse somebody else's service or .dev/store.
  const { createServer } = await import("node:net");
  for (const port of [5176, 8083, 2226])
    await new Promise<void>((resolve, reject) => {
      const probe = createServer();
      probe.once("error", () =>
        reject(
          new Error(`Port ${port} is in use; no existing service was touched.`),
        ),
      );
      probe.listen(port, "127.0.0.1", () => probe.close(() => resolve()));
    });
  if (!existsSync(join(ui, "node_modules/vite/bin/vite.js")))
    throw new Error("Run bun install --frozen-lockfile in ui/ first.");
  await mkdir(join(directory, "store"), { recursive: true, mode: 0o700 });
  if (!existsSync(join(ui, "dist/index.html"))) {
    await mkdir(join(ui, "dist"), { recursive: true });
    await writeFile(
      join(ui, "dist/index.html"),
      "<!doctype html><title>Local Monitor development</title>",
    );
  }
  console.log("Building local Monitor…");
  const executable = join(directory, "monitor");
  const code = await start(["go", "build", "-o", executable, "."]).done;
  if (code) throw new Error(`Go build failed (${code}).`);
  const monitor = start([
    executable,
    "-listen",
    "127.0.0.1:2226",
    "-api",
    "127.0.0.1:8083",
    "-bucket",
    `${pathToFileURL(join(directory, "store"))}?no_tmp_dir=true`,
  ]);
  let ready = false;
  for (let i = 0; i < 100; i++) {
    if (monitor.child.exitCode !== null)
      throw new Error("Local Monitor exited during startup.");
    if (
      await fetch(`${BACKEND}/healthz`)
        .then((r) => r.ok)
        .catch(() => false)
    ) {
      ready = true;
      break;
    }
    await new Promise((resolve) => setTimeout(resolve, 100));
  }
  if (!ready) throw new Error("Local Monitor did not become ready.");
  const client = ownerClient({ endpoint: BACKEND, key: STORAGE_KEY });
  let view = await client.unlock();
  // Seed once. Restarts preserve the connections/permissions edited in the UI.
  if (!onboarded(view)) {
    view = await client.onboard(view, "known_only", undefined, {
      allowPaidInference: false,
    });
    await client.edit(sourceChanges({ identities }));
    console.log(
      "Seeded two fake sandbox identities and a trusted development device.",
    );
  }
  // Repair the old fixture name without resetting any permissions edited in dev.
  const oldDevice = view.config.identities?.["dev-laptop"];
  if (
    oldDevice?.key === identities[DEVICE_ID].key &&
    !view.config.identities?.[DEVICE_ID]
  ) {
    await client.edit([
      ...sourceChanges({ identities: { [DEVICE_ID]: oldDevice } }),
      ...edits.removeAgent("dev-laptop"),
    ]);
  }
  const vite = start(
    [
      process.execPath,
      join(ui, "node_modules/vite/bin/vite.js"),
      "--mode",
      "dev-console",
    ],
    ui,
  );
  console.log(
    `Local console: ${ORIGIN}\nAll state: ${directory}\nFake account/passkeys and sandbox inventory. Sandbox VMs and shells are not started.`,
  );
  process.exitCode = await Promise.race([monitor.done, vite.done]);
} catch (cause) {
  console.error(cause instanceof Error ? cause.message : cause);
  process.exitCode = 1;
} finally {
  stop();
}
