import { spawn, type ChildProcess } from "node:child_process";
import { existsSync } from "node:fs";
import { mkdir, writeFile } from "node:fs/promises";
import { dirname, join } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";

// Run with `bun dev/run.ts`. Extra arguments go to Monitor.
const root = join(dirname(fileURLToPath(import.meta.url)), "..");
const ui = join(root, "ui");
const directory = join(root, ".dev");
const vitePort = process.env.MONITOR_UI_PORT ?? "5173";
const children = new Set<ChildProcess>();

function start(command: string[], cwd = root) {
  const child = spawn(command[0]!, command.slice(1), {
    cwd,
    stdio: "inherit",
    detached: true,
  });
  children.add(child);
  const exited = new Promise<number>((resolve, reject) => {
    child.once("error", reject);
    child.once("exit", (code) => resolve(code ?? 1));
  }).finally(() => children.delete(child));
  return { child, exited };
}

function stop() {
  for (const child of children) {
    if (child.pid) {
      try {
        process.kill(-child.pid, "SIGTERM");
      } catch {}
    }
  }
}
process.on("SIGINT", () => {
  stop();
  process.exit(130);
});
process.on("SIGTERM", () => {
  stop();
  process.exit(143);
});
process.on("exit", stop);

async function run(command: string[], cwd = root) {
  const code = await start(command, cwd).exited;
  if (code !== 0)
    throw new Error(`${command.join(" ")} exited with status ${code}`);
}

try {
  await mkdir(join(directory, "store"), { recursive: true, mode: 0o700 });
  await run([process.execPath, "install", "--frozen-lockfile"], ui);
  // Go requires an embed target, but development serves source through Vite.
  // Production assets are built by go generate or the Docker build.
  if (!existsSync(join(ui, "dist/index.html"))) {
    await mkdir(join(ui, "dist"), { recursive: true });
    await writeFile(
      join(ui, "dist/index.html"),
      "<!doctype html><title>Monitor</title><p>Start the UI with bun dev/run.ts, or build it with bun run --cwd ui build.</p>\n",
    );
  }
  const executable = join(directory, "monitor");
  await run(["go", "build", "-o", executable, "."]);

  const vite = start(
    [
      process.execPath,
      join(ui, "node_modules/vite/bin/vite.js"),
      "--port",
      vitePort,
    ],
    ui,
  );
  const monitor = start([
    executable,
    "-bucket",
    `${pathToFileURL(join(directory, "store"))}?no_tmp_dir=true`,
    "-ui-dev-url",
    `http://127.0.0.1:${vitePort}`,
    ...process.argv.slice(2),
  ]);
  console.log(
    "Monitor UI: http://127.0.0.1:8080/app/ (or the address passed with -api)",
  );
  process.exitCode = await Promise.race([vite.exited, monitor.exited]);
} catch (error) {
  console.error(error instanceof Error ? error.message : error);
  process.exitCode = 1;
} finally {
  stop();
}
