import { execFile, spawn, type ChildProcess } from "node:child_process";
import { createHash, randomUUID } from "node:crypto";
import { existsSync, openSync, readFileSync } from "node:fs";
import { mkdir, writeFile } from "node:fs/promises";
import type { IncomingMessage, ServerResponse } from "node:http";
import { createServer, type AddressInfo } from "node:net";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { promisify } from "node:util";
import type { Plugin } from "vite";
import { stringify } from "yaml";
import type { Container } from "../src/hosted/controlplane";

// Answers the console's controlplane calls on this dev server: Monitors run as local
// processes and sandboxes boot under Podman through dev/cvm. State lives in .dev/console.
const root = fileURLToPath(new URL("../..", import.meta.url));
const dir = join(root, ".dev/console");
const saved = join(dir, "rows.json");
const binary = join(dir, "monitor");
const HEALTH_POLL_MS = 100;
const HEALTH_ATTEMPTS = 100;
const run = promisify(execFile);

type Row = Container & {
  env: Record<string, string>;
  ports?: { api: number; ssh: number };
};

const freePort = () =>
  new Promise<number>((resolve, reject) => {
    const server = createServer()
      .on("error", reject)
      .listen(0, "127.0.0.1", () => {
        const { port } = server.address() as AddressInfo;
        server.close(() => resolve(port));
      });
  });

const read = async (req: IncomingMessage) => {
  const chunks: Buffer[] = [];
  for await (const chunk of req) chunks.push(chunk);
  return Buffer.concat(chunks);
};

const send = (res: ServerResponse, status: number, data: unknown) => {
  res.statusCode = status;
  res.setHeader("Content-Type", "application/json");
  res.end(JSON.stringify(data));
};

// The controlplane verifies the Clerk token; here only its subject names the creator.
const subject = (req: IncomingMessage) =>
  JSON.parse(
    Buffer.from(
      req.headers.authorization?.split(".")[1] ?? "",
      "base64url",
    ).toString() || "{}",
  ).sub as string | undefined;

export default function local(): Plugin {
  const rows = new Map<string, Row>(
    existsSync(saved)
      ? (JSON.parse(readFileSync(saved, "utf8")) as Row[]).map((row) => [
          row.id,
          { ...row, status: "stopped" },
        ])
      : [],
  );
  const monitors = new Map<string, ChildProcess>();
  let built: Promise<unknown> | undefined;
  const save = () => writeFile(saved, JSON.stringify([...rows.values()]));

  const startMonitor = async (row: Row) => {
    built ??= run("go", ["build", "-tags", "dev", "-o", binary, "."], {
      cwd: root,
    });
    await built;
    const home = join(dir, row.id);
    await mkdir(join(home, "store"), { recursive: true });
    if (!existsSync(join(home, "host_key")))
      await run("ssh-keygen", [
        "-q",
        "-t",
        "ed25519",
        "-N",
        "",
        "-f",
        join(home, "host_key"),
      ]);
    const log = openSync(join(home, "log"), "a");
    const { api, ssh } = row.ports!;
    const child = spawn(
      binary,
      [
        "-listen",
        `127.0.0.1:${ssh}`,
        "-api",
        `127.0.0.1:${api}`,
        "-ssh-host-key",
        join(home, "host_key"),
      ],
      {
        cwd: root,
        env: { ...process.env, ...row.env },
        stdio: ["ignore", log, log],
      },
    );
    monitors.set(row.id, child);
    child.on("exit", () => {
      if (monitors.get(row.id) !== child) return;
      monitors.delete(row.id);
      row.status = "stopped";
      void save();
    });
    for (let attempt = 0; attempt < HEALTH_ATTEMPTS; attempt++) {
      if (child.exitCode !== null) break;
      if (
        await fetch(`http://127.0.0.1:${api}/healthz`).then(
          (r) => r.ok,
          () => false,
        )
      )
        return;
      await new Promise((resolve) => setTimeout(resolve, HEALTH_POLL_MS));
    }
    throw new Error(
      `Monitor did not become healthy; see ${join(home, "log")}.`,
    );
  };

  const startSandbox = async (row: Row) => {
    const monitor = rows.get(row.network_policy?.egress[0]?.container_id ?? "");
    if (monitor?.status !== "running")
      throw new Error("Start its Monitor first.");
    await run(
      join(root, "dev/cvm"),
      [
        `console-${row.id}`,
        String(monitor.ports!.ssh),
        `console-${row.volumes!.workspace}`,
      ],
      { cwd: root, env: { ...process.env, ...row.env } },
    );
  };

  const start = (row: Row) => {
    row.status = "deploying";
    row.error_message = undefined;
    (row.ports ? startMonitor(row) : startSandbox(row))
      .then(
        () => (row.status = "running"),
        (cause) => {
          row.status = "failed";
          row.error_message = String(cause.stderr || cause.message || cause);
        },
      )
      .finally(save);
  };

  const stop = async (row: Row) => {
    if (row.ports) monitors.get(row.id)?.kill();
    else await run("podman", ["rm", "-f", "--ignore", `console-${row.id}`]);
    row.status = "stopped";
  };

  const create = async (req: IncomingMessage, body: any): Promise<Row> => {
    const id = randomUUID();
    const monitor = "object_storage" in body;
    const env: Record<string, string> = { ...body.variables };
    if (monitor)
      env.TINFOIL_STORAGE_BUCKET = `file://${join(dir, id, "store")}?no_tmp_dir=true`;
    const config = stringify({
      containers: [
        {
          name: "workload",
          env: Object.entries(env).map(([k, v]) => ({ [k]: v })),
        },
      ],
    });
    return {
      id,
      name: body.name,
      repo: body.repo,
      status: "created",
      domain: `${req.headers.host}/monitors/${id}`,
      config,
      config_name:
        "/tinfoil/containers/" +
        createHash("sha256").update(config).digest("hex"),
      debug: false,
      clerk_user_id: subject(req),
      network_policy: body.network_policy ?? null,
      env,
      ...(monitor
        ? { ports: { api: await freePort(), ssh: await freePort() } }
        : { volumes: { workspace: body.volumes?.workspace ?? randomUUID() } }),
    };
  };

  const handle = async (req: IncomingMessage, res: ServerResponse) => {
    const path = new URL(req.url!, "http://local").pathname;
    const rpc = path.match(/^\/monitors\/([^/]+)\/owner\/rpc$/);
    if (rpc && req.method === "POST") {
      const row = rows.get(rpc[1]);
      if (!row?.ports) return send(res, 404, { error: "No such Monitor." });
      const reply = await fetch(`http://127.0.0.1:${row.ports.api}/owner/rpc`, {
        method: "POST",
        headers: {
          "Content-Type": req.headers["content-type"] ?? "application/json",
        },
        body: await read(req),
      });
      res.statusCode = reply.status;
      res.setHeader(
        "Content-Type",
        reply.headers.get("Content-Type") ?? "application/json",
      );
      return res.end(Buffer.from(await reply.arrayBuffer()));
    }
    if (path.match(/^\/api\/github\/repos\/.+\/tags$/))
      return send(res, 200, {
        tags: [{ name: "dev", has_release: true, latest: true }],
      });
    if (path === "/api/volumes")
      return send(res, 200, {
        volumes: [...rows.values()]
          .filter((row) => row.volumes)
          .map((row) => ({
            id: row.volumes!.workspace,
            name: `${row.name}-workspace`,
            container_id: row.id,
            size_bytes: 0,
          })),
      });
    if (path === "/api/containers" && req.method === "GET")
      return send(res, 200, [...rows.values()]);
    if (path === "/api/containers" && req.method === "POST") {
      const body = JSON.parse((await read(req)).toString());
      if ([...rows.values()].some((row) => row.name === body.name))
        return send(res, 409, { error: `${body.name} already exists.` });
      const row = await create(req, body);
      rows.set(row.id, row);
      start(row);
      return send(res, 200, row);
    }
    const action = path.match(/^\/api\/containers\/([^/]+)(\/deploy|\/stop)?$/);
    const row = action && rows.get(decodeURIComponent(action[1]));
    if (!row) return send(res, 404, { error: "Not found." });
    if (action![2] === "/deploy") start(row);
    if (action![2] === "/stop") await stop(row);
    await save();
    send(res, 200, row);
  };

  return {
    name: "local-controlplane",
    async configureServer(server) {
      await mkdir(dir, { recursive: true });
      server.httpServer?.once("close", () =>
        monitors.forEach((child) => child.kill()),
      );
      server.middlewares.use((req, res, next) => {
        if (!req.url?.startsWith("/api/") && !req.url?.startsWith("/monitors/"))
          return next();
        handle(req, res).catch((cause) =>
          send(res, 500, { error: String(cause) }),
        );
      });
    },
  };
}
