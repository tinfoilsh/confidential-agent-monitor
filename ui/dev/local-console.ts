import { mkdirSync, readFileSync, writeFileSync, existsSync } from "node:fs";
import { fileURLToPath } from "node:url";
import type { IncomingMessage } from "node:http";
import type { Plugin } from "vite";
import type { KeyState } from "../src/terminal/keys.ts";
import { ORIGIN, rows } from "./fixtures.ts";

const empty = (): KeyState => ({
  revision: 0,
  dek_id: null,
  encrypted_mk: null,
  recovery: [],
});
const directory = fileURLToPath(
  new URL("../../.dev/console/", import.meta.url),
);
const file = directory + "keys.json";

export function localRequestAllowed(req: Pick<IncomingMessage, "headers">) {
  return (
    req.headers.host === new URL(ORIGIN).host &&
    (!req.headers.origin || req.headers.origin === ORIGIN) &&
    (!req.headers["sec-fetch-site"] ||
      ["same-origin", "none"].includes(String(req.headers["sec-fetch-site"])))
  );
}

// This plugin is only installed by `vite --mode dev-console` while serving loopback.
// It implements just the inventory and revisioned key-state APIs, never a cloud API.
export default function localConsole(): Plugin {
  mkdirSync(directory, { recursive: true, mode: 0o700 });
  let state: KeyState = existsSync(file)
    ? JSON.parse(readFileSync(file, "utf8"))
    : empty();
  return {
    name: "local-console-account",
    apply: "serve",
    configureServer(server) {
      server.middlewares.use(async (req, res, next) => {
        const path = new URL(req.url ?? "/", ORIGIN).pathname;
        if (!path.startsWith("/api/") && !path.startsWith("/__dev/monitor"))
          return next();
        const reply = (status: number, body: unknown) => {
          res.writeHead(status, {
            "Content-Type": "application/json",
            "Cache-Control": "no-store",
          });
          res.end(JSON.stringify(body));
        };
        if (!localRequestAllowed(req))
          return reply(403, { error: "Local development requests only." });
        if (path.startsWith("/__dev/monitor")) return next();
        try {
          if (req.method === "GET" && path === "/api/containers")
            return reply(200, rows);
          if (req.method === "GET" && path.startsWith("/api/containers/")) {
            const row = rows.find(
              (r) => r.id === path.slice("/api/containers/".length),
            );
            return reply(row ? 200 : 404, row ?? { error: "not_found" });
          }
          if (path !== "/api/sandboxes/owner-key")
            return reply(404, {
              error: "Not implemented by the local development API.",
            });
          if (req.method === "GET") return reply(200, state);
          if (req.method !== "PUT" && req.method !== "DELETE")
            return reply(405, { error: "method_not_allowed" });
          let body = "";
          for await (const chunk of req) {
            body += chunk;
            if (body.length > 1024 * 1024)
              return reply(413, { error: "body_too_large" });
          }
          const change = JSON.parse(body);
          if (change.expected_revision !== state.revision)
            return reply(409, { error: "stale_revision" });
          if (req.method === "DELETE")
            state = { ...empty(), revision: state.revision + 1 };
          else {
            if (
              typeof change.dek_id !== "string" ||
              typeof change.encrypted_mk !== "string" ||
              !Array.isArray(change.recovery)
            )
              return reply(400, { error: "invalid_key_state" });
            state = {
              revision: state.revision + 1,
              dek_id: change.dek_id,
              encrypted_mk: change.encrypted_mk,
              recovery: change.recovery,
            };
          }
          writeFileSync(file, JSON.stringify(state), { mode: 0o600 });
          return reply(200, { revision: state.revision });
        } catch (cause) {
          reply(400, {
            error: cause instanceof Error ? cause.message : String(cause),
          });
        }
      });
    },
  };
}
