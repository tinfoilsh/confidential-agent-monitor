import { request } from "node:https";
import type { IncomingHttpHeaders } from "node:http";
import type { Plugin } from "vite";

const ATTESTATION = "/.well-known/tinfoil-attestation";
const ENCAPSULATED_KEY = "ehbp-encapsulated-key";
const LOCAL_ORIGIN = "https://local.tinfoil.sh";
const MAX_BODY = 16 * 1024 * 1024;

// Use the SDK's existing relay contract. The browser still verifies the actual
// enclave and encrypts owner bodies to its attested key before they reach Vite.
export function relayTarget(
  method: string,
  path: string,
  headers: IncomingHttpHeaders,
) {
  const url = new URL(path, LOCAL_ORIGIN);
  if (url.pathname !== ATTESTATION && url.pathname !== "/owner/rpc") return;
  if (
    (headers.origin && headers.origin !== LOCAL_ORIGIN) ||
    (headers["sec-fetch-site"] &&
      headers["sec-fetch-site"] !== "same-origin" &&
      headers["sec-fetch-site"] !== "none")
  )
    throw new Error(
      "The monitor relay is only available to the local console.",
    );
  let target: URL;
  if (url.pathname === ATTESTATION) {
    if (
      method !== "GET" ||
      url.searchParams.size !== 2 ||
      url.searchParams.getAll("enclave").length !== 1 ||
      !/^[a-f0-9]{64}$/i.test(url.searchParams.get("nonce") ?? "")
    )
      throw new Error("Invalid attestation relay request.");
    target = new URL(`https://${url.searchParams.get("enclave")}`);
  } else {
    if (
      method !== "POST" ||
      url.search ||
      typeof headers[ENCAPSULATED_KEY] !== "string" ||
      !/^[a-f0-9]{64}$/i.test(headers[ENCAPSULATED_KEY]) ||
      typeof headers["x-tinfoil-enclave-url"] !== "string"
    )
      throw new Error("The monitor relay requires an encrypted owner request.");
    target = new URL(headers["x-tinfoil-enclave-url"]);
  }
  if (
    target.protocol !== "https:" ||
    target.port ||
    target.username ||
    target.password ||
    target.pathname !== "/" ||
    target.search ||
    target.hash ||
    !/^(?:[a-z0-9](?:[a-z0-9-]*[a-z0-9])?\.)+containers\.tinfoil\.dev$/.test(
      target.hostname,
    )
  )
    throw new Error(
      "The monitor relay only forwards to hosted Tinfoil containers.",
    );
  target.pathname = url.pathname;
  if (url.pathname === ATTESTATION)
    target.searchParams.set("nonce", url.searchParams.get("nonce")!);
  return target;
}

export default function monitorRelay(): Plugin {
  return {
    name: "local-monitor-relay",
    apply: "serve",
    configureServer(server) {
      server.middlewares.use((req, res, next) => {
        let target: URL | undefined;
        const fail = (status: number, message: string) => {
          if (res.headersSent) return res.destroy();
          res.writeHead(status, {
            "Content-Type": "application/json",
            "Cache-Control": "no-store",
          });
          res.end(JSON.stringify({ error: message }));
        };
        try {
          target = relayTarget(req.method ?? "", req.url ?? "/", req.headers);
        } catch (cause) {
          fail(
            400,
            cause instanceof Error
              ? cause.message
              : "Invalid monitor relay request.",
          );
          return;
        }
        if (!target) return next();
        const headers: Record<string, string> = {};
        // Cookies, authorization, and the browser's Origin never travel upstream.
        for (const name of ["content-type", ENCAPSULATED_KEY])
          if (typeof req.headers[name] === "string")
            headers[name] = req.headers[name];
        const upstream = request(
          target,
          { method: req.method, headers },
          (response) => {
            res.statusCode = response.statusCode ?? 502;
            res.setHeader("Cache-Control", "no-store");
            for (const name of [
              "content-type",
              ENCAPSULATED_KEY,
              "ehbp-response-nonce",
              "retry-after",
            ])
              if (response.headers[name])
                res.setHeader(name, response.headers[name]);
            response.on("error", () => res.destroy());
            response.pipe(res);
          },
        );
        upstream.on("error", () => fail(502, "Could not reach the monitor."));
        upstream.setTimeout(45_000, () => upstream.destroy());
        req.on("aborted", () => upstream.destroy());
        req.on("error", () => upstream.destroy());
        res.on("close", () => upstream.destroy());
        let bytes = 0;
        req.on("data", (chunk: Buffer) => {
          bytes += chunk.length;
          if (bytes > MAX_BODY) {
            req.unpipe(upstream);
            fail(413, "Monitor request is too large.");
            upstream.destroy();
          }
        });
        req.pipe(upstream);
      });
    },
  };
}
