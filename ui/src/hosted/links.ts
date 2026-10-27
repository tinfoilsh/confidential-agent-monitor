import { keyBundle } from "./keys";

export type MonitorLink = {
  name: string;
  endpoint: string;
  // Exact config returned by the container API, pinned by its SHA-256 digest.
  config: string;
  // The public reference or passkey-wrapped bundle returned by /start.
  bundle: string;
};

const fields = ["endpoint", "config", "bundle"] as const;
const validate = (target: MonitorLink): MonitorLink => {
  if (
    !target.name ||
    target.name.length > 128 ||
    /[/\\\x00-\x1f]/.test(target.name)
  )
    throw new Error("Invalid monitor name.");
  const endpoint = new URL(target.endpoint);
  if (
    endpoint.protocol !== "https:" ||
    endpoint.username ||
    endpoint.password ||
    endpoint.pathname !== "/" ||
    endpoint.search ||
    endpoint.hash
  )
    throw new Error("The monitor endpoint must be an HTTPS origin.");
  if (!target.config || target.config.length > 128_000)
    throw new Error("The monitor link is missing its measured configuration.");
  if (!target.bundle || target.bundle.length > 16_000)
    throw new Error("The monitor link is missing its key bundle.");
  keyBundle(target.bundle);
  return { ...target, endpoint: endpoint.origin };
};

// Dashboard callers pass the container's name, HTTPS domain and exact config,
// together with the bundle from onboarding. No private key or login token belongs here.
export function monitorURL(
  target: MonitorLink,
  consoleURL = "https://terminal.tinfoil.sh",
): string {
  target = validate(target);
  const url = new URL(consoleURL);
  url.pathname = `/monitor/${encodeURIComponent(target.name)}`;
  url.search = "";
  url.hash = new URLSearchParams(
    Object.fromEntries(fields.map((key) => [key, target[key]])),
  ).toString();
  return url.href;
}

export const hasMonitorHandoff = (hash: string) => {
  const params = new URLSearchParams(hash.replace(/^#/, ""));
  return fields.some((key) => params.has(key));
};

// Keep only public connection metadata in this tab, leaving the hash available
// for App's navigation and preserving reloads and OAuth returns.
export function readMonitorLink(
  url: URL,
  storage: Pick<Storage, "getItem" | "setItem">,
): MonitorLink {
  const match = url.pathname.match(/^\/monitor\/([^/]+)\/?$/);
  if (!match)
    throw new Error("Open a monitor link from your Tinfoil dashboard.");
  const name = decodeURIComponent(match[1]);
  const key = `tinfoil-console/monitor/${encodeURIComponent(name)}`;
  const params = new URLSearchParams(url.hash.slice(1));
  if (hasMonitorHandoff(url.hash)) {
    if (
      fields.some((key) => params.getAll(key).length !== 1) ||
      params.size !== fields.length
    )
      throw new Error(
        "This monitor link is incomplete. Open it again from your dashboard.",
      );
    const target = validate({
      name,
      endpoint: params.get("endpoint")!,
      config: params.get("config")!,
      bundle: params.get("bundle")!,
    });
    storage.setItem(key, JSON.stringify(target));
    return target;
  }
  const saved = storage.getItem(key);
  if (!saved)
    throw new Error(
      "This monitor link is missing its connection details. Open it again from your dashboard.",
    );
  const target = validate(JSON.parse(saved));
  if (target.name !== name)
    throw new Error("The saved connection belongs to a different monitor.");
  return target;
}
