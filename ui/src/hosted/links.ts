import { validateOwnerKey, type OwnerKey } from "./keys";

export type MonitorLink = {
  name: string;
  endpoint: string;
  // Exact config returned by the container API, pinned by its SHA-256 digest.
  config: string;
  // The owner key record as stored by the dashboard: JSON of OwnerKey. Only
  // the public key is readable; the rest needs the owner's passkey or data key.
  key: string;
};

const fields = ["endpoint", "config", "key"] as const;
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
  if (!target.key || target.key.length > 64_000)
    throw new Error("The monitor link is missing its owner key.");
  ownerKey(target);
  return { ...target, endpoint: endpoint.origin };
};

export const ownerKey = (target: Pick<MonitorLink, "key">): OwnerKey =>
  validateOwnerKey(JSON.parse(target.key));

// Dashboard callers pass the container's name, HTTPS domain and exact config,
// together with the owner key record. No unencrypted private key or login
// token belongs here.
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

const LINK_PREFIX = "tinfoil-console/monitor/";
const OWNER_PREFIX = "tinfoil-console/owner-key/";

// Monitors whose connection records this browser remembers.
export const savedMonitors = (storage: Storage) =>
  Object.keys(storage)
    .filter((key) => key.startsWith(LINK_PREFIX))
    .map((key) => decodeURIComponent(key.slice(LINK_PREFIX.length)))
    .sort();

// Remember the connection record in this browser, with each owner key record
// kept once for all its Monitors, leaving the hash available for App's
// navigation and preserving reloads and OAuth returns. The console lists
// remembered Monitors, so reopening one needs no dashboard.
export function readMonitorLink(
  url: URL,
  storage: Pick<Storage, "getItem" | "setItem">,
): MonitorLink {
  const match = url.pathname.match(/^\/monitor\/([^/]+)\/?$/);
  if (!match)
    throw new Error("Open a monitor link from your Tinfoil dashboard.");
  const name = decodeURIComponent(match[1]);
  const key = LINK_PREFIX + encodeURIComponent(name);
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
      key: params.get("key")!,
    });
    const { key: record, ...link } = target;
    const owner = ownerKey(target).public_key;
    storage.setItem(OWNER_PREFIX + owner, record);
    storage.setItem(key, JSON.stringify({ ...link, owner }));
    return target;
  }
  const saved = storage.getItem(key);
  if (!saved)
    throw new Error(
      "This monitor link is missing its connection details. Open it again from your dashboard.",
    );
  const { owner, ...link } = JSON.parse(saved);
  const target = validate({
    ...link,
    key: storage.getItem(OWNER_PREFIX + owner),
  });
  if (target.name !== name)
    throw new Error("The saved connection belongs to a different monitor.");
  return target;
}
