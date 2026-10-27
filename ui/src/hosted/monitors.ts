import { ed25519 } from "@noble/curves/ed25519.js";
import { sha256 } from "@noble/hashes/sha2.js";
import { bytesToHex, utf8ToBytes } from "@noble/hashes/utils.js";
import { parse } from "yaml";
import { SecureClient } from "tinfoil";
import { sealedOwnerClient, storedGeneration } from "../owner";
import { monitorKeys, publicKey } from "./keys";
import type { MonitorLink } from "./links";

export type AttestMonitor = (
  target: { url: string; source: string },
  signal: AbortSignal,
) => Promise<typeof fetch>;

// The SDK owns attestation and EHBP key refresh; only sealed owner RPC is allowed.
export const attestMonitor: AttestMonitor = async ({ url, source }, signal) => {
  const relay =
    import.meta.env.DEV && location.origin === "https://local.tinfoil.sh"
      ? location.origin
      : undefined;
  const client = new SecureClient({
    enclaveURL: url,
    baseURL: relay ?? url,
    configRepo: source,
    transport: "ehbp",
    attestationRelayURL: relay,
  });
  await client.ready({ signal });
  signal.throwIfAborted();
  return (input, init) => {
    if (
      String(input) !== `${url}/owner/rpc` ||
      init?.method !== "POST" ||
      typeof init.body !== "string"
    )
      throw new Error(
        "Refusing to send credentials outside the monitor owner API.",
      );
    return client.fetch(relay ? `${relay}/owner/rpc` : input, init);
  };
};

export function monitorConfig(config: string) {
  const doc = parse(config, { schema: "core" });
  if (!Array.isArray(doc?.containers) || !doc.containers.length)
    throw new Error("The monitor link has an invalid measured configuration.");
  const env = new Map<string, string>();
  for (const container of doc.containers) {
    if (!Array.isArray(container?.env))
      throw new Error("Missing measured monitor environment.");
    for (const entry of container.env) {
      const pairs =
        entry && typeof entry === "object" && !Array.isArray(entry)
          ? Object.entries(entry)
          : [];
      if (
        pairs.length !== 1 ||
        typeof pairs[0][1] !== "string" ||
        env.has(pairs[0][0])
      )
        throw new Error("The measured monitor environment is ambiguous.");
      env.set(pairs[0][0], pairs[0][1]);
    }
  }
  const owner = env.get("MONITOR_OWNER_PUBLIC_KEY");
  const bucket = env.get("TINFOIL_STORAGE_BUCKET");
  if (!owner || !bucket)
    throw new Error(
      "The monitor configuration is missing its owner key or storage.",
    );
  const digest = bytesToHex(sha256(utf8ToBytes(config)));
  return {
    owner,
    bucket,
    source: `tinfoil/containers@${digest}@sha256:${digest}`,
  };
}

export async function openMonitor({
  target,
  key,
  signal,
  attest = attestMonitor,
  storage = globalThis.localStorage,
}: {
  target: MonitorLink;
  key: Uint8Array;
  signal: AbortSignal;
  attest?: AttestMonitor;
  storage?: Pick<Storage, "getItem" | "setItem">;
}) {
  signal.throwIfAborted();
  const config = monitorConfig(target.config);
  if (publicKey(key) !== config.owner)
    throw new Error(
      "This key does not own this monitor. Open the link with the key bundle used to create it.",
    );
  const sealed = await attest(
    { url: target.endpoint, source: config.source },
    signal,
  );
  signal.throwIfAborted();
  const secrets = monitorKeys(key, config.bucket);
  const clear = () => secrets.seed.fill(0);
  signal.addEventListener("abort", clear, { once: true });
  try {
    const client = sealedOwnerClient({
      endpoint: target.endpoint,
      monitor: config.bucket,
      sign: async (message) => {
        signal.throwIfAborted();
        return ed25519.sign(message, secrets.seed);
      },
      storageKey: btoa(String.fromCharCode(...secrets.storage)),
      // First open also creates the encrypted store. A remembered generation
      // keeps a returning monitor from treating missing state as a fresh start.
      initialize: storedGeneration(config.bucket, storage) === 0,
      storage,
      assets: "/",
      fetch: (input, init) => {
        signal.throwIfAborted();
        return sealed(input, {
          ...init,
          signal: init?.signal
            ? AbortSignal.any([signal, init.signal])
            : signal,
        });
      },
    });
    secrets.storage.fill(0);
    await client.unlock(undefined, signal);
    const snapshot = await client.read(signal);
    signal.throwIfAborted();
    return { client, snapshot };
  } catch (cause) {
    clear();
    signal.removeEventListener("abort", clear);
    throw cause;
  } finally {
    secrets.storage.fill(0);
  }
}
