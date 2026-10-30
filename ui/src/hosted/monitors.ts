import { randomBytes } from "@noble/hashes/utils.js";
import { SecureClient } from "tinfoil";
import { sealedOwnerClient, type Snapshot } from "../owner";
import { b64u, signOwnerRequest, unb64u, type MKBinding } from "./contract";
import * as keys from "./keys";
import { MONITOR_REPO, type Container, type Scope } from "./session";
import { TEMPLATES } from "./templates";
import { bucketOwnedBy, measuredEnv, monitorDigest } from "./trust";

const SPKI = "https://tinfoil.sh/key/spki/v1";
const ED25519_SPKI = /^302a300506032b6570032100([0-9a-f]{64})$/;
const CREDENTIALS_PATH = "/api/deployments/storage-credentials";
const SSH_ED25519 = new Uint8Array([
  0, 0, 0, 11, 115, 115, 104, 45, 101, 100, 50, 53, 53, 49, 57, 0, 0, 0, 32,
]);

const std64 = (bytes: Uint8Array) => btoa(String.fromCharCode(...bytes));
const hex = (text: string) =>
  Uint8Array.from(text.match(/../g)!, (byte) => parseInt(byte, 16));

// authorized_keys form of a 32-byte Ed25519 public key.
export const sshPublicKey = (raw: Uint8Array) =>
  "ssh-ed25519 " + std64(new Uint8Array([...SSH_ED25519, ...raw]));

export type AttestMonitor = (
  target: { url: string; authorize: (config: Uint8Array) => Promise<void> },
  signal: AbortSignal,
) => Promise<{ fetch: typeof fetch; hostKey: () => string }>;

// The SDK owns attestation and EHBP key refresh; only sealed owner RPC is allowed.
export const attestMonitor: AttestMonitor = async (
  { url, authorize },
  signal,
) => {
  const relay =
    import.meta.env.DEV && location.origin === "https://local.tinfoil.sh"
      ? location.origin
      : undefined;
  const client = new SecureClient({
    enclaveURL: url,
    baseURL: relay ?? url,
    configRepo: "",
    transport: "ehbp",
    attestationRelayURL: relay,
    verification: { configAuthorizer: ({ config }) => authorize(config) },
  });
  await client.ready({ signal });
  signal.throwIfAborted();
  // Read from the SDK's current verification, which follows a newly verified boot.
  const hostKey = () => {
    const spki = client
      .inspect()
      ?.verification.cryptoMaterialData("host-ssh", SPKI)
      ?.match(ED25519_SPKI)?.[1];
    if (!spki) throw new Error("The Monitor did not attest its SSH host key.");
    return sshPublicKey(hex(spki));
  };
  hostKey();
  return {
    hostKey,
    fetch: (input, init) => {
      if (
        String(input) !== `${url}/owner/rpc` ||
        init?.method !== "POST" ||
        typeof init.body !== "string"
      )
        throw new Error(
          "Refusing to send credentials outside the monitor owner API.",
        );
      return client.fetch(relay ? `${relay}/owner/rpc` : input, init);
    },
  };
};

// The saved key of a TMK Monitor, re-resolved from a fresh, successful read of
// the operation's own account; the existing binding must still match it.
async function resolve(scope: Scope, id: string) {
  const rows = await scope.fresh();
  const row = rows.find((r) => r.id === id && r.repo === MONITOR_REPO);
  if (!row) throw new Error("This Monitor is not in the selected account.");
  const detail = (await scope.api(`/api/containers/${id}`)) as Container;
  if (
    detail.id !== id ||
    detail.repo !== MONITOR_REPO ||
    detail.clerk_user_id !== scope.user
  )
    throw new Error("This Monitor changed. Refresh and try again.");
  if (detail.owner_key_mode !== "tmk")
    throw new Error(
      "This Monitor's keys stay with the CLI. Open it with `tinfoil monitor open`.",
    );
  const resource = scope
    .unlocked()
    ?.payload.resources.find(
      (r) =>
        r.kind === "monitor" && r.owner_public_key === detail.owner_public_key,
    );
  if (!resource)
    throw new Error("Your saved keys do not include this Monitor's owner key.");
  const bucket = measuredEnv(detail.config).TINFOIL_STORAGE_BUCKET ?? "";
  if (!bucketOwnedBy(bucket, scope.account, scope.user))
    throw new Error("This Monitor's storage belongs to another account.");
  const binding: MKBinding = {
    account: scope.account,
    container_id: id,
    instance_id: null,
    volume_id: null,
    bucket,
  };
  if (!resource.binding)
    await scope.update(keys.bindResource(resource.key_id, binding));
  else if (JSON.stringify(resource.binding) !== JSON.stringify(binding))
    throw new Error(
      "This Monitor does not match the resource its key was made for.",
    );
  return { row: detail, resource, bucket };
}

export type OpenedMonitor = Awaited<ReturnType<typeof openMonitor>>;

// Verifies the complete Monitor configuration, owner, storage and image
// provenance before its state key leaves this page, then opens saved state at
// the recovered generation and persists any advance.
export async function openMonitor({
  scope,
  id,
  signal,
  onCheckpoint,
  attest = attestMonitor,
}: {
  scope: Scope;
  id: string;
  signal: AbortSignal;
  onCheckpoint: (error?: string) => void;
  attest?: AttestMonitor;
}) {
  signal = AbortSignal.any([signal, scope.signal]);
  const { row, resource, bucket } = await resolve(scope, id);
  const owner = resource.owner_public_key;
  const seed = unb64u(resource.owner_seed, 32);
  const { fetch: sealed, hostKey } = await attest(
    {
      url: `https://${row.domain}`,
      authorize: async (config) => {
        monitorDigest(TEMPLATES.monitor, config, {
          owner,
          bucket,
          credentials: keys.TARGETS.api_origin + CREDENTIALS_PATH,
        });
      },
    },
    signal,
  );
  let checkpoints: Promise<unknown> = Promise.resolve();
  const client = sealedOwnerClient({
    endpoint: `https://${row.domain}`,
    sign: async (call) => {
      signal.throwIfAborted();
      return signOwnerRequest(seed, {
        protocol: "monitor-owner-v2",
        owner,
        resource: bucket,
        ...call,
        session: "",
        nonce: b64u(randomBytes(24)),
      });
    },
    generation: resource.min_generation!,
    storageKey: std64(unb64u(resource.storage_key, 32)),
    remember: (generation) => {
      checkpoints = checkpoints
        .then(() => scope.update(keys.checkpoint(resource.key_id, generation)))
        .then(
          () => onCheckpoint(),
          (cause) =>
            onCheckpoint(
              `The Monitor's newest state was not saved with your keys: ${cause instanceof Error ? cause.message : cause}`,
            ),
        );
    },
    fetch: (input, init) => {
      signal.throwIfAborted();
      return sealed(input, {
        ...init,
        signal: init?.signal ? AbortSignal.any([signal, init.signal]) : signal,
      });
    },
  });
  // A signed status read precedes the state key: saved state that has gone
  // missing below a recorded generation is a rollback, not a new Monitor.
  const health = (await client.call("GET", "/healthz", undefined, signal)) as {
    locked?: unknown;
    state?: unknown;
  };
  if (
    typeof health?.locked !== "boolean" ||
    (health.state !== "present" && health.state !== "absent")
  )
    throw new Error("This Monitor does not support the owner protocol.");
  if (health.state === "absent" && resource.min_generation! > 0)
    throw new Error(
      "This Monitor's saved state is missing. Restore its storage before opening it.",
    );
  await client.unlock(undefined, signal);
  const snapshot: Snapshot = await client.read(signal);
  signal.throwIfAborted();
  checkHostKey(snapshot.view.host_key, hostKey());
  return { row, resource, client, snapshot, hostKey, scope };
}

// The Monitor's own view must name the host key its attestation verified.
export function checkHostKey(reported: string, verified: string) {
  if (reported?.trim() !== verified)
    throw new Error("The Monitor restarted while opening. Open it again.");
}
