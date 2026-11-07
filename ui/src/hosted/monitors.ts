import { Verifier } from "@tinfoilsh/verifier";
import { EnclaveHTTPClient } from "tinfoil";
import { ownerApi, type OwnerApi, type Request, type Snapshot } from "../owner";
import { openChannel, rpcChannel, type Session } from "./channel";
import { sshPublicKey, toBase64, unb64u, type MKBinding } from "./contract";
import * as keys from "./keys";
import { MONITOR_REPO, type Container, type Scope } from "./session";
import { TEMPLATES } from "./templates";
import {
  bucketOwnedBy,
  measuredEnv,
  monitorDigest,
  registryTarget,
  verifyImage,
  type RegistryTarget,
} from "./trust";

const SPKI = "https://tinfoil.sh/key/spki/v1";
const PROTOCOL = "monitor-owner-v1";
const ED25519_SPKI = /^302a300506032b6570032100([0-9a-f]{64})$/;
const X25519_SPKI = /^302a300506032b656e032100([0-9a-f]{64})$/;
const CREDENTIALS_PATH = "/api/deployments/storage-credentials";

const hex = (text: string) =>
  Uint8Array.from(text.match(/../g)!, (byte) => parseInt(byte, 16));

// An attested key's raw bytes, read from the SDK's current verification, which
// follows a newly verified boot.
export function attestedKey(
  client: EnclaveHTTPClient,
  id: string,
  spki = X25519_SPKI,
) {
  const key = client.current?.cryptoMaterialData(id, SPKI)?.match(spki)?.[1];
  if (!key) throw new Error(`The enclave did not attest its ${id} key.`);
  return hex(key);
}

// The SDK owns attestation and its refresh; owner sessions use the attested owner-session key.
export async function attestMonitor(
  { url, reference, registry }: RegistryTarget,
  signal: AbortSignal,
) {
  const relay =
    import.meta.env.DEV && location.origin === "https://local.tinfoil.sh"
      ? location.origin
      : undefined;
  const client = await EnclaveHTTPClient.create(new URL(url).host, reference, {
    verifier: await Verifier.create({ configRegistryIDs: [registry] }),
    attestationFetch: relay
      ? (input, init) => {
          const doc = new URL(String(input));
          doc.searchParams.set("enclave", doc.host);
          return fetch(relay + doc.pathname + doc.search, init);
        }
      : undefined,
    signal,
  });
  signal.throwIfAborted();
  const hostKey = () =>
    sshPublicKey(attestedKey(client, "host-ssh", ED25519_SPKI));
  const sessionKey = async (at = signal) => {
    await client.ensureVerified({ signal: AbortSignal.any([signal, at]) });
    return attestedKey(client, "owner-session");
  };
  hostKey();
  await sessionKey();
  return { hostKey, sessionKey, refresh: () => client.reverify({ signal }) };
}

// The saved key of a TMK Monitor, re-resolved from a fresh, successful read of
// the operation's own account; the existing binding must still match it.
async function resolve(scope: Scope, id: string) {
  const detail = (await scope.api(`/api/containers/${id}`).catch((cause) => {
    throw cause instanceof keys.ApiError && cause.status === 404
      ? new Error("This Monitor is not in the selected account.")
      : cause;
  })) as Container;
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
}: {
  scope: Scope;
  id: string;
  signal: AbortSignal;
  onCheckpoint: (error?: string) => void;
}) {
  signal = AbortSignal.any([signal, scope.signal]);
  const { row, resource, bucket } = await resolve(scope, id);
  const owner = resource.owner_public_key;
  const seed = unb64u(resource.owner_seed, 32);
  // The attestation binds these checked bytes through the pinned config digest.
  const config = new TextEncoder().encode(row.config ?? "");
  const digest = monitorDigest(TEMPLATES.monitor, config, {
    owner,
    bucket,
    credentials: keys.TARGETS.api_origin + CREDENTIALS_PATH,
  });
  // GitHub hides attestations of the internal monitor repo from anonymous requests.
  // await verifyImage("monitor", digest, { signal });
  const account = (await scope.api("/api/config-registry/v2/account")) as {
    scope: string;
  };
  signal.throwIfAborted();
  const target = registryTarget(row, config, account.scope);
  const { hostKey, sessionKey, refresh } = await attestMonitor(target, signal);
  const url = `wss://${row.domain}/owner/ws`;
  const session = async (hello: object, at = signal): Promise<Session> => ({
    serverKey: await sessionKey(at),
    prologue: PROTOCOL,
    seed,
    hello,
  });
  // A sandbox session runs inside a relay socket, so Monitor carries only its ciphertext.
  const relay = async (instance_id: string, inner: Session, at?: AbortSignal) =>
    openChannel(
      url,
      [await session({ open: "relay", instance_id }, at), inner],
      AbortSignal.any(at ? [signal, at] : [signal]),
    );
  let floor = resource.min_generation!;
  const call = rpcChannel(
    async () => openChannel(url, [await session({ open: "rpc" })], signal),
    refresh,
  );
  const storageKey = toBase64(unb64u(resource.storage_key, 32));
  // Each call carries the newest generation seen.
  const request: Request = (method, path, body = null, at) =>
    call(
      method,
      path,
      path.split("?")[0] === "/unlock"
        ? { ...(body as object), storage_key: storageKey }
        : body,
      floor,
      at,
    );
  let checkpoints: Promise<unknown> = Promise.resolve();
  const client: OwnerApi & { call: Request } = {
    ...ownerApi(request, floor, (generation) => {
      floor = generation;
      checkpoints = checkpoints
        .then(() => scope.update(keys.checkpoint(resource.key_id, generation)))
        .then(
          () => onCheckpoint(),
          (cause) =>
            onCheckpoint(
              `The Monitor's newest state was not saved with your keys: ${cause instanceof Error ? cause.message : cause}`,
            ),
        );
    }),
    // Hosted callers also reach owner routes outside the shared management API.
    call: request,
  };
  // The Monitor refuses saved state that is missing or older than the recovered generation.
  await client.unlock(undefined, signal);
  const snapshot: Snapshot = await client.read(signal);
  signal.throwIfAborted();
  checkHostKey(snapshot.view.host_key, hostKey());
  return {
    row,
    resource,
    client,
    snapshot,
    hostKey,
    relay,
    refresh,
    scope,
    registry: target.registry,
  };
}

// The Monitor's own view must name the host key its attestation verified.
export function checkHostKey(reported: string, verified: string) {
  if (reported?.trim() !== verified)
    throw new Error("The Monitor restarted while opening. Open it again.");
}
