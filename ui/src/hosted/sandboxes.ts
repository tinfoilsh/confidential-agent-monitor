import { ed25519 } from "@noble/curves/ed25519.js";
import { Verifier } from "@tinfoilsh/verifier";
import { EnclaveHTTPClient } from "tinfoil";
import type { ShellOpen, ShellOpener } from "../owner";
import { openShell, rpcChannel } from "./channel";
import {
  UUID,
  ownerPublicKey,
  sshPublicKey,
  unb64u,
  type MKBinding,
  type MKResource,
} from "./contract";
import * as keys from "./keys";
import { attestedKey, checkHostKey, type OpenedMonitor } from "./monitors";
import { SANDBOX_REPO, monitorOf, type Container } from "./session";
import { TEMPLATES } from "./templates";
import {
  measuredEnv,
  registryTarget,
  sandboxDigest,
  verifyImage,
  volumeSize,
} from "./trust";

const PROTOCOL = "sandbox-owner-v1";
const ATTESTATION = "/.well-known/tinfoil-attestation";
const VOLUMES = "/api/volumes";
const HOST = /^[a-z0-9.-]+$/;

export type SandboxStatus = {
  protocol: typeof PROTOCOL;
  instance_id: string;
  volume: "unlocked" | "locked";
  monitor_identity: string | null;
  monitor_host_key: string | null;
};
type RelayReply = { status: number; body: string };

// Sandbox identity that is not on its Monitor; only an explicit restore re-adds it.
export class RestoreRequired extends Error {}

const routed = (monitor: OpenedMonitor, row: Container) =>
  row.repo === SANDBOX_REPO &&
  monitorOf(row) === monitor.row.id &&
  row.owner_key_mode === "tmk";
const agentKey = (resource: MKResource) =>
  sshPublicKey(
    ed25519.getPublicKey(unb64u(resource.monitor_identity_seed, 32)),
  );

// One sandbox reached through its Monitor's relay. Its sessions handshake with
// the attested owner-session key and are signed by the sandbox owner key, so
// Monitor carries only ciphertext.
export async function sandboxClient(
  monitor: OpenedMonitor,
  row: Container,
  resource: MKResource,
  binding: MKBinding,
  size: string,
  signal: AbortSignal,
) {
  const seed = unb64u(resource.owner_seed, 32);
  const owner = ownerPublicKey(seed);
  const instance_id = binding.instance_id!;
  if (!HOST.test(row.domain)) throw new Error("This sandbox has no address.");
  const config = new TextEncoder().encode(row.config ?? "");
  const digest = sandboxDigest(TEMPLATES.sandbox, config, {
    owner,
    instance_id,
    size,
  });
  const target = registryTarget(row, config, monitor.registry);
  await verifyImage("sandbox", digest, { signal });
  signal.throwIfAborted();
  const secure = await EnclaveHTTPClient.create(row.domain, target.reference, {
    verifier: await Verifier.create({ configRegistryIDs: [target.registry] }),
    attestationFetch: async (input, init) => {
      const url = new URL(String(input));
      const nonce = url.searchParams.get("nonce") ?? "";
      if (url.pathname !== ATTESTATION || !/^[0-9a-f]{64}$/.test(nonce))
        throw new Error("Refused sandbox attestation request.");
      const reply = (await monitor.client.call(
        "POST",
        "/sandboxes/relay",
        { instance_id, nonce },
        init?.signal ?? undefined,
      )) as RelayReply;
      return new Response(new Uint8Array(unb64u(reply.body)), {
        status: reply.status,
      });
    },
    signal,
  });
  const connect = async (hello: object, signal?: AbortSignal) => {
    await secure.ensureVerified({ signal });
    const serverKey = attestedKey(secure, "owner-session");
    return monitor.relay(
      instance_id,
      { serverKey, prologue: PROTOCOL, seed, hello },
      signal,
    );
  };
  const call = rpcChannel(
    () => connect({ open: "rpc" }),
    async () => (await monitor.refresh(), secure.reverify()),
  );

  return {
    status: async (signal?: AbortSignal) => {
      const status = (await call(
        "GET",
        "/status",
        undefined,
        0,
        signal,
      )) as SandboxStatus;
      if (status?.protocol !== PROTOCOL || status.instance_id !== instance_id)
        throw new Error("The sandbox answered for a different instance.");
      return status;
    },
    enroll: (
      monitor_host_key: string,
      allow_initialize: boolean,
      signal?: AbortSignal,
    ) =>
      call(
        "POST",
        "/enroll",
        {
          monitor_identity_seed: resource.monitor_identity_seed,
          monitor_host_key,
          disk_key: resource.storage_key,
          allow_initialize,
        },
        0,
        signal,
      ) as Promise<SandboxStatus>,
    shell: (size: ShellOpen, signal: AbortSignal) =>
      connect({ open: "shell", ...size }, signal),
  };
}
export type SandboxClient = Awaited<ReturnType<typeof sandboxClient>>;

// A TMK sandbox routed through this Monitor, re-resolved from a fresh,
// successful read of the operation's account. Its saved binding must name the
// same instance and workspace volume before any sandbox secret is sent.
async function resolve(
  monitor: OpenedMonitor,
  id: string,
  bind: boolean,
  readVolumes = () => monitor.scope.api(VOLUMES),
) {
  const { scope } = monitor;
  const detail = (await scope.api(`/api/containers/${id}`)) as Container;
  if (
    detail.id !== id ||
    detail.repo !== SANDBOX_REPO ||
    detail.clerk_user_id !== scope.user ||
    monitorOf(detail) !== monitor.row.id
  )
    throw new Error(
      "This sandbox changed or is not routed through this Monitor.",
    );
  if (detail.owner_key_mode !== "tmk")
    throw new Error(
      "This sandbox's keys stay with the CLI. Connect with `tinfoil attest-ssh`.",
    );
  const resource = scope
    .unlocked()
    ?.payload.resources.find(
      (r) =>
        r.kind === "sandbox" && r.owner_public_key === detail.owner_public_key,
    );
  if (!resource)
    throw new Error("Your saved keys do not include this sandbox's owner key.");
  const instance_id = measuredEnv(detail.config).SANDBOX_INSTANCE_ID ?? "";
  const volume_id = detail.volumes?.workspace ?? "";
  const volumes = (await readVolumes()) as {
    volumes?: {
      id: string;
      container_id: string | null;
      slot: string | null;
      size_bytes: number;
    }[];
  };
  const volume = volumes.volumes?.find(
    (v) =>
      v.id === volume_id && v.container_id === id && v.slot === "workspace",
  );
  if (
    !UUID.test(instance_id) ||
    !volume ||
    !Number.isSafeInteger(volume.size_bytes) ||
    volume.size_bytes <= 0
  )
    throw new Error(
      "This sandbox's instance or workspace could not be confirmed.",
    );
  const binding: MKBinding = {
    account: scope.account,
    container_id: id,
    instance_id,
    volume_id,
    bucket: null,
  };
  if (resource.binding) {
    if (JSON.stringify(resource.binding) !== JSON.stringify(binding))
      throw new Error(
        "This sandbox's instance or workspace no longer matches its saved key.",
      );
  } else if (bind)
    await scope.update(keys.bindResource(resource.key_id, binding));
  else return;
  return {
    row: detail,
    resource,
    binding,
    size: volumeSize(volume.size_bytes),
  };
}

// What connecting needs. A never-enrolled sandbox is added, a removed one
// returns only by explicit restore, and a running agent pinned to an older
// Monitor boot is re-linked.
export function connectPlan(
  status: SandboxStatus,
  agent: string,
  hostKey: string,
  known: boolean,
  restore: boolean,
): { monitor: boolean; sandbox: boolean } {
  if (status.monitor_identity && status.monitor_identity !== agent)
    throw new Error("This sandbox holds a different Monitor identity.");
  if (!known && !restore && status.monitor_identity)
    throw new RestoreRequired(
      "This sandbox's identity is not on its Monitor. Restore it to reconnect.",
    );
  return {
    monitor: !known,
    sandbox:
      !status.monitor_identity ||
      status.volume !== "unlocked" ||
      status.monitor_host_key !== hostKey,
  };
}

export async function connectSandbox({
  monitor,
  id,
  restore = false,
  signal,
}: {
  monitor: OpenedMonitor;
  id: string;
  restore?: boolean;
  signal?: AbortSignal;
}): Promise<SandboxClient> {
  signal = signal
    ? AbortSignal.any([signal, monitor.scope.signal])
    : monitor.scope.signal;
  const { row, resource, binding, size } = (await resolve(monitor, id, true))!;
  const sandbox = await sandboxClient(
    monitor,
    row,
    resource,
    binding,
    size,
    signal,
  );
  const status = await sandbox.status(signal);
  const agent = agentKey(resource);
  const hostKey = monitor.hostKey();
  const { view } = await monitor.client.read(signal);
  checkHostKey(view.host_key, hostKey);
  const known = Object.values(view.config.identities ?? {}).some(
    (identity) => identity.key === agent,
  );
  const steps = connectPlan(status, agent, hostKey, known, restore);
  if (steps.monitor)
    await monitor.client.enroll(
      { [row.name]: { key: agent, routes: false, restore } },
      signal,
    );
  // The volume worker formats only a blank workspace and otherwise unlocks it.
  if (steps.sandbox) await sandbox.enroll(hostKey, true, signal);
  return sandbox;
}

// After a Monitor restart, re-links each still-authorized, bound sandbox to the
// newly verified host key; removed identities and CLI-held sandboxes are left alone.
export async function relinkSandboxes(monitor: OpenedMonitor) {
  const failures: string[] = [];
  const hostKey = monitor.hostKey();
  checkHostKey(monitor.snapshot.view.host_key, hostKey);
  const identities = Object.values(
    monitor.snapshot.view.config.identities ?? {},
  );
  const rows = (await monitor.scope.fresh()).filter(
    (row) => routed(monitor, row) && row.status === "running",
  );
  let volumes: Promise<unknown> | undefined;
  const readVolumes = () => (volumes ??= monitor.scope.api(VOLUMES));
  await Promise.all(
    rows.map(async (row) => {
      try {
        const resolved = await resolve(monitor, row.id, false, readVolumes);
        if (!resolved) return;
        const { resource, binding } = resolved;
        const agent = agentKey(resource);
        if (!identities.some((identity) => identity.key === agent)) return;
        const sandbox = await sandboxClient(
          monitor,
          resolved.row,
          resource,
          binding,
          resolved.size,
          monitor.scope.signal,
        );
        const status = await sandbox.status(monitor.scope.signal);
        if (
          status.monitor_identity === agent &&
          status.monitor_host_key !== hostKey
        )
          await sandbox.enroll(hostKey, false, monitor.scope.signal);
      } catch (cause) {
        failures.push(
          `${row.name}: ${cause instanceof Error ? cause.message : cause}`,
        );
      }
    }),
  );
  return failures;
}

export function sandboxCandidates(monitor: OpenedMonitor, rows: Container[]) {
  const resources = monitor.scope.unlocked()?.payload.resources ?? [];
  return rows.flatMap((row) => {
    const resource = resources.find(
      (r) =>
        r.kind === "sandbox" && r.owner_public_key === row.owner_public_key,
    );
    return routed(monitor, row) &&
      row.status === "running" &&
      resource?.monitor_identity_seed
      ? [{ name: row.name, key: agentKey(resource) }]
      : [];
  });
}

// Accepting adds the sandbox to the Monitor, or with restore re-adds a removed
// one, then enrolls and unlocks it.
export async function acceptSandbox(
  monitor: OpenedMonitor,
  rows: Container[],
  name: string,
  restore: boolean,
) {
  const row = rows.find((r) => r.name === name && r.repo === SANDBOX_REPO);
  if (!row) throw new Error(`${name} is no longer in this account.`);
  await connectSandbox({ monitor, id: row.id, restore });
}

export function shellOpener(
  monitor: OpenedMonitor,
  rows: Container[],
  name: string,
  restore = false,
): ShellOpener | undefined {
  const row = rows.find((r) => r.name === name && r.repo === SANDBOX_REPO);
  if (!row || !routed(monitor, row)) return undefined;
  return async (size, handlers, signal) => {
    const sandbox = await connectSandbox({
      monitor,
      id: row.id,
      restore,
      signal,
    });
    return openShell(await sandbox.shell(size, signal), handlers, signal);
  };
}
