import { ed25519 } from "@noble/curves/ed25519.js";
import { randomBytes } from "@noble/hashes/utils.js";
import { SecureClient } from "tinfoil";
import {
  OwnerError,
  openShell,
  refusedTime,
  type ShellOpener,
  type ShellReply,
  type ShellRequest,
} from "../owner";
import {
  b64u,
  ownerPublicKey,
  signOwnerRequest,
  unb64u,
  type MKBinding,
} from "./contract";
import * as keys from "./keys";
import { checkHostKey, sshPublicKey, type OpenedMonitor } from "./monitors";
import { SANDBOX_REPO, monitorOf, type Container } from "./session";
import { TEMPLATES } from "./templates";
import { measuredEnv, sandboxDigest, volumeSize } from "./trust";

const OWNER_DEADLINE_MS = 60_000;
const OWNER_ATTEMPTS = 3;
const ATTESTATION = "/.well-known/tinfoil-attestation";
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;
const HOST = /^[a-z0-9.-]+$/;

export type SandboxStatus = {
  protocol: "sandbox-owner-v1";
  instance_id: string;
  volume: "unlocked" | "locked";
  agent_public_key: string | null;
  monitor_host_key: string | null;
};
type RelayReply = {
  status: number;
  headers: Record<string, string>;
  body: string;
};

// Sandbox identity that is not on its Monitor; only an explicit restore re-adds it.
export class RestoreRequired extends Error {}

const response = (reply: RelayReply) =>
  new Response(
    reply.status === 204 ? null : new Uint8Array(unb64u(reply.body)),
    {
      status: reply.status,
      headers: reply.headers,
    },
  );

// One sandbox reached through its Monitor's relay. Requests are signed by the
// sandbox owner key and sealed to the attested sandbox-ehbp key, so Monitor
// carries only ciphertext.
export function sandboxClient(
  monitor: OpenedMonitor,
  row: Container,
  owner_seed: string,
  binding: MKBinding,
  size: string,
) {
  const seed = unb64u(owner_seed, 32);
  const owner = ownerPublicKey(seed);
  const instance_id = binding.instance_id!;
  if (!HOST.test(row.domain)) throw new Error("This sandbox has no address.");
  const host = `https://${row.domain}`;
  const relay = async (body: unknown, signal?: AbortSignal | null) =>
    response(
      (await monitor.client.call(
        "POST",
        "/sandboxes/relay",
        body,
        signal ?? undefined,
      )) as RelayReply,
    );
  const secure = new SecureClient({
    enclaveURL: host,
    baseURL: host,
    configRepo: "",
    verification: {
      configAuthorizer: async ({ config }) => {
        sandboxDigest(TEMPLATES.sandbox, config, {
          owner,
          instance_id,
          size,
        });
      },
    },
    acquisition: {
      fetch: async (input, init) => {
        const url = new URL(String(input));
        const nonce = url.searchParams.get("nonce") ?? "";
        if (url.pathname !== ATTESTATION || !/^[0-9a-f]{64}$/.test(nonce))
          throw new Error("Refused sandbox attestation request.");
        return relay(
          {
            instance_id,
            target: "attestation",
            nonce,
            headers: null,
            body: "",
          },
          init?.signal,
        );
      },
    },
    ehbpKeyID: "sandbox-ehbp",
    ehbpRelay: async (sealed) =>
      relay(
        {
          instance_id,
          target: "owner",
          nonce: null,
          headers: {
            "Ehbp-Encapsulated-Key": sealed.headers.get(
              "Ehbp-Encapsulated-Key",
            ),
            "Content-Type": sealed.headers.get("Content-Type"),
          },
          body: b64u(new Uint8Array(await sealed.arrayBuffer())),
        },
        sealed.signal,
      ),
  });

  // The sandbox's clock minus ours, learned when it refuses a request's time.
  let skew = 0;
  // A lost reply is retried at the same time with a fresh nonce; every sandbox
  // effect is safe to repeat.
  async function call(
    method: "GET" | "POST",
    path: string,
    body?: unknown,
    session = "",
    signal?: AbortSignal,
  ): Promise<unknown> {
    const started = Date.now();
    const operation = {
      operation: b64u(randomBytes(16)),
      issued_at: Date.now() + skew,
      body:
        method === "GET"
          ? ""
          : b64u(new TextEncoder().encode(JSON.stringify(body))),
    };
    for (let attempt = 1; ; attempt++) {
      const envelope = signOwnerRequest(seed, {
        protocol: "sandbox-owner-v1",
        owner,
        resource: instance_id,
        method,
        path,
        ...operation,
        session,
        generation: 0,
        nonce: b64u(randomBytes(24)),
      });
      try {
        const reply = await secure.fetch(`${host}/owner/rpc`, {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: envelope,
          signal,
        });
        const text = await reply.text();
        const now = refusedTime(reply.status, text);
        if (now !== undefined && attempt < OWNER_ATTEMPTS) {
          skew = now - Date.now();
          operation.issued_at = now;
          continue;
        }
        if (!reply.ok)
          throw new OwnerError(
            text.trim() || `Sandbox request failed (${reply.status})`,
            reply.status,
          );
        return text ? JSON.parse(text) : null;
      } catch (cause) {
        // A 4xx answer is definitive; a lost hop or 5xx may follow the effect.
        if (
          (cause instanceof OwnerError && cause.status < 500) ||
          signal?.aborted ||
          attempt >= OWNER_ATTEMPTS ||
          Date.now() >= started + OWNER_DEADLINE_MS
        )
          throw cause;
      }
    }
  }

  return {
    status: async (signal?: AbortSignal) => {
      const status = (await call(
        "GET",
        "/status",
        undefined,
        "",
        signal,
      )) as SandboxStatus;
      if (
        status?.protocol !== "sandbox-owner-v1" ||
        status.instance_id !== instance_id
      )
        throw new Error("The sandbox answered for a different instance.");
      return status;
    },
    enroll: (body: unknown, signal?: AbortSignal) =>
      call("POST", "/enroll", body, "", signal) as Promise<SandboxStatus>,
    shell: (request: ShellRequest, signal?: AbortSignal) =>
      call(
        "POST",
        "/shell",
        request,
        request.action === "open" ? "" : request.id,
        signal,
      ) as Promise<ShellReply>,
  };
}
export type SandboxClient = ReturnType<typeof sandboxClient>;

// A TMK sandbox routed through this Monitor, re-resolved from a fresh,
// successful read of the operation's account. Its saved binding must name the
// same instance and workspace volume before any sandbox secret is sent.
async function resolve(monitor: OpenedMonitor, id: string, bind: boolean) {
  const { scope } = monitor;
  const rows = await scope.fresh();
  if (!rows.some((r) => r.id === id && r.repo === SANDBOX_REPO))
    throw new Error("This sandbox is not in the selected account.");
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
  const volumes = (await scope.api("/api/volumes")) as {
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

// What connecting needs. A sandbox not on its Monitor is added only by the
// owner's explicit accept or restore; a running agent pinned to an older Monitor
// boot is re-linked.
export function connectPlan(
  status: SandboxStatus,
  agent: string,
  hostKey: string,
  known: boolean,
  restore: boolean,
): { monitor: boolean; sandbox: boolean } {
  if (status.agent_public_key && status.agent_public_key !== agent)
    throw new Error("This sandbox holds a different agent identity.");
  if (!known && !restore)
    throw new RestoreRequired(
      "This sandbox's identity is not on its Monitor. Restore it to reconnect.",
    );
  return {
    monitor: !known,
    sandbox:
      !status.agent_public_key ||
      status.volume !== "unlocked" ||
      status.monitor_host_key !== hostKey,
  };
}

// Opens a sandbox for its owner after reconciling its actual state.
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
  const sandbox = sandboxClient(
    monitor,
    row,
    resource.owner_seed,
    binding,
    size,
  );
  const status = await sandbox.status(signal);
  const agent = sshPublicKey(
    ed25519.getPublicKey(unb64u(resource.agent_seed, 32)),
  );
  const hostKey = monitor.hostKey();
  const { view } = await monitor.client.read(signal);
  checkHostKey(view.host_key, hostKey);
  const known = Object.values(view.config.identities ?? {}).some(
    (identity) => identity.key === agent,
  );
  const steps = connectPlan(status, agent, hostKey, known, restore);
  if (steps.monitor)
    await monitor.client.call(
      "POST",
      "/enroll",
      { [row.name]: { key: agent, routes: false, restore } },
      signal,
    );
  if (steps.sandbox)
    await sandbox.enroll(
      {
        agent_seed: resource.agent_seed,
        monitor_host_key: hostKey,
        disk_key: resource.storage_key,
        // The volume worker formats only a blank workspace and otherwise unlocks it.
        allow_initialize: true,
      },
      signal,
    );
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
    (row) =>
      row.repo === SANDBOX_REPO &&
      monitorOf(row) === monitor.row.id &&
      row.owner_key_mode === "tmk" &&
      row.status === "running",
  );
  await Promise.all(
    rows.map(async (row) => {
      try {
        const resolved = await resolve(monitor, row.id, false);
        if (!resolved) return;
        const { resource, binding } = resolved;
        const agent = sshPublicKey(
          ed25519.getPublicKey(unb64u(resource.agent_seed, 32)),
        );
        if (!identities.some((identity) => identity.key === agent)) return;
        const sandbox = sandboxClient(
          monitor,
          resolved.row,
          resource.owner_seed,
          binding,
          resolved.size,
        );
        const status = await sandbox.status(monitor.scope.signal);
        if (
          status.agent_public_key === agent &&
          status.monitor_host_key !== hostKey
        )
          await sandbox.enroll(
            {
              agent_seed: resource.agent_seed,
              monitor_host_key: hostKey,
              disk_key: resource.storage_key,
              allow_initialize: false,
            },
            monitor.scope.signal,
          );
      } catch (cause) {
        failures.push(
          `${row.name}: ${cause instanceof Error ? cause.message : cause}`,
        );
      }
    }),
  );
  return failures;
}

// Sandboxes routed through this Monitor whose keys this terminal holds, with
// the agent key each would enroll.
export function sandboxCandidates(monitor: OpenedMonitor, rows: Container[]) {
  const resources = monitor.scope.unlocked()?.payload.resources ?? [];
  return rows.flatMap((row) => {
    const resource = resources.find(
      (r) =>
        r.kind === "sandbox" && r.owner_public_key === row.owner_public_key,
    );
    return row.repo === SANDBOX_REPO &&
      monitorOf(row) === monitor.row.id &&
      row.owner_key_mode === "tmk" &&
      row.status === "running" &&
      resource?.agent_seed
      ? [
          {
            name: row.name,
            key: sshPublicKey(
              ed25519.getPublicKey(unb64u(resource.agent_seed, 32)),
            ),
          },
        ]
      : [];
  });
}

// Accepting is the owner's explicit first open: it adds the sandbox to the
// Monitor, or restores a removed one, then enrolls and unlocks it.
export async function acceptSandbox(
  monitor: OpenedMonitor,
  rows: Container[],
  name: string,
) {
  const row = rows.find((r) => r.name === name && r.repo === SANDBOX_REPO);
  if (!row) throw new Error(`${name} is no longer in this account.`);
  await connectSandbox({ monitor, id: row.id, restore: true });
}

// The hosted shell capability: opening a shell first connects the sandbox.
export function shellOpener(
  monitor: OpenedMonitor,
  rows: Container[],
  name: string,
  restore = false,
): ShellOpener | undefined {
  const row = rows.find((r) => r.name === name && r.repo === SANDBOX_REPO);
  if (!row || monitorOf(row) !== monitor.row.id || row.owner_key_mode !== "tmk")
    return undefined;
  return async (size, handlers, signal) => {
    const sandbox = await connectSandbox({
      monitor,
      id: row.id,
      restore,
      signal,
    });
    return openShell(sandbox.shell, size, handlers, signal);
  };
}
