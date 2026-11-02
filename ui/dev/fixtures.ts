// Public, throwaway development credentials. Never use these with real resources.
import { ed25519 } from "@noble/curves/ed25519.js";
import { sha256 } from "@noble/hashes/sha2.js";
import { utf8ToBytes } from "@noble/hashes/utils.js";
import { b64u, ownerPublicKey, type MKResource } from "../src/hosted/contract";
import type { Container } from "../src/hosted/session";

export const ORIGIN = "http://127.0.0.1:5175";
export const BACKEND = "http://127.0.0.1:8082";
export const USER = "user_dev";
export const MONITOR_ID = "11111111-1111-4111-8111-111111111111";
export const bytes = (name: string) =>
  sha256(utf8ToBytes(`tinfoil-local-console:${name}`));
export const STORAGE_KEY = btoa(String.fromCharCode(...bytes("storage")));
const publicSSH = (name: string) =>
  "ssh-ed25519 " +
  btoa(
    String.fromCharCode(
      ...new Uint8Array([
        0,
        0,
        0,
        11,
        ...utf8ToBytes("ssh-ed25519"),
        0,
        0,
        0,
        32,
        ...ed25519.getPublicKey(bytes(name)),
      ]),
    ),
  );
export const identities = {
  danielbox1: {
    key: publicSSH("sandbox-1"),
    accounts: { network: { level: "ask" } },
  },
  danielbox2: {
    key: publicSSH("sandbox-2"),
    accounts: { network: { level: "allow" } },
  },
  "dev-laptop": { key: publicSSH("device"), routes: true, accounts: {} },
};
export const resource: MKResource = {
  key_id: b64u(bytes("key-id").slice(0, 16)),
  kind: "monitor",
  attempt_id: b64u(bytes("attempt-id").slice(0, 16)),
  owner_seed: b64u(bytes("owner")),
  owner_public_key: ownerPublicKey(bytes("owner")),
  storage_key: b64u(bytes("storage")),
  monitor_identity_seed: null,
  min_generation: 0,
  binding: {
    account: "personal",
    container_id: MONITOR_ID,
    instance_id: null,
    volume_id: null,
    bucket: "file://local-development",
  },
};
export const rows: Container[] = [
  {
    id: MONITOR_ID,
    name: "monitor",
    repo: "tinfoilsh/confidential-agent-monitor",
    status: "running",
    domain: "127.0.0.1:8082",
    clerk_user_id: USER,
    owner_key_mode: "tmk",
    owner_public_key: resource.owner_public_key,
  },
  ...["danielbox1", "danielbox2"].map((name, i): Container => ({
    id: `22222222-2222-4222-8222-22222222222${i + 1}`,
    name,
    repo: "tinfoilsh/confidential-agent-sandbox",
    status: "running",
    domain: "local-sandbox.invalid",
    clerk_user_id: USER,
    // These are inventory/identity fixtures, not running VMs. CLI-only mode
    // prevents the hosted flow from attempting attestation, enrollment or shells.
    owner_key_mode: "umk",
    owner_public_key: ownerPublicKey(bytes(`sandbox-owner-${i}`)),
    network_policy: { egress: [{ container_id: MONITOR_ID }] },
  })),
];
