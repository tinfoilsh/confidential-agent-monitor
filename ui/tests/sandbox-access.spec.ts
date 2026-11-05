import { expect, test } from "bun:test";
import { sandboxCandidates } from "../src/terminal/sandboxes";
import type { OpenedMonitor } from "../src/terminal/connection";
import type { Container } from "../src/terminal/session";

const row = {
  id: "sandbox",
  name: "my-sandbox",
  repo: "tinfoilsh/confidential-agent-sandbox",
  status: "running",
  owner_key_mode: "tmk",
  owner_public_key: "sandbox-owner",
  network_policy: { egress: [{ container_id: "my-monitor" }] },
} as Container;
const resource = {
  kind: "sandbox",
  owner_public_key: "sandbox-owner",
  monitor_identity_seed: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
};
const monitor = (resources: unknown[]) =>
  ({
    row: { id: "my-monitor" },
    scope: { unlocked: () => ({ payload: { resources } }) },
    // A Monitor-supplied identity list is not the source of browser shell authority.
    snapshot: {
      view: { config: { identities: { claimed: { key: "untrusted-claim" } } } },
    },
  }) as unknown as OpenedMonitor;

test("browser shell candidates come from inventory and locally unlocked keys, not Monitor claims", () => {
  const candidates = sandboxCandidates(monitor([resource]), [row]);
  expect(candidates.map((candidate) => candidate.name)).toEqual(["my-sandbox"]);
  expect(candidates[0].key.startsWith("ssh-ed25519 ")).toBe(true);
  expect(sandboxCandidates(monitor([]), [row])).toEqual([]);
});

for (const [reason, override] of [
  ["CLI-held owner keys", { owner_key_mode: "umk" }],
  ["stopped sandbox", { status: "stopped" }],
  ["different owner", { owner_public_key: "other-owner" }],
  [
    "different Monitor route",
    { network_policy: { egress: [{ container_id: "other-monitor" }] } },
  ],
  ["not a sandbox", { repo: "tinfoilsh/confidential-agent-monitor" }],
] as const) {
  test(`browser shell excludes ${reason}`, () => {
    expect(
      sandboxCandidates(monitor([resource]), [
        { ...row, ...override } as Container,
      ]),
    ).toEqual([]);
  });
}

test("a saved owner record without its sandbox identity does not offer a browser shell", () => {
  expect(
    sandboxCandidates(monitor([{ ...resource, monitor_identity_seed: null }]), [
      row,
    ]),
  ).toEqual([]);
});
