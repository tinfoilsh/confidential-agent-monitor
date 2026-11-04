import { describe, expect, test } from "bun:test";
import { createProposalDemo, proposalScenario } from "../dev/proposals";
import type { OwnerApi, Snapshot, View } from "../src/owner";

const view = (): View => ({
  generation: 1,
  host_key: "host",
  host_id: "id",
  ca: "ca",
  config: {
    accounts: {
      tinfoil: { preset: "tinfoil", contents: "me", sends: "me" },
      network: { preset: "tcp", contents: "me", sends: "me" },
    },
    identities: {
      danielbox1: { key: "one", accounts: {} },
      danielbox2: {
        key: "two",
        accounts: { network: { level: "allow" } },
      },
    },
  },
  labels: {},
  status: {},
  fields: {},
  presets: {
    tinfoil: { title: "Tinfoil" },
    github: { title: "GitHub" },
    tcp: { title: "Network" },
  },
  vocabulary: {},
});

const backing = (): OwnerApi => {
  const snapshot: Snapshot = { view: view(), requests: [], proposals: [] };
  return {
    read: async () => structuredClone(snapshot),
    proposal: async () => {
      throw new Error("missing");
    },
    approveProposal: async () => {
      throw new Error("unexpected real approval");
    },
    rejectProposal: async () => {
      throw new Error("unexpected real rejection");
    },
  } as unknown as OwnerApi;
};

describe("local proposal previews", () => {
  test("mixed is the safe default and none is explicit", () => {
    expect(proposalScenario(null)).toBe("mixed");
    expect(proposalScenario("unknown")).toBe("mixed");
    expect(createProposalDemo("mixed").records()).toHaveLength(2);
    expect(createProposalDemo("none").records()).toHaveLength(0);
  });

  test("approval changes only the in-memory preview", async () => {
    const original = backing();
    const client = createProposalDemo("new").wrap(original);
    const before = await client.read();
    const record = before.proposals![0]!;
    expect(before.view.config.accounts?.github).toBeUndefined();

    await client.approveProposal(record);
    const after = await client.read();
    expect(after.proposals).toEqual([]);
    expect(after.view.config.accounts?.github?.preset).toBe("github");
    expect((await original.read()).view.config.accounts?.github).toBeUndefined();
  });

});
