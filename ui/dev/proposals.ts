// Render-only connection proposals for the isolated local console. Decisions stay
// in page memory and never reach the Monitor backend.
import {
  OwnerError,
  previewChanges,
  type Change,
  type OwnerApi,
  type PolicyProposal,
  type Snapshot,
  type View,
} from "../src/owner";
import { DEVICE_ID } from "./fixtures";

export const PROPOSAL_SCENARIOS = [
  "mixed",
  "existing",
  "new",
  "none",
] as const;
export type ProposalScenario = (typeof PROPOSAL_SCENARIOS)[number];
export const proposalScenario = (value: string | null): ProposalScenario =>
  PROPOSAL_SCENARIOS.includes(value as ProposalScenario)
    ? (value as ProposalScenario)
    : "mixed";

const proposal = (
  id: string,
  connection: string,
  reason: string,
  changes: Change[],
  options: {
    proposer_kind?: PolicyProposal["proposer_kind"];
    proposer?: PolicyProposal["proposer"];
    stale?: boolean;
    source_diff?: string;
  } = {},
): PolicyProposal => ({
  id,
  digest: `dev-${id}-digest`,
  created_at: "2026-11-03T22:00:00Z",
  reason,
  proposer_kind: options.proposer_kind ?? "trusted_device",
  proposer: options.proposer ?? { name: DEVICE_ID },
  connection,
  affected: [{ kind: "connection", target: connection }],
  changes,
  source_diff:
    options.source_diff ??
    [
      "--- active/policy.toml",
      "+++ proposed/policy.toml",
      ...changes.flatMap((change) => [
        `@@ ${change.path.join(".")} @@`,
        `+ ${change.path.join(".")} = ${JSON.stringify(change.value)}`,
      ]),
    ].join("\n"),
  stale: options.stale,
});

const fixtures = {
  existing: proposal(
    "dev-proposal-tinfoil",
    "tinfoil",
    "Allow Captain Haddock to use approved Tinfoil models.",
    [
      { path: ["accounts", "tinfoil", "contents"], value: "team" },
      {
        path: ["identities", "danielbox1", "accounts", "tinfoil", "level"],
        value: "allow",
      },
    ],
    {
      source_diff: [
        "--- active/policy.toml",
        "+++ proposed/policy.toml",
        "@@ accounts.tinfoil @@",
        '- contents = "me"',
        '+ contents = "team"',
        "@@ identities.danielbox1.accounts.tinfoil @@",
        '- level = "ask"',
        '+ level = "allow"',
      ].join("\n"),
    },
  ),
  new: proposal(
    "dev-proposal-github",
    "github",
    "Add GitHub for repository triage",
    [
      {
        path: ["accounts", "github"],
        value: { preset: "github", contents: "me", sends: "me" },
      },
      {
        path: ["identities", "danielbox1", "accounts", "github"],
        value: { level: "ask" },
      },
    ],
    { proposer_kind: "sandbox", proposer: { name: "danielbox1" } },
  ),
};

const selected = (scenario: ProposalScenario) => {
  if (scenario === "none") return [];
  if (scenario === "mixed") return [fixtures.existing, fixtures.new];
  return [fixtures[scenario]];
};

export function createProposalDemo(scenario: ProposalScenario = "mixed") {
  const pending = new Map(
    selected(scenario).map((record) => [record.id, structuredClone(record)]),
  );
  const approved: Change[] = [];
  const records = () => structuredClone([...pending.values()]);
  const overlay = (view: View) => {
    const next = structuredClone(view);
    if (approved.length) previewChanges(next, approved);
    return next;
  };
  const snapshot = (original: Snapshot): Snapshot => ({
    ...original,
    view: overlay(original.view),
    proposals: records(),
  });
  const wrap = <T extends OwnerApi>(client: T): T =>
    Object.assign({}, client, {
      read: async (signal?: AbortSignal) => snapshot(await client.read(signal)),
      proposals: async (signal?: AbortSignal) => {
        signal?.throwIfAborted();
        return records();
      },
      proposal: async (id: string, signal?: AbortSignal) => {
        signal?.throwIfAborted();
        const record = pending.get(id);
        if (!record) return client.proposal(id, signal);
        return structuredClone(record);
      },
      approveProposal: async (
        record: PolicyProposal,
        signal?: AbortSignal,
      ) => {
        signal?.throwIfAborted();
        const saved = pending.get(record.id);
        if (!saved) return client.approveProposal(record, signal);
        if (saved.stale)
          throw new OwnerError("This proposal needs to be updated.", 409);
        approved.push(...structuredClone(saved.changes));
        pending.delete(saved.id);
        return overlay((await client.read(signal)).view);
      },
      rejectProposal: async (
        record: PolicyProposal,
        signal?: AbortSignal,
      ) => {
        signal?.throwIfAborted();
        if (!pending.delete(record.id))
          return client.rejectProposal(record, signal);
        return null;
      },
    });
  return { wrap, records };
}
