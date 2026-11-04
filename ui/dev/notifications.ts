// Local-only approval traffic. Decisions and saved rules stay in memory and
// never reach the Monitor backend or the example hosts.
import {
  OwnerError,
  type OwnerApi,
  type RequestRecord,
  type Rule,
  type Snapshot,
} from "../src/owner";
import { DEVICE_ID } from "./fixtures";

const samples = [
  { principal: "danielbox1", host: "api.github.com", port: 443 },
  { principal: "danielbox2", host: "smtp.example.com", port: 587 },
  { principal: "danielbox1", host: "api.openai.com", port: 443 },
  { principal: "danielbox2", host: "packages.example.com", port: 443 },
  { principal: "danielbox1", host: "db.example.com", port: 5432 },
  { principal: "danielbox2", host: "api.stripe.com", port: 443 },
];

export function createActivityDemo() {
  const records = new Map<string, RequestRecord>();
  const rules = new Map<string, Record<string, Rule>>();
  let cursor = 0;
  let seeded = false;
  const addRequest = () => {
    const sample = samples[cursor++ % samples.length];
    const now = Date.now();
    const record: RequestRecord = {
      id: `dev-approval-${crypto.randomUUID()}`,
      state: "pending",
      time: new Date(now).toISOString(),
      expires: new Date(now + 5 * 60_000).toISOString(),
      requirements: [
        { id: "ask", message: "This connection needs your approval." },
      ],
      facts: {
        title: `Connect to ${sample.host}:${sample.port}`,
        principal: { name: sample.principal },
        account: "network",
        service: "tcp",
        operation: {
          id: "tcp.connect",
          action: "connect",
          effects: ["read", "send"],
        },
        parameters: { host: sample.host, port: sample.port },
      },
    };
    records.set(record.id, record);
    return structuredClone(record);
  };
  const addRule = (name: string, id: string, rule: Rule) => {
    rules.set(name, { ...rules.get(name), [id]: structuredClone(rule) });
  };
  const seed = () => {
    if (seeded) return;
    seeded = true;
    addRequest();
    const outdated: RequestRecord = {
      id: "dev-proposal-outdated",
      state: "outdated",
      time: new Date(Date.now() - 30 * 60_000).toISOString(),
      requirements: [{
        id: "policy.outdated",
        message: "Settings affecting this connection changed before the proposal was reviewed.",
      }],
      facts: {
        title: "Restrict network access for package downloads.",
        principal: { name: DEVICE_ID },
        account: "network",
        service: "policy-proposal",
        details: {
          policy: {
            source_diff: [
              "--- active/policy.toml",
              "+++ proposed/policy.toml",
              "@@ accounts.network @@",
              '- hosts = ["*"]',
              '+ hosts = ["registry.npmjs.org"]',
            ].join("\n"),
          },
        },
      },
    };
    records.set(outdated.id, outdated);
    const approved: RequestRecord = {
      id: "dev-proposal-approved",
      state: "approved",
      time: new Date(Date.now() - 45 * 60_000).toISOString(),
      requirements: [{
        id: "policy",
        message: "Allow Captain Haddock to use approved Tinfoil models.",
      }],
      reviews: [{
        by: "owner",
        decision: "once",
        time: new Date(Date.now() - 44 * 60_000).toISOString(),
      }],
      facts: {
        title: "Allow Captain Haddock to use approved Tinfoil models.",
        principal: { name: DEVICE_ID },
        account: "tinfoil",
        service: "policy-proposal",
        details: {
          policy: {
            source_diff: [
              "--- active/policy.toml",
              "+++ proposed/policy.toml",
              "@@ accounts.tinfoil @@",
              '- contents = "me"',
              '+ contents = "team"',
            ].join("\n"),
          },
        },
      },
    };
    records.set(approved.id, approved);
    const rejected: RequestRecord = {
      id: "dev-proposal-rejected",
      state: "denied",
      time: new Date(Date.now() - 60 * 60_000).toISOString(),
      requirements: [{
        id: "policy",
        message: "Restrict package downloads to one registry.",
      }],
      reviews: [{
        by: "owner",
        decision: "deny",
        time: new Date(Date.now() - 59 * 60_000).toISOString(),
      }],
      facts: {
        title: "Restrict package downloads to one registry.",
        principal: { name: "danielbox1" },
        account: "network",
        service: "policy-proposal",
        details: {
          policy: {
            source_diff: [
              "--- active/policy.toml",
              "+++ proposed/policy.toml",
              "@@ accounts.network @@",
              '- hosts = ["*"]',
              '+ hosts = ["registry.npmjs.org"]',
            ].join("\n"),
          },
        },
      },
    };
    records.set(rejected.id, rejected);
    addRule("danielbox1", "dev-rule-github", {
      account: "network",
      action: "connect",
      operation: "tcp.connect",
      scope: { host: "api.github.com", port: 443 },
      requirements: [
        { id: "ask", message: "This connection needs your approval." },
      ],
    });
    addRule("danielbox2", "dev-rule-packages", {
      account: "network",
      action: "connect",
      operation: "tcp.connect",
      scope: { host: "registry.npmjs.org", port: 443 },
      requirements: [
        { id: "ask", message: "This connection needs your approval." },
      ],
    });
  };
  const snapshot = (original: Snapshot): Snapshot => {
    const next = structuredClone(original);
    next.requests.push(...structuredClone([...records.values()]));
    for (const [name, saved] of rules) {
      const identity = next.view.config.identities?.[name];
      if (identity)
        identity.rules = { ...identity.rules, ...structuredClone(saved) };
    }
    return next;
  };
  const wrap = <T extends OwnerApi>(client: T): T =>
    Object.assign({}, client, {
      read: async (signal?: AbortSignal) => snapshot(await client.read(signal)),
      request: async (id: string, signal?: AbortSignal) =>
        records.has(id)
          ? structuredClone(records.get(id)!)
          : client.request(id, signal),
      archived: async (segment: string, id: string, signal?: AbortSignal) =>
        records.has(id)
          ? structuredClone(records.get(id)!)
          : client.archived(segment, id, signal),
      decide: async (
        id: string,
        decision: "once" | "save" | "deny",
        signal?: AbortSignal,
      ) => {
        signal?.throwIfAborted();
        const record = records.get(id);
        if (!record) return client.decide(id, decision, signal);
        if (
          record.state !== "pending" ||
          Date.parse(record.expires!) <= Date.now()
        )
          throw new OwnerError("This request is no longer pending.", 409);
        record.state = decision === "deny" ? "denied" : "approved";
        record.reviews = [
          { by: "owner", decision, time: new Date().toISOString() },
        ];
        if (decision === "save") {
          const name = record.facts.principal.name;
          const saved = rules.get(name) ?? {};
          saved[id] = {
            account: record.facts.account,
            action: "connect",
            operation: "tcp.connect",
            scope: record.facts.parameters,
            requirements: record.requirements,
          };
          rules.set(name, saved);
        }
        return null;
      },
      edit: async (
        changes: Parameters<OwnerApi["edit"]>[0],
        signal?: AbortSignal,
      ) => {
        const real = changes.filter((change) => {
          const [root, name, key, id] = change.path;
          if (
            root !== "identities" ||
            key !== "rules" ||
            !id?.startsWith("dev-approval-")
          )
            return true;
          if (!change.delete)
            throw new OwnerError("Demo rules can only be removed.", 400);
          delete rules.get(name)?.[id];
          return false;
        });
        const view = real.length
          ? await client.edit(real, signal)
          : (await client.read(signal)).view;
        return snapshot({ view, requests: [] }).view;
      },
    });
  const play = (refresh: () => Promise<void>) => {
    let live = true;
    const remaining = Math.max(0, samples.length - cursor);
    const timers = Array.from({ length: remaining }, (_, index) =>
      setTimeout(
        () => {
          if (!live) return;
          addRequest();
          void refresh();
        },
        1000 + index * 5000,
      ),
    );
    return () => {
      live = false;
      timers.forEach(clearTimeout);
    };
  };
  return { wrap, play, addRequest, addRule, seed };
}

export const activityDemo = createActivityDemo();
export const playNotifications = activityDemo.play;
