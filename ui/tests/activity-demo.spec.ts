import { expect, test } from "bun:test";
import { createActivityDemo } from "../dev/notifications";
import { needsOwner, type OwnerApi, type Snapshot } from "../src/owner";

function backend() {
  const state: Snapshot = {
    view: {
      generation: 1,
      host_key: "",
      host_id: "",
      ca: "",
      fields: {},
      labels: {},
      vocabulary: {},
      status: {},
      presets: {},
      config: {
        identities: { danielbox1: { key: "one" }, danielbox2: { key: "two" } },
      },
    },
    requests: [],
  };
  const client = {
    read: async () => state,
    decide: async () => {
      throw new Error("Mock decisions must not reach the backend");
    },
    edit: async () => {
      throw new Error("Mock rules must not reach the backend");
    },
  } as unknown as OwnerApi;
  return { state, client };
}

test("the static preview seeds pending, approved, rejected and outdated activity plus two rules", async () => {
  const real = backend(),
    demo = createActivityDemo(),
    client = demo.wrap(real.client);
  demo.seed();
  demo.seed();
  const preview = await client.read();
  expect(preview.requests.map((record) => record.state)).toEqual([
    "pending",
    "outdated",
    "approved",
    "denied",
  ]);
  expect(preview.requests.filter(needsOwner)).toHaveLength(1);
  expect(
    Object.values(preview.view.config.identities ?? {}).flatMap((identity) =>
      Object.keys(identity.rules ?? {}),
    ),
  ).toEqual(["dev-rule-github", "dev-rule-packages"]);
  expect(real.state.requests).toEqual([]);
  expect(real.state.view.config.identities!.danielbox1.rules).toBeUndefined();
});

test("pending demo requests share the list/detail source without mutating backend state", async () => {
  const real = backend(),
    demo = createActivityDemo(),
    client = demo.wrap(real.client);
  const first = demo.addRequest(),
    second = demo.addRequest();
  const read = await client.read();
  expect(read.requests.filter(needsOwner).map((r) => r.id)).toEqual([
    first.id,
    second.id,
  ]);
  expect((await client.request(first.id)).facts).toEqual(first.facts);
  expect(read.requests.map((r) => r.facts.principal.name)).toEqual([
    "danielbox1",
    "danielbox2",
  ]);
  expect(real.state.requests).toEqual([]);
});

test("allow and deny update authoritative demo records and reduce pending counts", async () => {
  const { client: source } = backend(),
    demo = createActivityDemo(),
    client = demo.wrap(source);
  const allowed = demo.addRequest(),
    denied = demo.addRequest();
  await client.decide(allowed.id, "once");
  expect((await client.read()).requests.filter(needsOwner)).toHaveLength(1);
  await client.decide(denied.id, "deny");
  expect((await client.read()).requests.filter(needsOwner)).toHaveLength(0);
  expect((await client.request(allowed.id)).state).toBe("approved");
  expect((await client.request(denied.id)).state).toBe("denied");
  await expect(client.decide(allowed.id, "once")).rejects.toThrow(
    "no longer pending",
  );
});

test("saving and removing a demo rule never writes to real policy", async () => {
  const real = backend(),
    demo = createActivityDemo(),
    client = demo.wrap(real.client);
  const request = demo.addRequest();
  await client.decide(request.id, "save");
  const saved = (await client.read()).view.config.identities!.danielbox1.rules!;
  expect(saved[request.id]).toMatchObject({
    account: "network",
    action: "connect",
    scope: { host: "api.github.com", port: 443 },
  });
  expect(real.state.view.config.identities!.danielbox1.rules).toBeUndefined();
  await client.edit([
    { path: ["identities", "danielbox1", "rules", request.id], delete: true },
  ]);
  expect(
    (await client.read()).view.config.identities!.danielbox1.rules?.[
      request.id
    ],
  ).toBeUndefined();
});
