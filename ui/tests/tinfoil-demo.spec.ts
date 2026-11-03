import { expect, test } from "bun:test";
import { readFileSync } from "node:fs";
import * as owner from "../src/owner";
import { createTinfoilDemo } from "../dev/tinfoil";

const preset = JSON.parse(
  readFileSync(new URL("../../presets/tinfoil.json", import.meta.url), "utf8"),
);
function backend() {
  const view: owner.View = {
    generation: 1,
    host_key: "",
    host_id: "",
    ca: "",
    fields: {},
    labels: {},
    vocabulary: {},
    status: {},
    presets: { tinfoil: { title: preset.title, ...preset.catalog } },
    config: { identities: { danielbox1: { key: "one" } }, accounts: {} },
  };
  const client = {
    read: async () => ({ view, requests: [] }),
    edit: async () => {
      throw new Error("Fixture edits must not reach the real backend");
    },
  } as unknown as owner.OwnerApi;
  return { view, client };
}

test("Tinfoil demo exposes added/changed/removed tools against a previous approved snapshot", async () => {
  const real = backend(),
    client = createTinfoilDemo().wrap(real.client);
  const { view } = await client.read();
  const review = owner
    .reviews(view, "tinfoil")
    .find((r) => r.key === "websearch")!;
  expect([
    review.added,
    review.changed,
    review.removed,
    review.blocked,
  ]).toEqual([1, 1, 1, 2]);
  const changed = owner.toolChange(
    review.changes.find((c) => c.startsWith("~"))!,
    review.tools,
    review.previousTools,
  );
  expect(changed.changedFields).toEqual([
    { name: "description", kind: "Changed" },
    { name: "parameter: page", kind: "Removed" },
    { name: "parameter: max_results", kind: "Added" },
  ]);
  expect(
    owner.toolChange("- fetch_page", review.tools, review.previousTools).tool
      ?.name,
  ).toBe("fetch_page");
  expect(real.view.config.accounts!.tinfoil).toBeUndefined();
});

test("first-use demo stays blocked until an explicit approval and never writes real credentials/policy", async () => {
  const real = backend(),
    client = createTinfoilDemo(true).wrap(real.client);
  const { view } = await client.read();
  const review = owner
    .reviews(view, "tinfoil")
    .find((r) => r.key === "websearch")!;
  expect(review.previousTools).toEqual([]);
  expect([review.added, review.changed, review.blocked]).toEqual([2, 0, 2]);
  const approved = await client.edit(
    owner.edits.approveTools(view, "tinfoil", "websearch"),
  );
  expect(owner.accountStatus(approved, "tinfoil").blocked).toBe(0);
  expect(
    owner.accountStatus((await client.read()).view, "tinfoil").blocked,
  ).toBe(0);
  expect(real.view.config.accounts!.tinfoil).toBeUndefined();
});

test("the existing Tinfoil entry is used without creating a duplicate or persisting fixture edits", async () => {
  const real = backend();
  real.view.config.accounts!.tinfoil = {
    preset: "tinfoil",
    contents: "team",
    sends: "me",
  };
  const client = createTinfoilDemo().wrap(real.client);
  const { view } = await client.read();
  expect(Object.keys(view.config.accounts!)).toEqual(["tinfoil"]);
  expect(owner.accountStatus(view, "tinfoil").blocked).toBe(2);
  const updated = await client.edit([
    {
      path: ["identities", "danielbox1", "accounts", "tinfoil", "level"],
      value: "allow",
    },
  ]);
  expect(updated.config.identities!.danielbox1.accounts!.tinfoil.level).toBe(
    "allow",
  );
  expect(real.view.config.accounts!.tinfoil).toEqual({
    preset: "tinfoil",
    contents: "team",
    sends: "me",
  });
  expect(real.view.config.identities!.danielbox1.accounts).toBeUndefined();
});
