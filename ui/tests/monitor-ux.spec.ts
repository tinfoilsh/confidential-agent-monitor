import { describe, expect, test } from "bun:test";
import { readFileSync } from "node:fs";
import * as owner from "../src/owner";

const preset = (name: string) => JSON.parse(
  readFileSync(new URL(`../../presets/${name}.json`, import.meta.url), "utf8"),
);
const tcp = preset("tcp");
const view = (): owner.View => ({
  generation: 1,
  host_key: "",
  host_id: "",
  ca: "",
  fields: {},
  labels: {},
  vocabulary: {},
  status: {},
  config: {
    accounts: {
      network: { preset: "tcp", contents: "anyone", sends: "anyone" },
    },
  },
  presets: { tcp: { title: tcp.title, ...tcp.catalog } },
});

test("missing preset metadata has a display fallback, not a raw Custom connection", () => {
  const v = view();
  expect(owner.presetOf(v, "removed-account").title).toBe("Connection");
  expect(owner.connectorIcon({}, "", "/app/").src).toContain("custom.svg");
  expect(Object.hasOwn(v.presets, "custom")).toBe(false);
  expect(owner.catalog(v).flatMap((group) => group.presets).some((p) => p.name === "custom" || p.name === "browser")).toBe(false);
});

test("generic connections are an informed fallback group at the end of the catalog", () => {
  const v = view();
  const names = ["web", "ssh", "tcp", "custom_api", "mcp"];
  v.presets = Object.fromEntries(names.map((name) => {
    const value = preset(name);
    return [name, { title: value.title, ...value.catalog }];
  }));
  const groups = owner.catalog(v);
  expect(groups.at(-1)?.title).toBe("Generic");
  expect(groups.at(-1)?.presets.map((entry) => entry.name)).toEqual(names);
  for (const name of names) {
    expect(v.presets[name].warning).toBeTruthy();
  }
});

describe("raw TCP setup and access", () => {
  test("does not offer read-only; existing stored settings remain unchanged", () => {
    const v = view();
    v.config.identities = {
      sandbox: { key: "key", accounts: { network: { level: "read" } } },
    };
    const access = owner.agentAccess(v, "sandbox", "network")[0];
    expect(access.levels.map(([level]) => level)).toEqual([
      "off",
      "ask",
      "allow",
    ]);
    expect(access.level).toBe("read");
    expect(
      owner
        .levelsOf({ ...v.config.accounts!.network, preset: "github" })
        .map(([l]) => l),
    ).toContain("read");
  });
  test("host patterns are editable during setup and keep data-flow defaults", () => {
    const v = view();
    const field = owner.setupFields(v, "tcp").find((f) => f.key === "hosts")!;
    expect(field.label).toBe("Hosts");
    expect(field.help).toBe(
      "Hostnames or wildcard patterns. Matches all TCP ports.",
    );
    expect(field.hint).toBe("example.com, *.example.com, or * for all hosts");
    expect(owner.fieldText(field, field.default)).toBe("*");
    const hosts = owner.readField(field, "example.com, *.example.com");
    expect(hosts).toEqual(["example.com", "*.example.com"]);
    owner.applyChanges(
      v.config,
      owner.edits.addAccount(v, "tcp", {
        name: "restricted",
        values: { hosts },
        answers: tcp.catalog.defaults,
      }),
    );
    expect(v.config.accounts!.restricted.connections![""].tcp.hosts).toEqual(
      hosts,
    );
    expect(v.config.accounts!.restricted).toMatchObject(tcp.catalog.defaults);
  });
});

describe("MCP review uses saved pins without approving them", () => {
  const before: owner.McpTool = {
    name: "search",
    description: "Old description",
    inputSchema: {
      properties: { query: { type: "string" }, old: { type: "string" } },
      required: ["query"],
    },
  };
  const after: owner.McpTool = {
    name: "search",
    description: "New description",
    inputSchema: {
      properties: { query: { type: "number" }, limit: { type: "number" } },
      required: ["query"],
    },
  };
  test("summarizes actual changes and required parameter metadata", () => {
    const change = owner.toolChange(
      "~ search\nnew definition",
      [after],
      [before],
    );
    expect(change.changedFields).toEqual([
      { name: "description", kind: "Changed" },
      { name: "parameter: query", kind: "Changed" },
      { name: "parameter: old", kind: "Removed" },
      { name: "parameter: limit", kind: "Added" },
    ]);
    expect(change.parameters[0]).toMatchObject({
      name: "query",
      type: "number",
      required: true,
    });
    expect(
      owner.toolChange("~ search", [after], [structuredClone(after)])
        .changedFields,
    ).toEqual([]);
  });
  test("removed tools retain their reviewed definition; missing prior pins do not invent a diff", () => {
    expect(owner.toolChange("- search", [], [before]).tool).toEqual(before);
    expect(owner.toolChange("+ search", [after]).changedFields).toEqual([]);
    expect(owner.toolChange("~ search", [after]).changedFields).toEqual([]);
  });
  test("review wording distinguishes first-use tools from changed server instructions", () => {
    const v = view();
    v.config.accounts!.network.connections = { "": { mcp: {} } };
    v.status.network = {
      state: "ready",
      details: { blocked: 1, changes: ["+ search"], pin: { tools: [after] } },
    };
    const first = owner.reviews(v, "network")[0];
    expect(first.previouslyApproved).toBe(false);
    expect(owner.toolReviewDescription(first)).toBe(
      "network advertises 1 MCP tool you haven’t approved yet. Review their definitions before using them.",
    );
    v.config.accounts!.network.connections[""].mcp.pin = {
      tools: [],
      instructions: "Old",
    };
    v.status.network.details!.changes = ["~ instructions:\nNew"];
    const changed = owner.reviews(v, "network")[0];
    expect(changed.previouslyApproved).toBe(true);
    expect(owner.toolReviewDescription(changed)).toContain(
      "Server instructions advertised by network differ from those you last approved.",
    );
  });
  test("reviews read the prior pin from config and leave approval an explicit edit", () => {
    const v = view();
    v.config.accounts!.network.connections = {
      "": { mcp: { pin: { tools: [before] } } },
    };
    v.status.network = {
      state: "ready",
      details: { blocked: 1, changes: ["~ search"], pin: { tools: [after] } },
    };
    const original = JSON.stringify(v);
    const review = owner.reviews(v, "network")[0];
    expect(review.previouslyApproved).toBe(true);
    expect(owner.toolReviewDescription(review)).toContain(
      "Tool definitions advertised by network differ from those you last approved.",
    );
    expect(review.previousTools).toEqual([before]);
    expect(review.tools).toEqual([after]);
    expect(JSON.stringify(v)).toBe(original);
    expect(owner.edits.approveTools(v, "network", "").length).toBeGreaterThan(
      0,
    );
  });
});
