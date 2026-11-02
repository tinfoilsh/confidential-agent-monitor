import { describe, expect, test } from "bun:test";
import { readFileSync } from "node:fs";
import * as owner from "../src/owner";

const tcp = JSON.parse(readFileSync(new URL("../../presets/tcp.json", import.meta.url), "utf8"));
const view = (): owner.View => ({
  generation: 1, host_key: "", host_id: "", ca: "", fields: {}, labels: {},
  vocabulary: {}, status: {},
  config: { accounts: { network: { preset: "tcp", contents: "anyone", sends: "anyone" } } },
  presets: { tcp: { title: tcp.title, ...tcp.catalog } },
});

describe("raw TCP setup and access", () => {
  test("does not offer read-only; existing stored settings remain unchanged", () => {
    const v = view();
    v.config.identities = { sandbox: { key: "key", accounts: { network: { level: "read" } } } };
    const access = owner.agentAccess(v, "sandbox", "network")[0];
    expect(access.levels.map(([level]) => level)).toEqual(["off", "ask", "allow"]);
    expect(access.level).toBe("read");
    expect(owner.levelsOf({ ...v.config.accounts!.network, preset: "github" }).map(([l]) => l)).toContain("read");
  });
  test("host patterns are editable during setup and keep data-flow defaults", () => {
    const v = view();
    const field = owner.setupFields(v, "tcp").find((f) => f.key === "hosts")!;
    expect(field.label).toBe("Host patterns (all TCP ports)");
    expect(owner.fieldText(field, field.default)).toBe("*");
    const hosts = owner.readField(field, "example.com, *.example.com");
    expect(hosts).toEqual(["example.com", "*.example.com"]);
    owner.applyChanges(v.config, owner.edits.addAccount(v, "tcp", {
      name: "restricted", values: { hosts }, answers: tcp.catalog.defaults,
    }));
    expect(v.config.accounts!.restricted.connections![""].tcp.hosts).toEqual(hosts);
    expect(v.config.accounts!.restricted).toMatchObject(tcp.catalog.defaults);
  });
});

describe("MCP review uses saved pins without approving them", () => {
  const before: owner.McpTool = {
    name: "search", description: "Old description",
    inputSchema: { properties: { query: { type: "string" }, old: { type: "string" } }, required: ["query"] },
  };
  const after: owner.McpTool = {
    name: "search", description: "New description",
    inputSchema: { properties: { query: { type: "number" }, limit: { type: "number" } }, required: ["query"] },
  };
  test("summarizes actual changes and required parameter metadata", () => {
    const change = owner.toolChange("~ search\nnew definition", [after], [before]);
    expect(change.changedFields).toEqual([
      { name: "description", kind: "Changed" },
      { name: "parameter: query", kind: "Changed" },
      { name: "parameter: old", kind: "Removed" },
      { name: "parameter: limit", kind: "Added" },
    ]);
    expect(change.parameters[0]).toMatchObject({ name: "query", type: "number", required: true });
    expect(owner.toolChange("~ search", [after], [structuredClone(after)]).changedFields).toEqual([]);
  });
  test("removed tools retain their reviewed definition; missing prior pins do not invent a diff", () => {
    expect(owner.toolChange("- search", [], [before]).tool).toEqual(before);
    expect(owner.toolChange("+ search", [after]).changedFields).toEqual([]);
    expect(owner.toolChange("~ search", [after]).changedFields).toEqual([]);
  });
  test("reviews read the prior pin from config and leave approval an explicit edit", () => {
    const v = view();
    v.config.accounts!.network.connections = { "": { mcp: { pin: { tools: [before] } } } };
    v.status.network = { state: "ready", details: { blocked: 1, changes: ["~ search"], pin: { tools: [after] } } };
    const original = JSON.stringify(v);
    const review = owner.reviews(v, "network")[0];
    expect(review.previousTools).toEqual([before]);
    expect(review.tools).toEqual([after]);
    expect(JSON.stringify(v)).toBe(original);
    expect(owner.edits.approveTools(v, "network", "").length).toBeGreaterThan(0);
  });
});
