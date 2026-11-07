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
    connections: {
      network: { preset: "tcp", contents: "anyone", sends: "anyone" },
    },
  },
  presets: { tcp: { title: tcp.title, ...tcp.catalog } },
});

test("missing preset metadata has a display fallback, not a raw Custom service", () => {
  const v = view();
  v.config.connections!.network.preset = "removed";
  expect(owner.presetOf(v, "network").title).toBe("Service");
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
      sandbox: { key: "key", connections: { network: { level: "read" } } },
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
        .levelsOf({ ...v.config.connections!.network, preset: "github" })
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
      owner.edits.addConnection(v, "tcp", {
        name: "restricted",
        values: { hosts },
        answers: tcp.catalog.defaults,
      }).changes,
    );
    expect(v.config.connections!.restricted.tcp).toEqual({ hosts });
    expect(v.config.connections!.restricted).toMatchObject(
      tcp.catalog.defaults,
    );
  });
});

test("Custom API can be created before its credential is configured", () => {
  const v = view();
  const { changes, credentials } = owner.edits.addCustomApi(v, {
    name: "example-api",
    api: {
      url: "https://api.example.com/v1",
      auth: "bearer",
      header: "X-API-Key",
      prefix: "",
      query: "api_key",
    },
    token: "",
    answers: { contents: "me", sends: "me", strangers: true },
  });
  expect(credentials).toEqual({});
  owner.applyChanges(v.config, changes);
  expect(v.config.connections!["example-api"]).toMatchObject({
    preset: "custom_api",
    http: {
      slots: [{
        value: "token",
        origin: "https://api.example.com",
        path: "/v1",
        header: "Authorization",
        prefix: "Bearer ",
      }],
    },
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
    v.config.connections!.network.mcp = {};
    v.status.network = {
      state: "ready",
      details: { blocked: 1, changes: ["+ search"], pin: { tools: [after] } },
    };
    const first = owner.review(v, "network")!;
    expect(first.previouslyApproved).toBe(false);
    expect(owner.toolReviewDescription(first)).toBe(
      "network advertises 1 MCP tool you haven’t approved yet. Review their definitions before using them.",
    );
    v.config.connections!.network.mcp = {
      pin: { tools: [], instructions: "Old" },
    };
    v.status.network.details!.changes = ["~ instructions:\nNew"];
    const changed = owner.review(v, "network")!;
    expect(changed.previouslyApproved).toBe(true);
    expect(owner.toolReviewDescription(changed)).toContain(
      "Server instructions advertised by network differ from those you last approved.",
    );
  });
  test("reviews read the prior pin from config and leave approval an explicit edit", () => {
    const v = view();
    v.config.connections!.network.mcp = { pin: { tools: [before] } };
    v.status.network = {
      state: "ready",
      details: { blocked: 1, changes: ["~ search"], pin: { tools: [after] } },
    };
    const original = JSON.stringify(v);
    const review = owner.review(v, "network")!;
    expect(review.previouslyApproved).toBe(true);
    expect(owner.toolReviewDescription(review)).toContain(
      "Tool definitions advertised by network differ from those you last approved.",
    );
    expect(review.changes[0]).toMatchObject({ kind: "Changed", tool: after });
    expect(review.changes[0].changedFields).toContainEqual({
      name: "description",
      kind: "Changed",
    });
    expect(JSON.stringify(v)).toBe(original);
    expect(owner.edits.approveTools(v, "network").length).toBeGreaterThan(0);
  });
});

describe("first setup", () => {
  const setupView = () => {
    const v = view();
    v.config.connections = {};
    v.presets = Object.fromEntries(
      ["tcp", "tinfoil", "tinfoil_websearch", "anthropic", "github"].map(
        (name) => {
          const value = preset(name);
          return [name, { title: value.title, ...value.catalog }];
        },
      ),
    );
    return v;
  };
  const onboard = async (choices: owner.OnboardingChoices) => {
    const v = setupView();
    const sent: { method: string; path: string; body: any }[] = [];
    await owner
      .ownerApi(async (method, path, body) => {
        sent.push({ method, path, body });
        return v;
      })
      .onboard(v, choices);
    return sent;
  };
  const access = (body: any, connection: string) =>
    body.changes.find(
      (change: owner.Change) =>
        change.path.join("/") === `default_access/${connection}`,
    )?.value;

  test("adds the picked services with their keys and the chosen network access", async () => {
    const [{ method, path, body }] = await onboard({
      services: [
        { preset: "tinfoil", level: "allow", credential: "tk_live" },
        { preset: "anthropic", level: "allow", credential: "sk-ant" },
        { preset: "github", level: "ask" },
      ],
      network: "ask",
    });
    expect([method, path]).toEqual(["POST", "/policy/edits"]);
    expect(body.credentials).toEqual({
      tinfoil: { TINFOIL_API_KEY: "tk_live" },
      "tinfoil-websearch": { token: "tk_live" },
      anthropic: { token: "sk-ant" },
      github: {},
    });
    expect(access(body, "network")).toEqual({ level: "ask" });
    expect(access(body, "tinfoil")).toEqual({ level: "allow" });
    expect(access(body, "tinfoil-websearch")).toEqual({ level: "allow" });
    expect(access(body, "anthropic")).toEqual({ level: "allow" });
    expect(access(body, "github")).toEqual({ level: "ask" });
  });

  test("refuses Tinfoil without a key", async () => {
    await expect(
      onboard({
        services: [{ preset: "tinfoil", level: "allow", credential: " " }],
        network: "off",
      }),
    ).rejects.toThrow("Choose a Tinfoil API key.");
  });
});
