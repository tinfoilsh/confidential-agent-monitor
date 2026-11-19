import { describe, expect, test } from "bun:test";
import { readFileSync } from "node:fs";
import * as owner from "../src/owner";
import * as slack from "../src/slack";

const preset = (name: string) =>
  JSON.parse(
    readFileSync(
      new URL(`../../connector/catalog/presets/${name}.json`, import.meta.url),
      "utf8",
    ),
  );
const github = preset("github");
const view = (): owner.View => ({
  generation: 1,
  revision: 1,
  host_key: "",
  host_id: "",
  ca: "",
  fields: {},
  labels: {},
  vocabulary: {
    read: {},
    write: { change: true },
    execute: { change: true },
    send: { change: true },
  },
  status: {},
  config: {
    connections: {
      github: {
        preset: "github",
        contents: "me",
        sends: "anyone",
        http: {},
      },
    },
    identities: {
      sandbox: {
        key: "key",
        connections: {
          github: {
            level: "allow",
            actions: { "repos.contents.write": "off" },
          },
        },
      },
    },
  },
  presets: { github: { title: github.title, ...github.catalog } },
});

describe("match-only mode", () => {
  test("is off by default and keeps the preset's actions", () => {
    const v = view();
    expect(owner.matchOnly(v, "github")).toBe(false);
    expect(Object.keys(owner.actionsOf(v, "github")).length).toBeGreaterThan(
      10,
    );
    expect(
      owner.levelsOf(v.config.connections!.github).map(([l]) => l),
    ).toContain("read");
  });

  test("toggling writes and removes only the connection's match_only flag", () => {
    const v = view();
    const on = owner.edits.setMatchOnly("github", true);
    expect(on).toEqual([
      { path: ["connections", "github", "match_only"], value: true },
    ]);
    owner.applyChanges(v.config, on);
    expect(v.config.connections!.github.match_only).toBe(true);
    // The setting is not mistaken for the connector kind holding the setup.
    expect(owner.kindOf(v.config.connections!.github)).toBe("http");
    owner.applyChanges(v.config, owner.edits.setMatchOnly("github", false));
    expect(v.config.connections!.github.match_only).toBeUndefined();
    expect(owner.kindOf(v.config.connections!.github)).toBe("http");
  });

  test("replaces the action tree with one broad request and drops read-only", () => {
    const v = view();
    v.config.connections!.github.match_only = true;
    expect(owner.actionsOf(v, "github")).toEqual({
      [owner.MATCH_ONLY_ACTION]: {
        title: "Any request (match-only)",
        effects: ["execute", "send"],
      },
    });
    expect(owner.actionTree(v, "github").map((n) => n.key)).toEqual([
      "request",
    ]);
    expect(owner.effectsOf(v, "github", "request").sort()).toEqual([
      "execute",
      "send",
    ]);
    expect(
      owner.levelsOf(v.config.connections!.github).map(([l]) => l),
    ).toEqual(["off", "ask", "allow"]);
    // Setup fields and title still come from the preset.
    expect(owner.presetOf(v, "github").title).toBe(github.title);
    expect(owner.presetOf(v, "github").fields).toEqual(github.catalog.fields);
    // The same copy is returned on every read.
    expect(owner.presetOf(v, "github")).toBe(owner.presetOf(v, "github"));
    // The view's own preset is unchanged for other connections.
    expect(Object.keys(v.presets.github.actions!).length).toBeGreaterThan(10);
  });

  test("an Allow bunker can make any request without asking; Ask still asks", () => {
    const v = view();
    v.config.connections!.github.match_only = true;
    const allow = owner.agentAccess(v, "sandbox", "github")[0];
    expect(allow.actions.map((a) => [a.key, a.mode])).toEqual([
      ["request", "allow"],
    ]);
    v.config.identities!.sandbox.connections!.github = { level: "ask" };
    const ask = owner.agentAccess(v, "sandbox", "github")[0];
    expect(ask.actions.map((a) => [a.key, a.mode])).toEqual([
      ["request", "ask"],
    ]);
  });

  test("pinned MCP tools are not listed as actions", () => {
    const v = view();
    v.config.connections!.tools = {
      preset: "github",
      contents: "me",
      sends: "anyone",
      match_only: true,
      mcp: { pin: { tools: [{ name: "delete_repo" }] } },
    };
    expect(Object.keys(owner.actionsOf(v, "tools"))).toEqual(["request"]);
  });
});

describe("Slack custom app", () => {
  test("offers app setup for the token-based Slack presets", () => {
    expect(slack.SLACK_APP_PRESETS).toEqual(["slack", "slack_socket_mode"]);
  });

  test("builds a read-and-post bot manifest that Slack's create-app URL carries", () => {
    const url = new URL(slack.slackCreateURL("slack", "Team agent", "write"));
    expect(url.origin).toBe("https://api.slack.com");
    expect(url.pathname).toBe("/apps");
    expect(url.searchParams.get("new_app")).toBe("1");
    const manifest = JSON.parse(url.searchParams.get("manifest_json")!);
    expect(manifest.display_information.name).toBe("Team agent");
    expect(manifest.features.bot_user.display_name).toBe("Team agent");
    expect(manifest.settings.socket_mode_enabled).toBe(false);
    const scopes: string[] = manifest.oauth_config.scopes.bot;
    expect(scopes).toContain("chat:write");
    expect(scopes).toContain("channels:history");
    expect(new Set(scopes).size).toBe(scopes.length);
  });

  test("read-only apps ask for no write scopes", () => {
    const scopes = slack.slackScopes("slack", "read");
    expect(
      scopes.some((s) => s.endsWith(":write") || s === "channels:join"),
    ).toBe(false);
    expect(scopes).toContain("channels:read");
  });

  test("every scope is a Slack bot scope name", () => {
    for (const access of ["read", "write"] as const)
      for (const p of slack.SLACK_APP_PRESETS)
        for (const scope of slack.slackScopes(p, access))
          expect(scope).toMatch(/^[a-z_]+(\.[a-z_]+)?:[a-z_.]+$/);
  });

  test("Socket Mode apps enable Socket Mode and subscribe to mentions and DMs", () => {
    const manifest = slack.slackManifest("slack_socket_mode", "", "write");
    expect(manifest.display_information.name).toBe(slack.SLACK_APP_NAME);
    expect(manifest.settings.socket_mode_enabled).toBe(true);
    expect(manifest.settings.event_subscriptions!.bot_events).toEqual([
      "app_mention",
      "message.im",
    ]);
    const scopes = manifest.oauth_config.scopes.bot;
    expect(scopes).toContain("app_mentions:read");
    expect(scopes).toContain("im:history");
    expect(slack.slackSteps("slack_socket_mode").join(" ")).toContain(
      "connections:write",
    );
  });

  test("names fit Slack's limit and GovSlack uses its own apps host", () => {
    expect(slack.slackAppName("x".repeat(80))).toHaveLength(35);
    expect(slack.slackAppName("   ")).toBe(slack.SLACK_APP_NAME);
    expect(slack.slackAppsOrigin("https://slack-gov.com")).toBe(
      "https://api.slack-gov.com",
    );
    expect(slack.slackAppsOrigin("https://slack.com")).toBe(
      "https://api.slack.com",
    );
    expect(
      slack.slackCreateURL("slack", "a", "read", "https://slack-gov.com/"),
    ).toStartWith("https://api.slack-gov.com/apps?");
  });
});
