import { render } from "solid-js/web";
import App from "../../src/App";
import * as owner from "../../src/owner";
import "../../src/dashboard.css";
import "../../src/shell.css";

const view: owner.View = {
  generation: 1,
  catalog_id: "test",
  host_key: "ssh-ed25519 test-host",
  host_id: "test-host",
  ca: "test-ca",
  fields: {},
  labels: {},
  vocabulary: { read: {}, write: { change: true } },
  status: {},
  config: {
    data: { onboarding: { completed: true } },
    connections: {
      "tinfoil-websearch": {
        preset: "tinfoil_websearch",
        contents: "me",
        sends: "me",
      },
      network: { preset: "tcp", contents: "anyone", sends: "anyone" },
    },
    identities: {
      "new-bunker": {
        key: "test-bunker",
        connections: {
          "tinfoil-websearch": {
            level: "allow",
            actions: { "use.fetch": "ask", "use.search": "ask" },
          },
          network: { level: "allow" },
        },
      },
    },
  },
  presets: {
    tinfoil_websearch: {
      title: "Tinfoil web search",
      group: "mcp",
      defaults: { contents: "me", sends: "me", strangers: true },
      actions: {
        "use.search": {
          title: "Search the web",
          effects: ["read", "pay", "send"],
        },
        "use.fetch": {
          title: "Fetch web pages",
          effects: ["read", "pay", "send"],
        },
      },
    },
    tcp: {
      title: "Network",
      group: "generic",
      defaults: { contents: "anyone", sends: "anyone", strangers: true },
      actions: {
        connect: { title: "Connect to a host", effects: ["read", "write"] },
      },
    },
  },
};
const requests: owner.RequestRecord[] = Array.from(
  { length: 60 },
  (_, index) => ({
    id: `request-${index}`,
    state: index < 2 ? "expired" : "allowed",
    time: new Date(Date.now() - index * 60_000).toISOString(),
    facts: {
      title:
        index % 4 < 2 ? "Connect to registry.npmjs.org:443" : "Search the web",
      principal: { name: "new-bunker" },
      connection: index % 4 < 2 ? "network" : "tinfoil-websearch",
      operation: { id: "search", action: "use.search", effects: ["read"] },
      parameters: { query: "test" },
    },
  }),
);
if (new URLSearchParams(location.search).has("single-tool"))
  delete view.presets.tinfoil_websearch.actions!["use.fetch"];
if (new URLSearchParams(location.search).has("root-override"))
  view.config.identities!["new-bunker"].connections![
    "tinfoil-websearch"
  ].actions = { use: "ask", "use.search": "off" };
if (new URLSearchParams(location.search).has("proposals")) {
  for (const state of ["pending", "approved"] as const)
    requests.push({
      id: `proposal-${state}`,
      state,
      time: new Date().toISOString(),
      expires: new Date(Date.now() + 60_000).toISOString(),
      facts: {
        title: "Update network access",
        principal: { name: "new-bunker", key: "test-bunker" },
        connection: "network",
        service: "policy-proposal",
      },
      changes: [{ path: ["effects", "write"], value: "ask" }],
    });
}
if (new URLSearchParams(location.search).has("review")) {
  view.config.connections!["tinfoil-websearch"]["tinfoil-mcp"] = {
    url: "https://websearch.example/mcp",
  };
  view.status["tinfoil-websearch"] = {
    state: "ready",
    details: {
      blocked: 2,
      changes: ["+ search", "+ fetch"],
      pin: { tools: [{ name: "search" }, { name: "fetch" }] },
    },
  };
  requests.push({
    id: "pending",
    state: "pending",
    time: new Date().toISOString(),
    expires: new Date(Date.now() + 60_000).toISOString(),
    facts: {
      title: "Connect to example.com",
      principal: { name: "new-bunker" },
      connection: "network",
    },
  });
}
const unexpected = async () => {
  throw new Error("Unexpected owner API call");
};
const client: owner.OwnerApi = {
  archived: unexpected,
  unlock: unexpected,
  onboard: unexpected,
  decide: unexpected,
  enroll: unexpected,
  signIn: unexpected,
  finishSignIn: unexpected,
  read: async () => structuredClone({ view, requests }),
  request: async (id: string) => {
    const request = requests.find((r) => r.id === id);
    if (!request) throw new Error(`Unknown request: ${id}`);
    return structuredClone(request);
  },
  archive: async () => ({ records: [] }),
  edit: async (changes: owner.Change[]) => {
    owner.applyChanges(view.config, changes);
    const setup = view.config.connections!["tinfoil-websearch"]["tinfoil-mcp"];
    if (setup && typeof setup === "object" && "pin" in setup) {
      if (
        JSON.stringify(setup.pin) !==
        JSON.stringify(view.status["tinfoil-websearch"].details?.pin)
      )
        throw new Error("Approval must save the reported tool definitions");
      view.status["tinfoil-websearch"] = { state: "ready" };
    }
    view.generation++;
    return structuredClone(view);
  },
};
render(
  () => <App client={client} snapshot={structuredClone({ view, requests })} />,
  document.getElementById("root")!,
);
