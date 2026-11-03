// Representative Tinfoil MCP catalogs for review UI development, not live
// server definitions or production approvals. Nothing connects to these URLs.
import {
  applyChanges,
  type Change,
  type Json,
  type McpTool,
  type OwnerApi,
  type View,
} from "../src/owner";

type DemoTool = McpTool & {
  inputSchema: NonNullable<McpTool["inputSchema"]> & { type: "object" };
};
const previous: DemoTool[] = [
  {
    name: "fetch_page",
    description: "Fetch the text of a single public page.",
    inputSchema: {
      type: "object",
      properties: {
        url: { type: "string", description: "The public page URL." },
      },
      required: ["url"],
    },
    annotations: { readOnlyHint: true },
  },
  {
    name: "search",
    description: "Search public web pages.",
    inputSchema: {
      type: "object",
      properties: {
        query: { type: "string", description: "The search query." },
        page: { type: "integer", description: "Page number." },
      },
      required: ["query"],
    },
    annotations: { readOnlyHint: true },
  },
];
const tools: DemoTool[] = [
  {
    name: "fetch",
    description:
      "Fetch readable text from public web pages. Each URL is fetched separately and returned with its source address.",
    inputSchema: {
      type: "object",
      properties: {
        urls: { type: "array", description: "The public page URLs to fetch." },
        max_length: {
          type: "integer",
          description: "Optional maximum text length for each page.",
        },
      },
      required: ["urls"],
    },
    annotations: { readOnlyHint: true },
  },
  {
    name: "search",
    description:
      "Search the public web and return ranked results with source URLs and excerpts. Use fetch to read a result in full.",
    inputSchema: {
      type: "object",
      properties: {
        query: { type: "string", description: "The search query." },
        max_results: {
          type: "integer",
          description: "Maximum number of results to return.",
        },
      },
      required: ["query"],
    },
    annotations: { readOnlyHint: true },
  },
];
const pin = { instructions: "", tools };
const json = (value: unknown): Json => JSON.parse(JSON.stringify(value));

export function createTinfoilDemo(firstUse = false) {
  const name = "tinfoil";
  const edits: Change[] = [];
  const decorate = (original: View): View => {
    const view = structuredClone(original);
    view.config.accounts ??= {};
    view.config.accounts[name] = {
      preset: "tinfoil",
      contents: "me",
      sends: "me",
      strangers: true,
      connections: {
        "": {
          tinfoil: {
            enclave: "inference.tinfoil.sh",
            repo: "tinfoilsh/confidential-model-router",
            secrets: { TINFOIL_API_KEY: "tfm_dev_placeholder" },
          },
        },
        websearch: {
          "tinfoil-mcp": {
            url: "https://websearch.tinfoil.sh/mcp",
            repo: "tinfoilsh/confidential-websearch",
            secrets: { token: "tfm_dev_placeholder" },
            ...(!firstUse && {
              pin: json({ instructions: pin.instructions, tools: previous }),
            }),
          },
        },
      },
    };
    view.fields[name] = [
      {
        path: ["connections", "", "tinfoil", "secrets", "TINFOIL_API_KEY"],
        kind: "secret",
        placeholder: "dev_tinfoil_placeholder",
      },
      {
        path: ["connections", "websearch", "tinfoil-mcp", "secrets", "token"],
        kind: "secret",
        placeholder: "dev_tinfoil_placeholder",
      },
    ];
    for (const sandbox of ["danielbox1", "danielbox2"]) {
      const identity = view.config.identities?.[sandbox];
      if (identity)
        identity.accounts = { ...identity.accounts, [name]: { level: "ask" } };
    }
    applyChanges(view.config, edits);
    if (!view.config.accounts[name]) {
      delete view.fields[name];
      delete view.status[name];
      delete view.status[`${name}-websearch`];
      return view;
    }
    const approved =
      JSON.stringify(
        view.config.accounts[name].connections?.websearch?.["tinfoil-mcp"]?.pin,
      ) === JSON.stringify(pin);
    const changes = firstUse
      ? tools.map((tool) => `+ ${tool.name}\n${JSON.stringify(tool, null, 2)}`)
      : [
          `+ fetch\n${JSON.stringify(tools[0], null, 2)}`,
          `~ search\n${JSON.stringify(tools[1], null, 2)}`,
          "- fetch_page",
        ];
    view.status[name] = { state: "ready" };
    view.status[`${name}-websearch`] = {
      state: "ready",
      details: {
        blocked: approved ? 0 : tools.length,
        changes: approved ? [] : changes,
        pin: json(pin),
      },
    };
    return view;
  };
  const mockChange = (change: Change) => {
    const [root, key, section, account] = change.path;
    return (
      (["accounts", "policies", "default_access"].includes(root) &&
        key === name) ||
      (root === "identities" && section === "accounts" && account === name)
    );
  };
  return {
    wrap<T extends OwnerApi>(client: T): T {
      return Object.assign({}, client, {
        read: async (signal?: AbortSignal) => {
          const snapshot = await client.read(signal);
          return { ...snapshot, view: decorate(snapshot.view) };
        },
        edit: async (changes: Change[], signal?: AbortSignal) => {
          signal?.throwIfAborted();
          const local = changes.filter(mockChange),
            real = changes.filter((change) => !mockChange(change));
          const view = real.length
            ? await client.edit(real, signal)
            : (await client.read(signal)).view;
          edits.push(...JSON.parse(JSON.stringify(local)));
          return decorate(view);
        },
      });
    },
  };
}
