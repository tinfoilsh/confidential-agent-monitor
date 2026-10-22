import { For, Show, createMemo, createSignal, createUniqueId } from "solid-js";
import * as owner from "./owner.js";
import {
  ConnectorIcon,
  Empty,
  Icon,
  LazyDetails,
  Permission,
  ResourceDisclosure,
  Search,
  href,
} from "./components";
import { useMonitor } from "./monitor";

export function Agents(props: { expanded?: string }) {
  const m = useMonitor(),
    [query, setQuery] = m.search("agents");
  if (props.expanded) setQuery("");
  const type = (name: string) =>
    owner.isDevice(name)
      ? "devices"
      : name.startsWith("sandbox-")
        ? "sandboxes"
        : "agents";
  const summaries = createMemo(() => {
    const view = m.view()!;
    return new Map(
      Object.keys(view.config.identities ?? {})
        .sort()
        .map((name) => {
          const description = owner.isDevice(name)
            ? `Sandbox access ${view.config.identities![name].routes ? "enabled" : "disabled"}`
            : `${owner.agentAccess(view, name).filter((access) => access.level !== "off").length} connections`;
          return [
            name,
            { description, search: `${name} ${description}`.toLowerCase() },
          ];
        }),
    );
  });
  const names = createMemo(() => {
    const search = query().toLowerCase();
    return [...summaries()]
      .filter(([, summary]) => summary.search.includes(search))
      .map(([name]) => name);
  });
  return (
    <>
      <div id="toolbar">
        <Search label="Search agents" value={query()} onInput={setQuery} />
      </div>
      <For
        each={[
          ["sandboxes", "Sandboxes"],
          ["devices", "Devices"],
          ["agents", "Other agents"],
        ]}
      >
        {([kind, title]) => {
          const members = createMemo(() =>
            names().filter((name) => type(name) === kind),
          );
          return (
            <Show when={members().length}>
              <div class="resource-list collection-list">
                <div class="resource-heading">
                  <h2>
                    {title} <span class="count">{members().length}</span>
                  </h2>
                </div>
                <For each={members()}>
                  {(name) => (
                    <ResourceDisclosure
                      class="agent-item"
                      open={props.expanded === name}
                      summary={
                        <>
                          <Icon name={kind} />
                          <strong class="collection-name" title={name}>
                            {name}
                          </strong>
                          <span class="collection-description">
                            {summaries().get(name)!.description}
                          </span>
                          <Show when={kind !== "devices"}>
                            <span class="resource-meta">
                              {owner.labelStatus(
                                m.view()!,
                                m.view()!.labels[name],
                              )}
                            </span>
                          </Show>
                          <span class="collection-chevron">
                            <Icon name="arrow" />
                          </span>
                        </>
                      }
                    >
                      {() => (
                        <div class="agent-inline">
                          <Show when={kind !== "devices"}>
                            <AgentAccess name={name} />
                          </Show>
                          <AgentSettings name={name} />
                        </div>
                      )}
                    </ResourceDisclosure>
                  )}
                </For>
              </div>
            </Show>
          );
        }}
      </For>
      <Show when={!names().length}>
        <div class="resource-list">
          <Empty
            title={query() ? "No matching agents" : "No agents yet"}
            action={
              <Show when={!query()}>
                <a class="button primary" href="#pair">
                  <Icon name="plus" />
                  Add agent
                </a>
              </Show>
            }
          >
            Add an agent with its SSH public key to configure access.
            <Show when={!query()}>
              <br />
              If your sandbox is missing, run{" "}
              <code>tinfoil attest-ssh &lt;sandbox-name&gt;</code>.
            </Show>
          </Empty>
        </div>
      </Show>
    </>
  );
}
export function AddAgent() {
  const m = useMonitor(),
    [name, setName] = createSignal(""),
    [key, setKey] = createSignal("");
  const submit = async (event: SubmitEvent) => {
    event.preventDefault();
    try {
      if (!name().trim()) throw new Error("Enter an agent name.");
      if (m.view()!.config.identities?.[name().trim()])
        throw new Error("An agent already uses this name.");
      await m.edit(
        owner.edits.pairAgent(name().trim(), key()),
        href("agents", name().trim()),
      );
    } catch (cause) {
      m.report(cause);
    }
  };
  return (
    <form onSubmit={submit} class="connection-fields">
      <label>
        Agent name
        <input
          required
          value={name()}
          onInput={(e) => setName(e.currentTarget.value)}
          autocomplete="off"
        />
      </label>
      <label>
        SSH public key
        <textarea
          required
          rows={3}
          value={key()}
          onInput={(e) => setKey(e.currentTarget.value)}
          placeholder="ssh-ed25519 …"
        />
      </label>
      <button class="primary" disabled={m.busy()}>
        Add agent
      </button>
    </form>
  );
}
function Actions(props: {
  name: string;
  account: string;
  nodes: owner.AccessNode[];
}) {
  const m = useMonitor();
  const nodes = createMemo(
    () => new Map(props.nodes.map((node) => [node.key, node])),
  );
  return (
    <For each={[...nodes().keys()]}>
      {(key) => {
        const node = () => nodes().get(key)!;
        const controls = () => (
          <>
            <span
              class="access-action-title"
              classList={{ "access-group-title": !!node().children.length }}
              title={node().effects.join(", ")}
            >
              {node().title}
              <Show when={node().overrides}>
                {" "}
                <small class="muted">{node().overrides} overrides</small>
              </Show>
            </span>
            <Permission
              label={key}
              value={node().own}
              inherited={node().inherited}
              onChange={(value) =>
                void m.edit(
                  owner.edits.setAccess(props.name, props.account, {
                    actions: { [key]: value },
                  }),
                )
              }
            />
          </>
        );
        return (
          <Show
            when={node().children.length}
            fallback={<div class="access-action">{controls()}</div>}
          >
            <LazyDetails
              class="access-action-group"
              summaryClass="access-action"
              label={node().title}
              summary={controls()}
            >
              {() => (
                <div class="access-children">
                  <Actions
                    name={props.name}
                    account={props.account}
                    nodes={node().children}
                  />
                </div>
              )}
            </LazyDetails>
          </Show>
        );
      }}
    </For>
  );
}
// The same action editor is used from both the agent and connection lists.
export function AgentConnectionAccess(props: {
  name: string;
  account: string;
  title?: string;
}) {
  const m = useMonitor();
  const entry = createMemo(
    () => owner.agentAccess(m.view()!, props.name, props.account)[0],
  );
  const [expanded, setExpanded] = createSignal(false);
  const open = () => expanded() && entry().level !== "off";
  const id = createUniqueId();
  return (
    <div class="acct">
      <div class="row">
        <button
          class="access-toggle"
          type="button"
          aria-label={`Actions for ${props.title ?? props.account}`}
          aria-expanded={open()}
          aria-controls={id}
          disabled={entry().level === "off"}
          onClick={() => setExpanded(!expanded())}
        >
          <span
            class="access-caret"
            aria-hidden="true"
            classList={{ hidden: entry().level === "off", expanded: open() }}
          >
            <Icon name="arrow" />
          </span>
          <Show
            when={props.title}
            fallback={<ConnectorIcon preset={entry().preset} />}
          >
            <Icon name="agents" />
          </Show>
          <b title={props.title ?? props.account}>
            {props.title ?? props.account}
          </b>
          <Show when={entry().level !== "off" && entry().overrides}>
            <small class="muted">{entry().overrides} overrides</small>
          </Show>
        </button>
        <span
          class="seg access-level"
          role="group"
          aria-label={
            props.title
              ? `Access for ${props.title}`
              : `Default access for ${props.account}`
          }
        >
          <For each={entry().levels.map(([value]) => value)}>
            {(value) => (
              <button
                type="button"
                classList={{ primary: entry().level === value }}
                aria-pressed={entry().level === value}
                onClick={() => {
                  setExpanded(value !== "off");
                  const own =
                    m.view()!.config.identities?.[props.name]?.accounts?.[
                      props.account
                    ]?.level;
                  if (own !== value)
                    void m.edit(
                      owner.edits.setAccess(props.name, props.account, {
                        level: value,
                      }),
                    );
                }}
              >
                {owner.LEVELS[value]}
              </button>
            )}
          </For>
        </span>
      </div>
      <div
        id={id}
        class="access-disclosure"
        classList={{ expanded: open() }}
        inert={!open()}
        aria-hidden={!open()}
      >
        <div>
          <Show when={open()}>
            <div class="access-actions">
              <Actions
                name={props.name}
                account={props.account}
                nodes={entry().actions}
              />
            </div>
          </Show>
        </div>
      </div>
    </div>
  );
}
function AgentAccess(props: { name: string }) {
  const m = useMonitor();
  const label = () =>
    m.view()!.labels[props.name] ?? {
      trust: "trusted" as const,
      audience: "anyone" as const,
    };
  return (
    <div class="agent-access">
      <div class="agent-controls">
        <div class="labels">
          <For
            each={
              [
                ["trust", "Trust", owner.TRUSTS, "integrity"],
                // ["audience", "Audience", owner.AUDIENCES, "confidentiality"],
              ] as const
            }
          >
            {([key, title, values, lattice]) => (
              <Show when={owner.lattices(m.view()!)[lattice]}>
                <label>
                  <span>{title}</span>
                  <select
                    aria-label={title}
                    value={label()[key]}
                    onChange={(e) => {
                      void m.label(props.name, {
                        [key]: e.currentTarget.value as owner.Label[typeof key],
                      });
                    }}
                  >
                    <For each={Object.keys(values)}>
                      {(value) => (
                        <option value={value} selected={label()[key] === value}>
                          {values[value as keyof typeof values]}
                        </option>
                      )}
                    </For>
                  </select>
                </label>
              </Show>
            )}
          </For>
        </div>
      </div>
      <For
        each={Object.keys(m.view()!.config.accounts ?? {})}
        fallback={
          <p>
            No connections yet. <a href="#catalog">Add connection</a>
          </p>
        }
      >
        {(account) => (
          <AgentConnectionAccess name={props.name} account={account} />
        )}
      </For>
    </div>
  );
}
function SandboxAccess(props: { name: string }) {
  const m = useMonitor(),
    id = createUniqueId();
  return (
    <div class="setting-row agent-connectivity">
      <label for={id}>Sandbox access</label>
      <input
        id={id}
        type="checkbox"
        role="switch"
        aria-describedby={`${id}-description`}
        checked={m.view()!.config.identities?.[props.name]?.routes}
        onChange={(e) =>
          void m.edit(
            owner.edits.setRoutes(props.name, e.currentTarget.checked),
          )
        }
      />
      <p id={`${id}-description`}>
        Allows connections to sandboxes. Turning this off closes existing
        sessions.
      </p>
    </div>
  );
}
function AgentSettings(props: { name: string }) {
  if (owner.isDevice(props.name))
    return (
      <div class="agent-settings">
        <section>
          <SandboxAccess name={props.name} />
        </section>
      </div>
    );
  const m = useMonitor(),
    [key, setKey] = createSignal(""),
    [copyFrom, setCopyFrom] = createSignal(""),
    [instructions, setInstructions] = createSignal<string>();
  const reviewId = createUniqueId();
  const identity = () => m.view()!.config.identities?.[props.name];
  const copySources = () =>
    Object.keys(m.view()!.config.identities ?? {}).filter(
      (name) => name !== props.name && !owner.isDevice(name),
    );
  return (
    <div class="agent-settings">
      <Show when={identity()}>
        <section>
          <div class="setting-row agent-connectivity">
            <label for={reviewId}>Auto review requests with Tinfoil</label>
            <input
              id={reviewId}
              type="checkbox"
              role="switch"
              checked={!!identity()?.reviewer}
              onChange={(e) => {
                if (
                  e.currentTarget.checked &&
                  !owner.tinfoilConnection(m.view()!)
                ) {
                  e.currentTarget.checked = false;
                  location.hash = "#add/tinfoil";
                } else
                  void m.edit(
                    owner.edits.setReviewer(
                      m.view()!,
                      props.name,
                      e.currentTarget.checked,
                    ),
                  );
              }}
            />
          </div>
          <Show when={!!identity()?.reviewer && m.view()!.config.reviewer}>
            {(reviewer) => (
              <form
                onSubmit={async (e) => {
                  e.preventDefault();
                  if (
                    await m.edit(
                      owner.edits.setReviewerInstructions(instructions()!),
                    )
                  )
                    setInstructions();
                }}
              >
                <label>
                  Instructions
                  <textarea
                    required
                    rows={4}
                    value={instructions() ?? reviewer().instructions}
                    onInput={(e) => setInstructions(e.currentTarget.value)}
                  />
                </label>
                <button
                  class="primary"
                  disabled={m.busy() || !instructions()?.trim()}
                >
                  Save
                </button>
              </form>
            )}
          </Show>
        </section>
        <ResourceDisclosure
          class="connection-advanced agent-maintenance"
          summary={
            <span class="connection-advanced-text">
              <span class="connection-advanced-heading">
                <strong class="connection-advanced-title">
                  Setup &amp; maintenance
                </strong>
                <span class="collection-chevron">
                  <Icon name="arrow" />
                </span>
              </span>
              <small>Sandbox access and SSH keys</small>
            </span>
          }
        >
          {() => (
            <div class="connection-advanced-content">
              <section>
                <SandboxAccess name={props.name} />
              </section>
              <section>
                <h3>Host key</h3>
                <pre>{m.view()!.host_key}</pre>
                <h3>CA</h3>
                <pre>{m.view()!.ca}</pre>
              </section>
              <section>
                <h2>Replace SSH key</h2>
                <p>
                  Use this after recreating the sandbox. The agent starts clean.
                </p>
                <form
                  onSubmit={async (e) => {
                    e.preventDefault();
                    try {
                      if (
                        await m.edit(owner.edits.replaceKey(props.name, key()))
                      )
                        setKey("");
                    } catch (cause) {
                      m.report(cause);
                    }
                  }}
                >
                  <label>
                    New SSH public key
                    <textarea
                      aria-label="Replacement public key"
                      placeholder="ssh-ed25519 …"
                      required
                      rows={3}
                      value={key()}
                      onInput={(e) => setKey(e.currentTarget.value)}
                    />
                  </label>
                  <button class="primary" disabled={m.busy() || !key().trim()}>
                    Save replacement key
                  </button>
                </form>
              </section>
              <Show when={copySources().length}>
                <section>
                  <h2>Copy settings from another agent</h2>
                  <div class="agent-copy-settings">
                    <select
                      aria-label="Copy settings from"
                      value={copyFrom()}
                      onChange={(e) => setCopyFrom(e.currentTarget.value)}
                    >
                      <option value="">Choose agent</option>
                      <For each={copySources()}>
                        {(name) => <option>{name}</option>}
                      </For>
                    </select>
                    <button
                      disabled={!copyFrom() || m.busy()}
                      onClick={() =>
                        void m.edit(
                          owner.edits.copySettings(
                            m.view()!,
                            copyFrom(),
                            props.name,
                          ),
                        )
                      }
                    >
                      Copy settings
                    </button>
                  </div>
                </section>
              </Show>
              <section class="agent-remove">
                <div>
                  <h2>Remove agent</h2>
                  <p>Revokes this agent’s access to the monitor.</p>
                </div>
                <button
                  class="danger"
                  disabled={m.busy()}
                  onClick={async () => {
                    if (
                      confirm(`Remove agent ${props.name}?`) &&
                      (await m.edit(owner.edits.removeAgent(props.name)))
                    )
                      location.hash = "#agents";
                  }}
                >
                  Remove agent
                </button>
              </section>
            </div>
          )}
        </ResourceDisclosure>
      </Show>
    </div>
  );
}
