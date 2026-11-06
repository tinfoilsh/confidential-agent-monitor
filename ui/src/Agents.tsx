import { For, Show, createMemo, createSignal, createUniqueId } from "solid-js";
import type { JSX } from "solid-js";
import * as owner from "./owner.js";
import {
  Copy,
  ConnectorIcon,
  Empty,
  DisclosureHeading,
  Icon,
  LazyDetails,
  RemoveRule,
  ResourceDisclosure,
  RuleText,
  SkeletonRows,
  href,
  TabBar,
} from "./components";
import { useMonitor } from "./monitor";

export function Agents(props: { expanded?: string }) {
  const m = useMonitor();
  // Two kinds of row, nothing else: SANDBOXES are what the Monitor
  // contains and what you configure; TRUSTED DEVICES are your own keys
  // (enrolled by `tinfoil attest-ssh`) that may reach sandboxes through
  // the Monitor. Anything that is neither is listed with the sandboxes.
  const type = (name: string) =>
    owner.isDevice(name) ? "devices" : "sandboxes";
  const summaries = createMemo(() => {
    const view = m.view()!;
    return new Map(
      Object.keys(view.config.identities ?? {})
        .sort()
        .map((name) => {
          const description = owner.isDevice(name)
            ? view.config.identities![name].routes
              ? "Can reach sandboxes"
              : "Sandbox access off"
            : `${owner.agentAccess(view, name).filter((access) => access.level !== "off").length} connections`;
          return [name, { description }];
        }),
    );
  });
  const names = createMemo(() => [...summaries().keys()]);
  return (
    <>
      <Show
        when={!m.sandboxesLoading() && !names().length && !m.waiting().length}
      >
        <div class="resource-list">
          <Empty
            icon="sandboxes"
            title="Create your first sandbox"
            action={<AddSandbox class="button primary" />}
          >
            A sandbox runs your agent in an isolated environment. This monitor
            guards what it can reach and holds its credentials. If yours is
            missing, run <code>tinfoil attest-ssh &lt;sandbox-name&gt;</code>.
          </Empty>
        </div>
      </Show>
      <For
        each={
          [
            ["sandboxes", "Sandboxes"],
            ["devices", "Trusted devices"],
          ] as const
        }
      >
        {([kind, title]) => {
          const members = createMemo(() =>
            names().filter((name) => type(name) === kind),
          );
          const waiting = () => (kind === "sandboxes" ? m.waiting() : []);
          const loading = () =>
            kind === "sandboxes" &&
            m.sandboxesLoading() &&
            !members().length &&
            !waiting().length;
          return (
            <Show when={members().length || waiting().length || loading()}>
              <div class="resource-list collection-list">
                <div class="resource-heading">
                  <h2>
                    {title}{" "}
                    <span class="count">
                      {loading() ? "…" : members().length + waiting().length}
                    </span>
                  </h2>
                  <Show
                    when={kind === "devices"}
                    fallback={
                      <AddSandbox class="button">
                        <Icon name="external" />
                      </AddSandbox>
                    }
                  >
                    <a class="button" href="#pair">
                      <Icon name="plus" />
                      Add trusted device
                    </a>
                  </Show>
                </div>
                <Show when={loading()}>
                  <SkeletonRows label="Loading your sandboxes…" />
                </Show>
                <For each={waiting()}>
                  {(name) => {
                    const manual = () =>
                      m.stalled().includes(name) && m.accepting() !== name;
                    return (
                      <div class="resource-row waiting-row">
                        <Icon name="sandboxes" />
                        <strong class="collection-name" title={name}>
                          {name}
                        </strong>
                        <Show
                          when={manual()}
                          fallback={
                            <span class="loading-spinner" aria-hidden="true" />
                          }
                        >
                          <span class="collection-description">
                            Accepting adds it to this Monitor and unlocks its
                            workspace
                          </span>
                          <button
                            type="button"
                            class="primary"
                            disabled={!!m.accepting()}
                            onClick={() => void m.accept(name)}
                          >
                            Accept
                          </button>
                        </Show>
                      </div>
                    );
                  }}
                </For>
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
                            {summaries().get(name)?.description}
                          </span>
                          <Show when={kind !== "devices"}>
                            <span class="resource-meta">
                              <Show when={m.shellFor(name)}>
                                <button
                                  type="button"
                                  class="icon-button open-shell"
                                  aria-label="Open shell"
                                  title="Open shell"
                                  onClick={() => {
                                    location.hash = href(
                                      "agents",
                                      name,
                                      "terminal",
                                    );
                                  }}
                                >
                                  <Icon name="integrations" />
                                </button>
                              </Show>
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
    </>
  );
}
function AddSandbox(props: { class: string; children?: JSX.Element }) {
  return (
    <a
      class={props.class}
      href="https://dash.tinfoil.sh/?tab=sandboxes"
      target="_blank"
      rel="noopener noreferrer"
    >
      <Icon name="plus" />
      Create sandbox
      {props.children}
    </a>
  );
}
// Adds a TRUSTED DEVICE: your own key, allowed to reach sandboxes through
// the Monitor. Named like the CLI names them (`device-<hash>`) so it sorts
// with the others; no connection grid. Sandboxes come from the dashboard.
export function AddAgent() {
  const m = useMonitor(),
    [key, setKey] = createSignal("");
  const submit = async (event: SubmitEvent) => {
    event.preventDefault();
    try {
      // Same name the CLI derives: SHA-256 of "<type> <base64>", comment
      // dropped, so a key added here and one enrolled by attest-ssh agree.
      const [type, blob] = key().trim().split(/\s+/);
      if (!/^(ssh-|ecdsa-)/.test(type ?? "") || !blob)
        throw new Error("Paste an SSH public key.");
      const pub = `${type} ${blob}`;
      const digest = new Uint8Array(
        await crypto.subtle.digest("SHA-256", new TextEncoder().encode(pub)),
      );
      const name =
        "device-" +
        [...digest.slice(0, 8)]
          .map((b) => b.toString(16).padStart(2, "0"))
          .join("");
      if (m.view()!.config.identities?.[name])
        throw new Error("This key is already a trusted device.");
      await m.edit(owner.edits.pairDevice(name, pub), href("agents", name));
    } catch (cause) {
      m.report(cause);
    }
  };
  return (
    <form onSubmit={submit} class="form-fields">
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
      <p class="muted">
        This key will be able to SSH into your sandboxes through the Monitor.
      </p>
      <button class="primary" disabled={m.busy()}>
        Add trusted device
      </button>
    </form>
  );
}
// Rows show action settings only; effects such as Payments apply separately.
function Actions(props: {
  name: string;
  connection: string;
  nodes: owner.AccessNode[];
  readOnly?: boolean;
  nested?: boolean;
}) {
  const m = useMonitor();
  const leaves = (node: owner.AccessNode): owner.Mode[] =>
    node.children.length ? node.children.flatMap(leaves) : [node.mode];
  const display = (node: owner.AccessNode): owner.Mode | null => {
    const values = new Set(leaves(node));
    return values.size === 1 ? [...values][0] : null;
  };
  const descendants = (node: owner.AccessNode): string[] => [
    node.key,
    ...node.children.flatMap(descendants),
  ];
  const set = (node: owner.AccessNode, value: owner.Mode) => {
    const actions: Record<string, owner.Mode | null> = Object.fromEntries(
      descendants(node).map((k) => [k, null]),
    );
    actions[node.key] = value;
    void m.edit(
      owner.edits.setAccess(props.name, props.connection, { actions }),
    );
  };
  // Keyed by action name: node objects are rebuilt on every view update,
  // and keying by them would recreate (and close) the rows.
  const byKey = createMemo(() => new Map(props.nodes.map((n) => [n.key, n])));
  return (
    <For each={[...byKey().keys()]}>
      {(key) => {
        const node = () => byKey().get(key)!;
        const value = () => display(node());
        const single = () => node().children.length === 1;
        const controls = () => (
          <>
            <span
              class="access-action-title"
              classList={{ "access-group-title": !!node().children.length }}
            >
              {node().title}
            </span>
            <Show when={!props.readOnly && !single()}>
              <TabBar
                class="access-mode"
                small={!!props.nested}
                label={`${node().title} permission`}
                value={value()}
                options={(Object.keys(owner.MODES) as owner.Mode[]).map(
                  (mode) => ({
                    value: mode,
                    label: owner.MODES[mode],
                    title:
                      value() === null && node().children.length
                        ? "Children differ. Click to set them all."
                        : owner.MODES[mode],
                  }),
                )}
                onChange={(mode) => {
                  if (value() !== mode) set(node(), mode);
                }}
              />
            </Show>
          </>
        );
        const children = () => (
          <div class="access-children">
            <Actions
              name={props.name}
              connection={props.connection}
              nodes={node().children}
              nested
            />
          </div>
        );
        return (
          <Show
            when={node().children.length}
            fallback={<div class="access-action">{controls()}</div>}
          >
            <Show
              when={!single()}
              fallback={
                <div class="access-action-group access-action-single">
                  <div class="access-action">{controls()}</div>
                  {children()}
                </div>
              }
            >
              <LazyDetails
                class="access-action-group"
                summaryClass="access-action"
                label={node().title}
                summary={controls()}
              >
                {children}
              </LazyDetails>
            </Show>
          </Show>
        );
      }}
    </For>
  );
}
export function AgentConnectionAccess(props: {
  name: string;
  connection: string;
  title?: string;
}) {
  const m = useMonitor();
  const entry = createMemo(
    () => owner.agentAccess(m.view()!, props.name, props.connection)[0],
  );
  const [expanded, setExpanded] = createSignal(false);
  const singleAction = () => {
    const nodes = entry().actions;
    return nodes.length === 1 && !nodes[0].children.length;
  };
  const expandable = () => entry().level !== "off";
  const open = () => expanded() && expandable();
  const id = createUniqueId();
  const rules = createMemo(() =>
    Object.entries(
      m.view()!.config.identities?.[props.name]?.rules ?? {},
    ).filter(([, rule]) => rule.connection === props.connection),
  );
  return (
    <div class="acct">
      <div class="row">
        <button
          class="access-toggle"
          type="button"
          aria-label={`Actions for ${props.title ?? props.connection}`}
          aria-expanded={open()}
          aria-controls={id}
          disabled={!expandable()}
          onClick={() => setExpanded(!expanded())}
        >
          <Show
            when={props.title}
            fallback={<ConnectorIcon preset={entry().preset} />}
          >
            <Icon name="agents" />
          </Show>
          <b title={props.title ?? props.connection}>
            {props.title ?? props.connection}
          </b>
          <span
            class="access-caret"
            aria-hidden="true"
            classList={{ hidden: !expandable(), expanded: open() }}
          >
            <Icon name="arrow" />
          </span>
          <Show when={entry().level !== "off" && entry().overrides}>
            <small class="muted">
              {entry().overrides}{" "}
              {entry().overrides === 1 ? "action set" : "actions set"}
            </small>
          </Show>
          <Show when={rules().length}>
            <small class="muted">
              {rules().length} {rules().length === 1 ? "rule" : "rules"}
            </small>
          </Show>
        </button>
        <TabBar
          class="access-level"
          label={`Access for ${props.title ?? props.connection}`}
          value={entry().level}
          options={entry().levels.map(([value]) => ({
            value,
            label: owner.LEVELS[value],
          }))}
          onChange={(value) => {
            setExpanded(value !== "off");
            const own =
              m.view()!.config.identities?.[props.name]?.connections?.[
                props.connection
              ]?.level;
            if (own !== value)
              void m.edit(
                owner.edits.setAccess(props.name, props.connection, {
                  level: value,
                }),
              );
          }}
        />
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
            <div class="access-block">
              <h4>Actions</h4>
              <p class="muted">What can be done through the connection</p>
              <div class="access-actions">
                <Actions
                  name={props.name}
                  connection={props.connection}
                  nodes={entry().actions}
                  readOnly={singleAction()}
                />
              </div>
            </div>
            <Show when={rules().length}>
              <div class="access-block access-rules">
                <h4>Rules</h4>
                <p class="muted">
                  Narrow, least-scoped actions you approved and saved.
                </p>
                <For each={rules()}>
                  {([id, rule]) => (
                    <a class="access-rule" href="#activity/rules">
                      <RuleText rule={rule} />
                      <RemoveRule agent={props.name} id={id} />
                      <Icon name="arrow" />
                    </a>
                  )}
                </For>
              </div>
            </Show>
          </Show>
        </div>
      </div>
    </div>
  );
}
function AgentAccess(props: { name: string }) {
  const m = useMonitor();
  return (
    <div class="agent-access">
      <For
        each={Object.keys(m.view()!.config.connections ?? {})}
        fallback={
          <p>
            No connections yet.{" "}
            <a href="#connections/catalog">Add connection</a>
          </p>
        }
      >
        {(connection) => (
          <AgentConnectionAccess name={props.name} connection={connection} />
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
        Turning this off closes existing SSH sessions.
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
    [copyFrom, setCopyFrom] = createSignal("");
  const identity = () => m.view()!.config.identities?.[props.name];
  const copySources = () =>
    owner.sandboxNames(m.view()!).filter((name) => name !== props.name);
  return (
    <div class="agent-settings">
      <Show when={identity()}>
        <ResourceDisclosure
          class="section-disclosure agent-maintenance"
          summary={
            <DisclosureHeading
              title="Advanced"
              description="Monitor keys, profile and removal"
              small
            />
          }
        >
          {() => (
            <div class="section-content agent-advanced">
              <div class="setting-row">
                <span>
                  Monitor keys
                  <small>Only needed if you set up SSH by hand.</small>
                </span>
                <span class="agent-advanced-actions">
                  <span class="key-pill" title={m.view()!.host_key}>
                    <span class="key-pill-label">Host key</span>
                    <code>{m.view()!.host_key.trim().slice(0, 24)}…</code>
                    <Copy
                      icon
                      text={m.view()!.host_key.trim()}
                      label="Copy host key"
                    />
                  </span>
                  <span class="key-pill">
                    <span class="key-pill-label">CA certificate</span>
                    <Copy
                      icon
                      text={m.view()!.ca}
                      label="Copy CA certificate"
                    />
                  </span>
                </span>
              </div>
              <Show when={copySources().length}>
                <div class="setting-row">
                  <span>
                    Copy sandbox profile
                    <small>
                      Takes its connection access, actions and rules.
                    </small>
                  </span>
                  <span class="agent-advanced-actions">
                    <select
                      aria-label="Copy profile from"
                      value={copyFrom()}
                      onChange={(e) => setCopyFrom(e.currentTarget.value)}
                    >
                      <option value="">Choose sandbox</option>
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
                      Override
                    </button>
                  </span>
                </div>
              </Show>
              <div class="setting-row">
                <span>
                  Remove sandbox
                  <small>
                    Forget this sandbox from the Monitor, along with its
                    connections and rules.
                  </small>
                </span>
                <button
                  class="danger"
                  disabled={m.busy()}
                  onClick={async () => {
                    if (
                      confirm(`Remove sandbox ${props.name}?`) &&
                      (await m.edit(owner.edits.removeAgent(props.name)))
                    )
                      location.hash = "#agents";
                  }}
                >
                  Remove sandbox
                </button>
              </div>
            </div>
          )}
        </ResourceDisclosure>
      </Show>
    </div>
  );
}
