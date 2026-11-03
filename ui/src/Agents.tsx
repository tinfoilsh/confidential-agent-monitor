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
  ResourceDisclosure,
  SkeletonRows,
  href,
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
      <Show when={m.waiting().length}>
        <div class="resource-list">
          <div class="resource-heading">
            <h2>
              Waiting to join <span class="count">{m.waiting().length}</span>
            </h2>
          </div>
          <For each={m.waiting()}>
            {(name) => (
              <div class="resource-row waiting-row">
                <Icon name="sandboxes" />
                <strong class="collection-name" title={name}>
                  {name}
                </strong>
                <span class="collection-description">
                  Accepting adds it to this Monitor and unlocks its workspace
                </span>
                <button
                  type="button"
                  class="primary"
                  disabled={!!m.accepting()}
                  aria-busy={m.accepting() === name}
                  onClick={() => void m.accept(name)}
                >
                  {m.accepting() === name ? "Accepting…" : "Accept"}
                </button>
              </div>
            )}
          </For>
        </div>
      </Show>
      <For
        each={[
          ["sandboxes", "Sandboxes", ""],
          ["devices", "Trusted devices", ""],
        ]}
      >
        {([kind, title, blurb]) => {
          const members = createMemo(() =>
            names().filter((name) => type(name) === kind),
          );
          return (
            <Show
              when={
                members().length ||
                kind === "devices" ||
                (kind === "sandboxes" && m.sandboxesLoading())
              }
            >
              <div class="resource-list collection-list">
                <div class="resource-heading">
                  <h2>
                    {title}{" "}
                    <span class="count">
                      {kind === "sandboxes" &&
                      m.sandboxesLoading() &&
                      !members().length
                        ? "…"
                        : members().length}
                    </span>
                  </h2>
                  <Show when={blurb}>
                    <span class="muted">{blurb}</span>
                  </Show>
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
                <Show
                  when={
                    kind === "sandboxes" &&
                    m.sandboxesLoading() &&
                    !members().length
                  }
                >
                  <SkeletonRows label="Loading your sandboxes…" />
                </Show>
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
                                  onClick={() => m.setShell(name)}
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
// Action rows show the action setting and nothing else: the sandbox-level
// access is the default for anything unset, and the Payments switches act
// under the hood without appearing here. A group (Inference, Use…) sets all
// of its children when clicked; a child sets only itself, and a group whose
// children disagree shows no value.
function Actions(props: {
  name: string;
  account: string;
  nodes: owner.AccessNode[];
  level: string;
  actions: Record<string, owner.Mode | undefined>;
  readOnly?: boolean;
  nested?: boolean;
}) {
  const m = useMonitor();
  // Effective action mode, ignoring effects: own entry, nearest ancestor's
  // entry, else what the sandbox-level access implies for actions.
  const fromLevel = (): owner.Mode =>
    props.level === "allow" || props.level === "read"
      ? "allow"
      : props.level === "ask"
        ? "ask"
        : "off";
  const resolve = (key: string): owner.Mode => {
    const parts = key.split(".");
    for (let i = parts.length; i > 0; i--) {
      const own = props.actions[parts.slice(0, i).join(".")];
      if (own) return own;
    }
    return fromLevel();
  };
  const leaves = (node: owner.AccessNode): string[] =>
    node.children.length ? node.children.flatMap(leaves) : [node.key];
  // A group's value is its children's, when they agree.
  const display = (node: owner.AccessNode): owner.Mode | null => {
    if (!node.children.length) return resolve(node.key);
    const values = new Set(leaves(node).map(resolve));
    return values.size === 1 ? [...values][0] : null;
  };
  const descendants = (node: owner.AccessNode): string[] => [
    node.key,
    ...node.children.flatMap(descendants),
  ];
  const set = (node: owner.AccessNode, value: owner.Mode) => {
    // Clear below, set here: children follow their group again.
    const actions: Record<string, owner.Mode | null> = Object.fromEntries(
      descendants(node).map((k) => [k, null]),
    );
    actions[node.key] = value;
    void m.edit(owner.edits.setAccess(props.name, props.account, { actions }));
  };
  // Keyed by action name: node objects are rebuilt on every view update,
  // and keying by them would recreate (and close) the rows.
  const byKey = createMemo(() => new Map(props.nodes.map((n) => [n.key, n])));
  return (
    <For each={[...byKey().keys()]}>
      {(key) => {
        const node = () => byKey().get(key)!;
        const value = () => display(node());
        // A group with a single child is shown open, with the child's
        // control only: there is nothing to set at the group.
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
              <span
                class="seg access-mode"
                classList={{ small: !!props.nested, mixed: value() === null }}
                role="group"
                aria-label={`${node().title} permission`}
              >
                <For each={Object.keys(owner.MODES) as owner.Mode[]}>
                  {(mode) => (
                    <button
                      type="button"
                      classList={{ primary: value() === mode }}
                      aria-pressed={value() === mode}
                      title={
                        value() === null && node().children.length
                          ? "Children differ. Click to set them all."
                          : owner.MODES[mode]
                      }
                      onClick={(e) => {
                        e.preventDefault();
                        e.stopPropagation();
                        if (value() !== mode) set(node(), mode);
                      }}
                    >
                      {owner.MODES[mode]}
                    </button>
                  )}
                </For>
              </span>
            </Show>
          </>
        );
        const children = () => (
          <div class="access-children">
            <Actions
              name={props.name}
              account={props.account}
              nodes={node().children}
              level={props.level}
              actions={props.actions}
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
  // A single action is the same dial as the access level: it is named but
  // not set separately.
  const singleAction = () => {
    const nodes = entry().actions;
    return nodes.length === 1 && !nodes[0].children.length;
  };
  const expandable = () => entry().level !== "off";
  const open = () => expanded() && expandable();
  const id = createUniqueId();
  // Rules: saved approvals for THIS agent on THIS connection — an action
  // plus specific parameters, narrower than the per-action settings below.
  const rules = createMemo(() =>
    Object.entries(
      m.view()!.config.identities?.[props.name]?.rules ?? {},
    ).filter(([, rule]) => rule.account === props.account),
  );
  return (
    <div class="acct">
      <div class="row">
        <button
          class="access-toggle"
          type="button"
          aria-label={`Actions for ${props.title ?? props.account}`}
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
          <b title={props.title ?? props.account}>
            {props.title ?? props.account}
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
            <div class="access-block">
              <h4>Actions</h4>
              <p class="muted">
                <Show
                  when={singleAction()}
                  fallback="What can be done through the connection"
                >
                  What can be done through the connection
                </Show>
              </p>
              <div class="access-actions">
                <Actions
                  name={props.name}
                  account={props.account}
                  nodes={entry().actions}
                  level={entry().level}
                  actions={
                    m.view()!.config.identities?.[props.name]?.accounts?.[
                      props.account
                    ]?.actions ?? {}
                  }
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
                      <span>
                        <strong>{owner.ruleTitle(m.view()!, rule)}</strong>
                        <small>
                          <For
                            each={Object.entries(rule.scope ?? {})}
                            fallback="Any request"
                          >
                            {([key, value]) => {
                              const text = `${key}: ${typeof value === "string" ? value : JSON.stringify(value)}`;
                              return <code title={text}>{text}</code>;
                            }}
                          </For>
                        </small>
                      </span>
                      <button
                        disabled={m.busy()}
                        onClick={(e) => {
                          e.preventDefault();
                          void m.edit(owner.edits.removeRule(props.name, id));
                        }}
                      >
                        Remove
                      </button>
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
        each={Object.keys(m.view()!.config.accounts ?? {})}
        fallback={
          <p>
            No connections yet.{" "}
            <a href="#connections/catalog">Add connection</a>
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
    Object.keys(m.view()!.config.identities ?? {}).filter(
      (name) => name !== props.name && !owner.isDevice(name),
    );
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
