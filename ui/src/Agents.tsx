import { For, Show, createMemo, createSignal, createUniqueId } from "solid-js";
import type { JSX } from "solid-js";
import * as owner from "./owner.js";
import {
  ConnectorIcon,
  Empty,
  DisclosureHeading,
  SectionHeading,
  Icon,
  LazyDetails,
  Permission,
  ResourceDisclosure,
  href,
} from "./components";
import { useMonitor } from "./monitor";

export function Agents(props: { expanded?: string }) {
  const m = useMonitor();
  // Two kinds of row, nothing else: SANDBOXES are what the Monitor
  // contains and what you configure; TRUSTED DEVICES are your own keys
  // (enrolled by `tinfoil attest-ssh`) that may reach sandboxes through
  // the Monitor. Anything that is neither is listed with the sandboxes.
  const type = (name: string) => (owner.isDevice(name) ? "devices" : "sandboxes");
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
  const names = createMemo(() =>
    [
      ...new Set([...summaries().keys(), ...(m.options.sandboxes?.() ?? [])]),
    ].sort(),
  );
  return (
    <>
      <For
        each={[
          ["sandboxes", "Sandboxes", ""],
          ["devices", "Trusted devices", "Your own keys. They can SSH into sandboxes through the Monitor; nothing else applies to them."],
        ]}
      >
        {([kind, title, blurb]) => {
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
                            {summaries().get(name)?.description ??
                              "Not set up yet"}
                          </span>
                          <Show when={kind !== "devices"}>
                            <span class="resource-meta">
                              <Show when={summaries().has(name)}>
                                {owner.labelStatus(
                                  m.view()!,
                                  m.view()!.labels[name],
                                )}
                              </Show>
                              {m.options.sandboxStatus?.(name) ?? (
                                <Show when={summaries().has(name)}>
                                  <button
                                    type="button"
                                    class="icon-button open-shell"
                                    aria-label="Open shell"
                                    disabled={
                                      !m.view()!.config.allow_sandbox_ssh
                                    }
                                    title={
                                      m.view()!.config.allow_sandbox_ssh
                                        ? "Open shell"
                                        : "Enable browser terminals in Settings"
                                    }
                                    onClick={() => m.setShell(name)}
                                  >
                                    <Icon name="integrations" />
                                  </button>
                                </Show>
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
                            {m.options.sandboxActions?.(name)}
                          </Show>
                          <Show when={summaries().has(name)}>
                            <Show when={kind !== "devices"}>
                              <AgentAccess name={name} />
                            </Show>
                            <AgentSettings name={name} />
                          </Show>
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
            icon="sandboxes"
            title="Create your first sandbox"
            action={<AddSandbox class="button primary" />}
          >
            A sandbox runs your agent in an isolated environment. This monitor
            guards what it can reach and holds its credentials.
            <Show when={!m.options.onAddSandbox}>
              {" "}
              If yours is missing, run{" "}
              <code>tinfoil attest-ssh &lt;sandbox-name&gt;</code>.
            </Show>
          </Empty>
        </div>
      </Show>
    </>
  );
}
function AddSandbox(props: { class: string; children?: JSX.Element }) {
  const m = useMonitor();
  return (
    <Show
      when={m.options.onAddSandbox}
      fallback={
        <a
          class={props.class}
          href="https://dash.tinfoil.sh/"
          target="_blank"
          rel="noopener noreferrer"
        >
          <Icon name="plus" />
          Create sandbox
          {props.children}
        </a>
      }
    >
      <button
        type="button"
        class={props.class}
        onClick={() => m.options.onAddSandbox!()}
      >
        <Icon name="plus" />
        Create sandbox
      </button>
    </Show>
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
      const pub = key().trim();
      if (!/^(ssh-|ecdsa-)/.test(pub)) throw new Error("Paste an SSH public key.");
      const digest = new Uint8Array(
        await crypto.subtle.digest("SHA-256", new TextEncoder().encode(pub)),
      );
      const name =
        "device-" +
        [...digest.slice(0, 8)].map((b) => b.toString(16).padStart(2, "0")).join("");
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
          disabled={entry().level === "off"}
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
            classList={{ hidden: entry().level === "off", expanded: open() }}
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
                What this sandbox may do on the connection. Each can be set on
                its own.
              </p>
              <div class="access-actions">
                <Actions
                  name={props.name}
                  account={props.account}
                  nodes={entry().actions}
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
            No connections yet. <a href="#connections/catalog">Add connection</a>
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
                class="form-fields"
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
          class="section-disclosure agent-maintenance"
          summary={
            <DisclosureHeading
              title="Setup & maintenance"
              description="Sandbox access and SSH keys"
            />
          }
        >
          {() => (
            <div class="section-content">
              <section>
                <SandboxAccess name={props.name} />
              </section>
              <section class="settings-group">
                <SectionHeading title="Host key" small />
                <pre>{m.view()!.host_key}</pre>
                <SectionHeading title="CA" small />
                <pre>{m.view()!.ca}</pre>
              </section>
              <section class="settings-group">
                <SectionHeading
                  title="Replace SSH key"
                  description="Use this after recreating the sandbox. It starts clean."
                  small
                />
                <form
                  class="form-fields"
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
                <section class="settings-group">
                  <SectionHeading
                    title="Copy settings from another sandbox"
                    small
                  />
                  <div class="agent-copy-settings">
                    <select
                      aria-label="Copy settings from"
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
                      Copy settings
                    </button>
                  </div>
                </section>
              </Show>
              <section class="agent-remove">
                <SectionHeading
                  title="Remove sandbox"
                  description="Revokes this sandbox’s access to the Monitor."
                  small
                />
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
              </section>
            </div>
          )}
        </ResourceDisclosure>
      </Show>
    </div>
  );
}
