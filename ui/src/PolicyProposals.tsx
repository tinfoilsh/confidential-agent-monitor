import { For, Show, createMemo, onMount } from "solid-js";
import * as owner from "./owner.js";
import {
  ConnectorIcon,
  Icon,
  ResourceDisclosure,
  createRecord,
} from "./components";
import { useMonitor } from "./monitor";
import "./policy-proposals.css";

function ProposerByline(props: { proposal: owner.RequestRecord }) {
  return (
    <>
      <strong>By {owner.isDevice(props.proposal.facts.principal.name) ? "trusted device" : "bunker"}:</strong>{" "}
      {props.proposal.facts.principal.name}
    </>
  );
}
const reasonPreview = (reason: string, limit = 50) =>
  reason.length <= limit ? reason : reason.slice(0, limit - 1).trimEnd() + "…";
const at = (value: unknown, path: string[]) => {
  let current = value as any;
  for (const key of path) {
    if (!current || typeof current !== "object" || !Object.hasOwn(current, key))
      return undefined;
    current = current[key];
  }
  return current as owner.Json;
};
type Leaf = { path: string[]; value?: owner.Json; removed?: boolean };
type Item = {
  label: string;
  kind?: "level" | "mode" | "audience" | "trust" | "preset";
  leaf: Leaf;
};
// A change that sets a table sets every setting beneath it.
const leaves = (change: owner.Change): Leaf[] => {
  const value = change.value;
  return !change.delete &&
    value &&
    typeof value === "object" &&
    !Array.isArray(value) &&
    Object.keys(value).length
    ? Object.entries(value).flatMap(([key, inner]) =>
        leaves({ path: [...change.path, key], value: inner }),
      )
    : [{ path: change.path, value, removed: change.delete }];
};
const ALL_BUNKERS = "All bunkers";
const AUDIENCES: { [A in owner.Audience]: string } = {
  me: "Only me",
  team: "My team",
  anyone: "Anyone",
};
const LEVEL_NOTES: { [L in owner.GrantLevel]: string } = {
  off: "Nothing is allowed.",
  read: "Reads go through; everything else is denied.",
  ask: "Reads go through; everything else asks you first.",
  allow:
    "Requests go through, except publishing, payments, and unrecognized requests, which ask you first.",
};
// How a connection handles data, as its settings name it.
const ANSWERS: Record<string, Pick<Item, "label" | "kind">> = {
  preset: { label: "Type", kind: "preset" },
  contents: { label: "Confidentiality", kind: "audience" },
  sends: { label: "Visibility", kind: "audience" },
  strangers: { label: "Data source", kind: "trust" },
};
const accessItem = (
  [kind, name]: string[],
  leaf: Leaf,
  actions: owner.Preset["actions"],
): Item =>
  kind === "actions" || kind === "effects"
    ? {
        label: (kind === "actions" && actions?.[name]?.title) || name,
        kind: "mode",
        leaf,
      }
    : { label: "Access", kind: kind === "level" ? "level" : undefined, leaf };
// Every changed setting, split into the connection's own setup and who may use it.
function changeGroups(view: owner.View, record: owner.RequestRecord) {
  const name = record.facts.connection;
  const preset = view.presets[proposalPreset(record, view)];
  const setup: Item[] = [],
    other: Item[] = [],
    access = new Map<string, Item[]>();
  const grant = (who: string, item: Item) =>
    access.set(who, [...(access.get(who) ?? []), item]);
  for (const leaf of (record.changes ?? []).flatMap(leaves)) {
    const [root, a, b, c, ...rest] = leaf.path;
    if (root === "connections" && a === name) {
      const setting = leaf.path.slice(2).join("/");
      const field = preset?.fields?.find((f) =>
        (f.paths ?? [f.path ?? []]).some((p) => p.join("/") === setting),
      );
      setup.push({
        ...(ANSWERS[setting] ?? {
          label: field?.label ?? leaf.path.slice(2).join(" › "),
        }),
        leaf,
      });
    } else if (root === "default_access" && a === name)
      grant(ALL_BUNKERS, accessItem(leaf.path.slice(2), leaf, preset?.actions));
    else if (root === "identities" && b === "connections" && c === name)
      grant(a, accessItem(rest, leaf, preset?.actions));
    else other.push({ label: leaf.path.join(" › "), leaf });
  }
  return { setup, access: [...access], other };
}
const itemText = (view: owner.View, item: Item, value: owner.Json) =>
  item.kind === "level"
    ? (owner.LEVELS[value as owner.GrantLevel] ?? String(value))
    : item.kind === "mode"
      ? (owner.MODES[value as owner.Mode] ?? String(value))
      : item.kind === "audience"
        ? (AUDIENCES[value as owner.Audience] ?? String(value))
        : item.kind === "trust"
          ? value
            ? "Untrusted"
            : "Trusted"
          : item.kind === "preset"
            ? (view.presets[value as string]?.title ?? String(value))
            : typeof value === "boolean"
              ? value
                ? "Yes"
                : "No"
              : typeof value === "object"
                ? JSON.stringify(value, null, 2)
                : String(value) || "Empty";
export const proposalPreset = (proposal: owner.RequestRecord, view: owner.View) => {
  for (const change of proposal.changes ?? []) {
    if (
      change.path.join("/") ===
        `connections/${proposal.facts.connection}/preset` &&
      typeof change.value === "string"
    )
      return change.value;
    if (
      change.path.length === 2 &&
      change.path[0] === "connections" &&
      change.path[1] === proposal.facts.connection
    ) {
      const connection = change.value as { preset?: owner.Json } | undefined;
      if (typeof connection?.preset === "string") return connection.preset;
    }
  }
  return view.config.connections?.[proposal.facts.connection]?.preset ?? "";
};
function ProposalSummary(props: {
  proposal: owner.RequestRecord;
  class?: string;
}) {
  const m = useMonitor();
  return (
    <>
      <ConnectorIcon preset={proposalPreset(props.proposal, m.view()!)} />
      <span class={props.class}>
        <strong>{reasonPreview(props.proposal.facts.title ?? "")}</strong>
        <small>
          {props.proposal.facts.connection} ·{" "}
          {props.proposal.facts.principal.name}
        </small>
      </span>
    </>
  );
}
function ProposalBadge(props: { proposal: owner.RequestRecord }) {
  const m = useMonitor();
  return (
    <Show
      when={m.view()!.config.connections?.[props.proposal.facts.connection]}
      fallback={<span class="badge proposal-kind status-new">New</span>}
    >
      <span class="badge proposal-kind status-pending">Update</span>
    </Show>
  );
}

function TechnicalDiff(props: { text: string }) {
  const lines = () =>
    (props.text || "No source changes.")
      .split("\n")
      .filter(
        (line) =>
          !line.startsWith("@@") &&
          !line.startsWith("--- active/") &&
          !line.startsWith("+++ proposed/"),
      );
  const kind = (line: string) =>
    line.startsWith("+")
      ? "diff-added"
      : line.startsWith("-")
        ? "diff-removed"
        : "";
  return (
    <pre class="proposal-diff-lines">
      <For each={lines()}>
        {(line) => (
          <span class={`proposal-diff-line ${kind(line)}`}>{line || " "}</span>
        )}
      </For>
    </pre>
  );
}

function ChangeValue(props: { item: Item; before?: owner.Json }) {
  const m = useMonitor();
  const after = () =>
    props.item.leaf.removed ? undefined : props.item.leaf.value;
  const list = (value?: owner.Json) => (Array.isArray(value) ? value : []);
  const text = (value: owner.Json) => itemText(m.view()!, props.item, value);
  return (
    <Show
      when={Array.isArray(props.before) || Array.isArray(after())}
      fallback={
        <span class="proposal-value">
          <Show
            when={
              props.before !== undefined &&
              JSON.stringify(props.before) !== JSON.stringify(after())
            }
          >
            <del>{text(props.before!)}</del>
            <span aria-hidden="true">→</span>
          </Show>
          <Show
            when={after() !== undefined}
            fallback={<span class="diff-removed">Removed</span>}
          >
            <ins>{text(after()!)}</ins>
          </Show>
        </span>
      }
    >
      <span class="proposal-value proposal-chips">
        <For
          each={list(props.before).filter(
            (entry) => !list(after()).includes(entry),
          )}
        >
          {(entry) => <del class="badge diff-removed">{String(entry)}</del>}
        </For>
        <For each={list(after())}>
          {(entry) => (
            <span
              class="badge"
              classList={{
                "diff-added":
                  props.before !== undefined &&
                  !list(props.before).includes(entry),
              }}
            >
              {String(entry)}
            </span>
          )}
        </For>
      </span>
    </Show>
  );
}

// What a proposal changes, in the owner's terms, then the exact source diff.
export function ProposalChanges(props: { record: owner.RequestRecord }) {
  const m = useMonitor();
  const groups = createMemo(() => changeGroups(m.view()!, props.record));
  const preset = () => proposalPreset(props.record, m.view()!);
  const added = () => groups().setup.some((item) => item.kind === "preset");
  const removed = () =>
    groups().setup.some((item) => item.leaf.path.length === 2);
  const Facts = (facts: { items: Item[] }) => (
    <ul class="proposal-facts">
      <For each={facts.items}>
        {(item) => (
          <li>
            <span class="proposal-label">{item.label}</span>
            <ChangeValue
              item={item}
              // Only a pending proposal still applies to the settings shown as current.
              before={
                props.record.state === "pending"
                  ? at(m.view()!.config, item.leaf.path)
                  : undefined
              }
            />
          </li>
        )}
      </For>
    </ul>
  );
  return (
    <>
      <Show when={groups().setup.length}>
        <section class="proposal-group">
          <header class="proposal-connection">
            <ConnectorIcon preset={preset()} />
            <span class="proposal-summary">
              <strong>{props.record.facts.connection}</strong>
              <small>{m.view()!.presets[preset()]?.title}</small>
            </span>
            <span
              class="badge"
              classList={{ "status-new": added(), "status-denied": removed() }}
            >
              {added()
                ? "New connection"
                : removed()
                  ? "Removes this connection"
                  : "Changes settings"}
            </span>
          </header>
          <Facts
            items={groups().setup.filter(
              (item) => item.kind !== "preset" && item.leaf.path.length > 2,
            )}
          />
        </section>
      </Show>
      <Show when={groups().access.length}>
        <section class="proposal-group">
          <h4>Access to {props.record.facts.connection}</h4>
          <For each={groups().access}>
            {([who, items]) => (
              <div class="proposal-access">
                <Icon
                  name={
                    who === ALL_BUNKERS
                      ? "agents"
                      : owner.isDevice(who)
                        ? "devices"
                        : "sandboxes"
                  }
                />
                <strong title={who}>{who}</strong>
                <Facts items={items} />
                <For each={items.filter((item) => item.kind === "level")}>
                  {(item) => (
                    <small>{LEVEL_NOTES[item.leaf.value as owner.GrantLevel]}</small>
                  )}
                </For>
              </div>
            )}
          </For>
        </section>
      </Show>
      <Show when={groups().other.length}>
        <section class="proposal-group">
          <h4>Other settings</h4>
          <Facts items={groups().other} />
        </section>
      </Show>
      <Show when={props.record.facts.details?.policy}>
        {(policy) => (
          <details class="proposal-diff">
            <summary>Source diff</summary>
            <TechnicalDiff text={policy().source_diff} />
          </details>
        )}
      </Show>
    </>
  );
}

// Rows for the pending proposals, inside a list that the caller provides.
export function ConnectionProposals(props: { id?: string }) {
  const m = useMonitor();
  onMount(() => {
    if (props.id)
      queueMicrotask(() => {
        const summary = document.querySelector<HTMLElement>(
          ".proposal-connection-item[open] > summary",
        );
        // The page header and the list's heading stick over whatever scrolls to the top.
        const sticky = [
          document.getElementById("page-header"),
          summary
            ?.closest(".resource-list")
            ?.querySelector(".resource-heading"),
        ].reduce(
          (height, el) => height + ((el as HTMLElement)?.offsetHeight ?? 0),
          0,
        );
        if (summary) summary.style.scrollMarginTop = `${sticky}px`;
        summary?.scrollIntoView({ block: "start" });
        summary?.focus();
      });
  });
  return (
    <For each={m.pendingProposals().map((proposal) => proposal.id)}>
      {(id) => {
        const proposal = () =>
          m.pendingProposals().find((record) => record.id === id)!;
        return (
          <ResourceDisclosure
            class="proposal-connection-item"
            summaryClass="collection-row proposal-connection-row"
            open={props.id === id}
            summary={
              <>
                <ProposalSummary
                  proposal={proposal()}
                  class="proposal-summary"
                />
                <span class="resource-meta">
                  <ProposalBadge proposal={proposal()} />
                </span>
                <span class="collection-chevron">
                  <Icon name="arrow" />
                </span>
              </>
            }
          >
            {(active) => (
              <Show when={active()}>
                <ConnectionProposalDetail proposal={proposal()} />
              </Show>
            )}
          </ResourceDisclosure>
        );
      }}
    </For>
  );
}

function ConnectionProposalDetail(props: { proposal: owner.RequestRecord }) {
  const m = useMonitor();
  const [full, { refetch }] = createRecord(() => ({
    api: m.api()!,
    id: props.proposal.id,
    segment: props.proposal.segment,
  }));
  const loaded = () => (full.error ? undefined : full());
  const decide = async (decision: "once" | "deny") => {
    if (m.busy() || !loaded()) return;
    if (await m.decide(props.proposal, decision, loaded()))
      location.hash = "#activity";
    else void refetch();
  };
  return (
    <div class="proposal-card proposal-card-inline">
      <div class="proposal-body">
        <div class="proposal-context">
          <p>
            <strong>Reason:</strong> {loaded()?.facts.title ?? props.proposal.facts.title}
          </p>
          <p class="proposal-byline">
            <ProposerByline proposal={props.proposal} />
          </p>
        </div>
        <Show when={full.error}>
          <p role="alert">{String(full.error)}</p>
        </Show>
        <Show
          when={
            m.view()!.presets[proposalPreset(loaded() ?? props.proposal, m.view()!)]
              ?.warning
          }
        >
          {(warning) => (
            <p class="connection-warning" role="note">
              {warning()}
            </p>
          )}
        </Show>
        <Show when={loaded()} fallback={!full.error && <p class="muted">Loading changes…</p>}>
          {(proposal) => <ProposalChanges record={proposal()} />}
        </Show>
      </div>
      <footer class="proposal-decision decision-buttons">
        <button
          class="allow"
          disabled={m.busy() || !loaded()}
          onClick={() => void decide("once")}
        >
          Approve changes
        </button>
        <button
          class="danger"
          disabled={m.busy() || !loaded()}
          onClick={() => void decide("deny")}
        >
          Reject
        </button>
      </footer>
    </div>
  );
}
