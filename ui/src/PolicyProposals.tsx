import { For, Show, createMemo, createResource, onMount } from "solid-js";
import * as owner from "./owner.js";
import {
  ConnectorIcon,
  Empty,
  Icon,
  ResourceDisclosure,
  href,
} from "./components";
import { useMonitor } from "./monitor";
import "./policy-proposals.css";

const proposalTime = new Intl.DateTimeFormat(undefined, {
  month: "numeric",
  day: "numeric",
  hour: "2-digit",
  minute: "2-digit",
});
const date = (value: string) => {
  const parsed = new Date(value);
  return Number.isNaN(parsed.valueOf()) ? value : proposalTime.format(parsed);
};
function ProposerByline(props: { proposal: owner.RequestRecord }) {
  return (
    <>
      <strong>By {owner.isDevice(props.proposal.facts.principal.name) ? "Trusted Device" : "Sandbox"}:</strong>{" "}
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
const valueText = (value: owner.Json | undefined) => {
  if (value === undefined) return "Not set";
  if (typeof value === "string") return value || "Empty";
  return JSON.stringify(value, null, 2);
};
const pathLabel = (proposal: owner.RequestRecord, path: string[]) => {
  if (path[0] === "identities")
    return [`Sandbox ${path[1]}`, ...path.slice(4)].join(" › ");
  if (path[0] === "default_access")
    return ["Default access", ...path.slice(2)].join(" › ");
  if (path[0] === "accounts" && path[1] === proposal.facts.account)
    return ["Connection", ...path.slice(2)].join(" › ");
  return path.join(" › ");
};
const proposalPreset = (proposal: owner.RequestRecord, view: owner.View) => {
  for (const change of proposal.changes ?? []) {
    if (
      change.path.join("/") === `accounts/${proposal.facts.account}/preset` &&
      typeof change.value === "string"
    )
      return change.value;
    if (
      change.path.length === 2 &&
      change.path[0] === "accounts" &&
      change.path[1] === proposal.facts.account
    ) {
      const account = change.value as { preset?: owner.Json } | undefined;
      if (typeof account?.preset === "string") return account.preset;
    }
  }
  return view.config.accounts?.[proposal.facts.account]?.preset ?? "";
};
const proposalBadge = (proposal: owner.RequestRecord, view: owner.View) =>
  view.config.accounts?.[proposal.facts.account]
    ? { label: "Update", class: "status-pending" }
    : { label: "New", class: "status-new" };

export function TechnicalDiff(props: { text: string }) {
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

function Change(props: {
  proposal: owner.RequestRecord;
  change: owner.Change;
}) {
  const m = useMonitor();
  const before = () => at(m.view()!.config, props.change.path);
  return (
    <div class="proposal-change">
      <strong class="proposal-path">
        {pathLabel(props.proposal, props.change.path)}
      </strong>
      <div class="proposal-values">
        <div>
          <small>Current</small>
          <pre>{valueText(before())}</pre>
        </div>
        <span class="proposal-arrow" aria-hidden="true">
          →
        </span>
        <div>
          <small>Proposed</small>
          <pre>
            {props.change.delete ? "Remove" : valueText(props.change.value)}
          </pre>
        </div>
      </div>
    </div>
  );
}

/** Activity lists pending proposals and links settled outcomes to their audit details. */
export function PolicyProposals() {
  const m = useMonitor();
  const history = createMemo(() =>
    m
      .records()
      .filter(owner.isConnectionProposalRecord)
      .filter((record) => record.state !== "pending")
      .sort((a, b) => Date.parse(b.time) - Date.parse(a.time)),
  );
  const total = () => m.proposals().length + history().length;
  return (
    <div id="list" class="resource-list proposal-list">
      <div class="resource-heading">
        <h2>
          Proposed changes <span class="count">{total()}</span>
        </h2>
        <span>Updates every 5 seconds</span>
      </div>
      <Show
        when={total()}
        fallback={
          <Empty
            title={
              !m.view() && m.loading()
                ? "Loading proposals…"
                : "No config proposals"
            }
            icon="policy"
          >
            Changes proposed by sandboxes or trusted devices will appear here.
          </Empty>
        }
      >
        <For each={m.proposals().map((proposal) => proposal.id)}>
          {(id) => {
            const proposal = () =>
              m.proposals().find((record) => record.id === id)!;
            const badge = () => proposalBadge(proposal(), m.view()!);
            return (
              <article class="resource-row activity-row">
                <span class="resource-link">
                  <ConnectorIcon
                    preset={proposalPreset(proposal(), m.view()!)}
                  />
                  <span>
                    <strong>{reasonPreview(proposal().facts.title ?? "")}</strong>
                    <small>
                      {proposal().facts.account} · {proposal().facts.principal.name}
                    </small>
                  </span>
                </span>
                <span class="resource-meta">
                  <time datetime={proposal().time}>
                    {date(proposal().time)}
                  </time>
                  <span class={`badge proposal-kind ${badge().class}`}>
                    {badge().label}
                  </span>
                  <a
                    class="button"
                    href={`#connections/pending/${encodeURIComponent(id)}`}
                  >
                    Review in Connections <Icon name="arrow" />
                  </a>
                </span>
              </article>
            );
          }}
        </For>
        <For each={history()}>
          {(record) => (
            <article class="resource-row activity-row proposal-history-row">
              <a class="resource-link" href={href("request", record.id)}>
                <ConnectorIcon
                  preset={
                    m.view()!.config.accounts?.[record.facts.account]?.preset ??
                    ""
                  }
                />
                <span>
                  <strong>
                    {reasonPreview(record.facts.title || "Connection proposal")}
                  </strong>
                  <small>
                    {record.facts.account || "Policy"} ·{" "}
                    {record.facts.principal.key
                      ? record.facts.principal.name
                      : "Owner API"}
                  </small>
                </span>
              </a>
              <span class="resource-meta">
                <time datetime={record.time}>{date(record.time)}</time>
                <span class={`badge status-${record.state}`}>
                  {owner.reviewStatus(record)}
                </span>
              </span>
            </article>
          )}
        </For>
      </Show>
    </div>
  );
}

/** Connections → Proposals, with each proposal expanding in place. */
export function ConnectionProposals(props: { id?: string }) {
  const m = useMonitor();
  let list!: HTMLDivElement;
  onMount(() => {
    if (props.id)
      queueMicrotask(() => {
        const summary = list.querySelector<HTMLElement>(
          "details[open] > summary",
        );
        (summary ?? list).scrollIntoView({ block: "start" });
        summary?.focus();
      });
  });
  return (
    <div ref={list} class="resource-list collection-list proposal-list">
      <div class="resource-heading">
        <h2>
          Proposals <span class="count">{m.proposals().length}</span>
        </h2>
      </div>
      <For each={m.proposals().map((proposal) => proposal.id)}>
        {(id) => {
          const proposal = () =>
            m.proposals().find((record) => record.id === id)!;
          const badge = () => proposalBadge(proposal(), m.view()!);
          return (
            <ResourceDisclosure
              class="proposal-connection-item"
              summaryClass="collection-row proposal-connection-row"
              open={props.id === id}
              summary={
                <>
                  <ConnectorIcon
                    preset={proposalPreset(proposal(), m.view()!)}
                  />
                  <span class="proposal-summary">
                    <strong class="proposal-reason-preview">
                      {reasonPreview(proposal().facts.title ?? "")}
                    </strong>
                    <small>
                      {proposal().facts.account} · {proposal().facts.principal.name}
                    </small>
                  </span>
                  <span class="resource-meta">
                    <span class={`badge proposal-kind ${badge().class}`}>
                      {badge().label}
                    </span>
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
    </div>
  );
}

function ConnectionProposalDetail(props: { proposal: owner.RequestRecord }) {
  const m = useMonitor();
  const [full] = createResource(() => props.proposal.id, (id) => m.api()!.request(id));
  const loaded = () => (full.error ? undefined : full());
  const decide = async (decision: "once" | "deny") => {
    if (m.busy() || !loaded()) return;
    if (await m.decide(props.proposal, decision)) location.hash = "#connections";
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
        <div class="proposal-change-list">
          <For each={loaded()?.changes}>
            {(change) => <Change proposal={props.proposal} change={change} />}
          </For>
        </div>
        <Show when={loaded()} fallback={!full.error && <p class="muted">Loading changes…</p>}>
          {(proposal) => (
            <details class="proposal-diff" open>
              <summary>Technical TOML diff</summary>
              <TechnicalDiff text={proposal().facts.details?.policy?.source_diff ?? ""} />
            </details>
          )}
        </Show>
      </div>
      <footer class="proposal-decision">
        <strong>Approve changes?</strong>
        <div class="form-actions">
          <button
            disabled={m.busy() || !loaded()}
            onClick={() => void decide("deny")}
          >
            Reject
          </button>
          <button
            class="primary"
            disabled={m.busy() || !loaded()}
            onClick={() => void decide("once")}
          >
            Approve changes
          </button>
        </div>
      </footer>
    </div>
  );
}
