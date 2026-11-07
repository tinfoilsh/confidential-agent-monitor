import { For, Show, createMemo, onCleanup, onMount } from "solid-js";
import * as owner from "./owner.js";
import {
  ConnectorIcon,
  Empty,
  Icon,
  RemoveRule,
  ResourceDisclosure,
  RuleText,
  createRecord,
  href,
  TabBar,
} from "./components";
import { useMonitor } from "./monitor";
import { PolicyProposals, TechnicalDiff } from "./PolicyProposals";

const PAGE = 50;
const HOLD_SCROLL_PX = 100;
const requestTime = new Intl.DateTimeFormat(undefined, {
  hour: "2-digit",
  minute: "2-digit",
});
const requestDate = new Intl.DateTimeFormat(undefined, {
  year: "numeric",
  month: "numeric",
  day: "numeric",
  hour: "numeric",
  minute: "numeric",
  second: "numeric",
});

export function Badge(props: { state: string; record: owner.RequestRecord }) {
  return (
    <Show when={props.state !== "pending"}>
      <span class="request-state" data-state={props.state}>
        {owner.reviewStatus({
          ...props.record,
          state: props.state as owner.RequestState,
        })}
      </span>
    </Show>
  );
}
export function Activity(props: { scope?: string; name?: string }) {
  const rules = () => props.scope === "rules";
  const proposals = () => props.scope === "proposals";
  const request = () => props.scope === "request" ? props.name : undefined;
  return (
    <>
      <TabBar
        class="page-tabs"
        label="Activity views"
        value={proposals() ? "proposals" : rules() ? "rules" : "requests"}
        options={[
          { value: "requests", label: "Requests", href: "#activity" },
          {
            value: "proposals",
            label: "Config proposals",
            href: "#activity/proposals",
          },
          { value: "rules", label: "Saved rules", href: "#activity/rules" },
        ]}
      />
      <Show
        when={proposals()}
        fallback={
          <Show when={rules()} fallback={<Requests expanded={request()} />}>
            <Rules />
          </Show>
        }
      >
        <PolicyProposals />
      </Show>
    </>
  );
}
function Rules() {
  const m = useMonitor(),
    rules = () =>
      Object.entries(m.view()!.config.identities ?? {}).flatMap(
        ([name, identity]) =>
          Object.keys(identity.rules ?? {}).map((id) => [name, id] as const),
      );
  return (
    <div class="resource-list">
      <div class="resource-heading">
        <h2>
          Saved rules <span class="count">{rules().length}</span>
        </h2>
        <span>Updates every 5 seconds</span>
      </div>
      <For
        each={rules()}
        fallback={
          <Empty title="No saved rules yet" icon="rules">
            Save an approval rule from a request to allow matching requests in
            the future.
          </Empty>
        }
      >
        {([name, id]) => {
          const rule = () => m.view()!.config.identities![name].rules![id];
          return (
            <div class="resource-row">
              <a
                class="resource-link"
                href={href("connection", rule().connection)}
              >
                <ConnectorIcon connection={rule().connection} />
                <RuleText rule={rule()}>
                  <small>
                    {name} · {rule().connection}
                    {rule().operation
                      ? ""
                      : " · Inactive: saved before approvals named an operation"}
                  </small>
                </RuleText>
              </a>
              <RemoveRule agent={name} id={id} />
            </div>
          );
        }}
      </For>
    </div>
  );
}
function Requests(props: { expanded?: string }) {
  const m = useMonitor();
  const page = () => m.activity.page,
    setPage = (value: number) => m.setActivity("page", value),
    anchor = () => m.activity.anchor;
  const filtered = createMemo(() => owner.ordered(m.requests(), m.dismissed()));
  const held = createMemo(() =>
    anchor()
      ? filtered().filter((r) => Date.parse(r.time) <= anchor())
      : filtered(),
  );
  const pages = () => Math.max(1, Math.ceil(held().length / PAGE)),
    current = () => Math.min(page(), pages() - 1);
  const visible = createMemo(() =>
    held()
      .slice(current() * PAGE, (current() + 1) * PAGE)
      .map((r) => r.id),
  );
  const newer = () => filtered().length - held().length;
  const latest = () => {
    m.setActivity({ page: 0, anchor: 0 });
    document.getElementById("workspace")!.scrollTop = 0;
  };
  const hold = () =>
    anchor() ||
    m.setActivity(
      "anchor",
      Date.parse(m.requests()[0]?.time ?? "") || Date.now(),
    );
  onMount(() => {
    const workspace = document.getElementById("workspace")!;
    const scrolled = () => workspace.scrollTop > HOLD_SCROLL_PX && hold();
    workspace.addEventListener("scroll", scrolled, { passive: true });
    onCleanup(() => workspace.removeEventListener("scroll", scrolled));
  });
  const next = async () => {
    hold();
    const end = (current() + 1) * PAGE,
      full = held().length >= end;
    if (held().length <= end) await m.loadOlder();
    if (full) setPage(current() + 1);
  };
  return (
    <>
      <div id="list" class="resource-list">
        <div class="resource-heading">
          <h2>
            Requests <span class="count">{filtered().length}</span>
          </h2>
          <Show when={anchor()} fallback={<span>Updates every 5 seconds</span>}>
            <button onClick={latest}>
              {newer() ? `View ${newer()} new` : "Back to latest"}
            </button>
          </Show>
        </div>
        <For
          each={visible()}
          fallback={
            <Empty
              title="No requests yet"
              action={
                <a class="button primary" href="#connections/catalog">
                  <Icon name="plus" />
                  Add a service
                </a>
              }
            >
              Requests appear here when a bunker uses a service.
            </Empty>
          }
        >
          {(id) => {
            const record = createMemo(() => m.recordsById().get(id)!);
            const timestamp = createMemo(() => record().time);
            const time = createMemo(() => new Date(timestamp()));
            return (
              <ResourceDisclosure
                class="request-item"
                summaryClass="request-row activity-row"
                open={props.expanded === id}
                summary={
                  <>
                    <span class="resource-link">
                      <ConnectorIcon connection={record().facts.connection} />
                      <span>
                        <strong>{owner.requestTitle(record())}</strong>
                        <small>
                          {record().facts.principal.name} ·{" "}
                          {record().facts.connection || "Policy"}
                        </small>
                      </span>
                    </span>
                    <div class="resource-meta">
                      <Badge state={record().state} record={record()} />
                      <Show when={record().state === "pending"}>
                        <span class="muted">
                          {owner.timeLeft(record(), m.now())} left
                        </span>
                      </Show>
                      <time title={requestDate.format(time())}>
                        {requestTime.format(time())}
                      </time>
                    </div>
                    <div class="row-actions">
                      <Show when={owner.decisions(record()).once}>
                        <button
                          class="danger"
                          onClick={() => void m.decide(record(), "deny")}
                        >
                          Deny request
                        </button>
                        <button
                          class="primary"
                          onClick={() => void m.decide(record(), "once")}
                        >
                          Allow once
                        </button>
                      </Show>
                    </div>
                    <span class="collection-chevron">
                      <Icon name="arrow" />
                    </span>
                  </>
                }
              >
                {(active) => <RequestDetail id={id} inline active={active()} />}
              </ResourceDisclosure>
            );
          }}
        </For>
        <Show when={pages() > 1 || m.older() !== null}>
          <div class="pagination">
            <span>
              {held().length ? current() * PAGE + 1 : 0} to{" "}
              {Math.min((current() + 1) * PAGE, held().length)} of{" "}
              {held().length}
              {m.older() !== null && "+"} requests
            </span>
            <div>
              <button
                disabled={current() === 0}
                onClick={() => setPage(current() - 1)}
              >
                Previous
              </button>
              <span>
                {current() + 1} of {pages()}
                {m.older() !== null && "+"}
              </span>
              <button
                disabled={
                  m.loadingOlder() ||
                  (current() + 1 === pages() && m.older() === null)
                }
                onClick={next}
              >
                Next
              </button>
            </div>
          </div>
        </Show>
      </div>
    </>
  );
}
export function RequestDetail(props: {
  id: string;
  inline?: boolean;
  active?: boolean;
}) {
  const m = useMonitor();
  const listed = createMemo(() => m.recordsById().get(props.id));
  const source = createMemo(() => ({
    api: m.api()!,
    id: props.id,
    segment: listed()?.segment,
    state: listed()?.state,
    reviews: listed()?.reviews?.length ?? 0,
    saving: !!listed()?.savingDecision,
  }));
  const selected = createMemo(
    (previous: ReturnType<typeof source> | undefined) =>
      props.active === false || listed()?.savingDecision ? previous : source(),
  );
  const [full, { refetch }] = createRecord(selected);
  const record = createMemo(() => {
    if (full.error) return;
    const current = full() ?? listed();
    return (
      current && {
        ...current,
        state: listed()?.state ?? current.state,
        savingDecision: listed()?.savingDecision,
      }
    );
  });
  return (
    <div
      id={props.inline ? undefined : "pane"}
      classList={{ "request-inline": props.inline }}
    >
      <Show when={!props.inline}>
        <a href="#activity">Back to activity</a>
      </Show>
      <Show when={full.error}>
        <p role="alert">{String(full.error)}</p>
        <button onClick={() => void refetch()}>Retry</button>
      </Show>
      <Show
        when={!full.error && record()}
        fallback={!full.error && <p>Loading request…</p>}
      >
        {(r) => {
          const state = createMemo(() => owner.stateAt(r(), m.now()));
          const reasons = createMemo(() => [
            ...new Set([...(r().deny ?? []), ...owner.reasons(r())]),
          ]);
          return (
            <section class="request-detail">
              <Show when={!props.inline}>
                <header class="request-detail-heading">
                  <h2>{owner.requestTitle(r())}</h2>
                  <Badge state={state()} record={r()} />
                </header>
              </Show>
              <dl class="request-context">
                <div>
                  <dt>Bunker</dt>
                  <dd>
                    <a
                      class="request-context-link"
                      href={href("agents", r().facts.principal.name)}
                    >
                      {r().facts.principal.name}
                      <Icon name="arrow" />
                    </a>
                  </dd>
                </div>
                <div>
                  <dt>Service</dt>
                  <dd>
                    <Show
                      when={
                        m.view()!.config.connections?.[r().facts.connection]
                      }
                      fallback={r().facts.connection || "Policy"}
                    >
                      {(connection) => (
                        <a
                          class="request-context-link"
                          href={href("connection", r().facts.connection)}
                        >
                          <ConnectorIcon preset={connection().preset} />
                          {r().facts.connection}
                          <Icon name="arrow" />
                        </a>
                      )}
                    </Show>
                  </dd>
                </div>
                <div>
                  <dt>Requested</dt>
                  <dd>
                    <time dateTime={r().time}>
                      {requestDate.format(new Date(r().time))}
                    </time>
                    <Show when={state() === "pending"}>
                      <span class="muted">
                        {" "}
                        · {owner.timeLeft(r(), m.now())} left to respond
                      </span>
                    </Show>
                  </dd>
                </div>
                <div>
                  <dt>Review</dt>
                  <dd>
                    <Show
                      when={r().reviews?.length}
                      fallback={
                        state() === "pending"
                          ? "Waiting for you."
                          : state() === "refused"
                            ? "Blocked by policy. No one was asked."
                            : state() === "expired"
                              ? "Nobody answered in time."
                              : state() === "outdated"
                                ? "Settings for this service changed before review."
                                : state() === "allowed" || state() === "approved"
                                  ? owner.isProposal(r())
                                    ? "Proposal approved."
                                    : "Allowed by policy."
                                  : state() === "denied" && owner.isProposal(r())
                                    ? "Proposal rejected."
                                    : "Blocked."
                      }
                    >
                      <For each={r().reviews}>
                        {(answer) => (
                          <p>
                            You
                            {answer.decision === "once"
                              ? " approved it once"
                              : answer.decision === "deny"
                                ? owner.isProposal(r())
                                  ? " rejected it"
                                  : " denied it"
                                : " approved it and saved a rule"}
                            <Show when={answer.reason}>: {answer.reason}</Show>
                          </p>
                        )}
                      </For>
                    </Show>
                  </dd>
                </div>
                <Show when={reasons().length}>
                  <div>
                    <dt>Reason</dt>
                    <dd>
                      <For each={reasons()}>{(reason) => <p>{reason}</p>}</For>
                    </dd>
                  </div>
                </Show>
              </dl>
              <Show when={full.loading}>
                <p class="muted">Loading request details…</p>
              </Show>
              <Show when={r().facts.details?.policy}>
                {(policy) => (
                  <>
                    <h3>Source changes</h3>
                    <TechnicalDiff text={policy().source_diff} />
                  </>
                )}
              </Show>
              <Show
                when={
                  (state() === "refused" || state() === "denied") &&
                  m.view()!.config.connections?.[r().facts.connection] &&
                  (r().invalid ||
                    (!owner.isDevice(r().facts.principal.name) &&
                      m.view()!.config.identities?.[r().facts.principal.name]))
                }
              >
                <div class="request-access">
                  <p class="muted">
                    {r().invalid
                      ? "Fix the request or client configuration using the error above, then retry."
                      : "Update this bunker’s access, then retry the request from your bunker."}
                  </p>
                  <a
                    class="button"
                    href={href("connection", r().facts.connection)}
                  >
                    {r().invalid ? "View service setup" : "Change access"}
                    <Icon name="arrow" />
                  </a>
                </div>
              </Show>
              <div class="decisions">
                <Show when={owner.decisions(r(), m.now()).dismiss}>
                  <button
                    onClick={() => {
                      m.dismiss(r().id);
                      location.hash = "#activity";
                    }}
                  >
                    Dismiss
                  </button>
                </Show>
                <Show when={owner.decisions(r(), m.now()).once}>
                  <button
                    class="primary"
                    onClick={() => void m.decide(r(), "once")}
                  >
                    Allow once
                  </button>
                </Show>
                <Show when={owner.decisions(r(), m.now()).save}>
                  <button
                    title={owner.saveText(r())}
                    onClick={() => void m.decide(r(), "save")}
                  >
                    Allow always
                  </button>
                </Show>
                <Show when={owner.decisions(r(), m.now()).deny}>
                  <button
                    class="danger"
                    onClick={() => void m.decide(r(), "deny")}
                  >
                    Deny
                  </button>
                </Show>
              </div>
            </section>
          );
        }}
      </Show>
    </div>
  );
}
