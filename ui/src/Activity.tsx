import { For, Show, createMemo, onCleanup, onMount } from "solid-js";
import * as owner from "./owner.js";
import {
  ConnectorIcon,
  Empty,
  Icon,
  ResourceDisclosure,
  createRecord,
  href,
  TabBar,
} from "./components";
import { useMonitor } from "./monitor";
import { PolicyProposals, TechnicalDiff } from "./PolicyProposals";
import { ApprovalActions } from "./Approvals";

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
// Shown in the page header, so the views stay in reach while the page scrolls.
export function ActivityTabs(props: { scope?: string }) {
  return (
    <TabBar
      class="page-tabs"
      label="Activity views"
      value={props.scope === "proposals" ? "proposals" : "requests"}
      options={[
        { value: "requests", label: "Requests", href: "#activity" },
        {
          value: "proposals",
          label: "Config proposals",
          href: "#activity/proposals",
        },
      ]}
    />
  );
}
export function Activity(props: { scope?: string; name?: string }) {
  const proposals = () => props.scope === "proposals";
  const request = () => props.scope === "request" ? props.name : undefined;
  return (
    <Show when={proposals()} fallback={<Requests expanded={request()} />}>
      <PolicyProposals />
    </Show>
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
  const stacks = createMemo(() => {
    const stacks = new Map<string, string[]>();
    let head: owner.RequestRecord | undefined;
    for (const r of held()) {
      if (
        m.activity.stacked &&
        r.id !== props.expanded &&
        head?.facts.connection === r.facts.connection &&
        head.facts.principal.name === r.facts.principal.name
      )
        stacks.get(head.id)!.push(r.id);
      else stacks.set((head = r).id, [r.id]);
    }
    return stacks;
  });
  const rows = createMemo(() => [...stacks().keys()]);
  const pages = () => Math.max(1, Math.ceil(rows().length / PAGE)),
    current = () => Math.min(page(), pages() - 1);
  const visible = createMemo(() =>
    rows().slice(current() * PAGE, (current() + 1) * PAGE),
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
      full = rows().length >= end;
    if (rows().length <= end) await m.loadOlder();
    if (full) setPage(current() + 1);
  };
  return (
    <>
      <div id="list" class="resource-list request-list">
        <div class="resource-heading">
          <h2>
            Requests <span class="count">{filtered().length}</span>
          </h2>
          <button
            class="icon-button fold"
            title="Stack requests by bunker and service"
            aria-pressed={m.activity.stacked}
            onClick={() => m.setActivity("stacked", !m.activity.stacked)}
          >
            <Icon name="arrow" />
            <Icon name="arrow" />
          </button>
          <Show when={anchor()}>
            <button
              class="icon-button"
              title={newer() ? `View ${newer()} new` : "Back to latest"}
              onClick={latest}
            >
              <Icon name="arrow-up" />
            </button>
          </Show>
        </div>
        <Show when={visible().length}>
          <div class="request-table-heading" aria-hidden="true">
            <span>Request</span>
            <span>Bunker</span>
            <span>Service</span>
            <span>Status</span>
            <span>Time</span>
            <span />
          </div>
        </Show>
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
          {(id) => (
            <RequestRow
              id={id}
              stack={stacks().get(id)!}
              open={props.expanded === id}
            />
          )}
        </For>
        <Show when={pages() > 1 || m.older() !== null}>
          <div class="pagination">
            <span>
              {rows().length ? current() * PAGE + 1 : 0} to{" "}
              {Math.min((current() + 1) * PAGE, rows().length)} of{" "}
              {rows().length}
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
function RequestRow(props: { id: string; stack: string[]; open?: boolean }) {
  const m = useMonitor();
  const record = createMemo(() => m.recordsById().get(props.id)!);
  const timestamp = createMemo(() => record().time);
  const time = createMemo(() => new Date(timestamp()));
  return (
    <ResourceDisclosure
      class="request-item"
      summaryClass="request-row activity-row"
      open={props.open}
      summary={
        <>
          <span class="resource-link">
            <span class="icon-stack" data-stacked={props.stack.length > 1}>
              <ConnectorIcon connection={record().facts.connection} />
            </span>
            <strong title={owner.requestTitle(record())}>
              <span class="sr-only">Request: </span>
              {owner.requestTitle(record())}
            </strong>
            <Show when={props.stack.length > 1}>
              <span class="count">×{props.stack.length}</span>
            </Show>
          </span>
          <span class="request-origin">
            <span title={record().facts.principal.name}>
              <span class="sr-only">Bunker: </span>
              {record().facts.principal.name}
            </span>
            <span title={record().facts.connection || "Policy"}>
              <span class="sr-only">Service: </span>
              {record().facts.connection || "Policy"}
            </span>
          </span>
          <span class="request-result">
            <span class="sr-only">Status: </span>
            <Badge state={record().state} record={record()} />
            <Show when={record().state === "pending"}>
              <a
                class="review-link"
                href="#connections"
                title={`Review in Permissions · ${owner.timeLeft(record(), m.now())} left`}
              >
                Review ({owner.timeLeft(record(), m.now())})
              </a>
            </Show>
          </span>
          <time dateTime={timestamp()} title={requestDate.format(time())}>
            <span class="sr-only">Requested at: </span>
            {requestTime.format(time())}
          </time>
          <span class="collection-chevron">
            <Icon name="arrow" />
          </span>
        </>
      }
    >
      {(active) => (
        <Show
          when={props.stack.length > 1}
          fallback={<RequestDetail id={props.id} inline active={active()} />}
        >
          <div class="request-stack">
            <For each={props.stack}>
              {(id) => <RequestRow id={id} stack={[id]} />}
            </For>
          </div>
        </Show>
      )}
    </ResourceDisclosure>
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
                    <Show when={state() === "pending"}>
                      {" "}
                      <a href="#connections">Answer in Permissions</a>
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
              <Show when={state() === "expired"}>
                <ApprovalActions
                  record={r()}
                  saveTitle={owner.saveText(r())}
                  onDismiss={() => {
                    m.dismiss(r().id);
                    location.hash = "#activity";
                  }}
                />
              </Show>
            </section>
          );
        }}
      </Show>
    </div>
  );
}
