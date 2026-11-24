import { For, Show, createMemo, onCleanup, onMount, type JSX } from "solid-js";
import * as owner from "./owner.js";
import {
  ConnectorIcon,
  Empty,
  Icon,
  ResourceDisclosure,
  createRecord,
  href,
} from "./components";
import { useMonitor } from "./monitor";
import { ProposalChanges, proposalPreset } from "./PolicyProposals";
import { ApprovalActions, NeedsApproval } from "./Approvals";

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
  return (
    <>
      <NeedsApproval
        proposal={props.scope === "pending" ? props.name : undefined}
      />
      <Requests expanded={props.scope === "request" ? props.name : undefined} />
    </>
  );
}
// What waits for an answer is listed at the top of the Activity page.
function ReviewLink(props: {
  record: owner.RequestRecord;
  class?: string;
  children: JSX.Element;
}) {
  return (
    <a
      class={props.class}
      href={
        owner.isProposal(props.record)
          ? href("activity", "pending", props.record.id)
          : "#activity"
      }
      onClick={() => {
        document.getElementById("workspace")!.scrollTop = 0;
      }}
    >
      {props.children}
    </a>
  );
}
function Requests(props: { expanded?: string }) {
  const m = useMonitor();
  const page = () => m.activity.page,
    setPage = (value: number) => m.setActivity("page", value),
    anchor = () => m.activity.anchor;
  const filtered = createMemo(() =>
    owner.ordered([...m.recordsById().values()], m.dismissed()),
  );
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
        r.id !== props.expanded &&
        !owner.isProposal(r) &&
        head &&
        !owner.isProposal(head) &&
        head.facts.connection === r.facts.connection &&
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
    const scrolled = () => {
      if (workspace.scrollTop > HOLD_SCROLL_PX) hold();
      else if (!workspace.scrollTop && !current()) m.setActivity("anchor", 0);
    };
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
            <span class="request-count">Count</span>
            <span>Bunker</span>
            <span>Connection</span>
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
                  Add a connection
                </a>
              }
            >
              Requests appear here when a bunker uses a connection.
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
              <Show
                when={owner.isProposal(record())}
                fallback={
                  <ConnectorIcon connection={record().facts.connection} />
                }
              >
                <ConnectorIcon preset={proposalPreset(record(), m.view()!)} />
              </Show>
            </span>
            <strong title={owner.requestTitle(record())}>
              <span class="sr-only">Request: </span>
              {owner.requestTitle(record())}
            </strong>
          </span>
          <span class="count request-count">
            <span class="sr-only">Request count: </span>
            {props.stack.length}
          </span>
          <span class="request-origin">
            <span title={owner.requester(record())}>
              <span class="sr-only">Bunker: </span>
              {owner.requester(record())}
            </span>
            <span title={record().facts.connection || "Policy"}>
              <span class="sr-only">Connection: </span>
              {record().facts.connection || "Policy"}
            </span>
          </span>
          <span class="request-result">
            <span class="sr-only">Status: </span>
            <Badge state={record().state} record={record()} />
            <Show when={record().state === "pending"}>
              <ReviewLink record={record()} class="review-link">
                Review
                <Show when={!owner.isProposal(record())}>
                  {" "}
                  ({owner.timeLeft(record(), m.now())})
                </Show>
              </ReviewLink>
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
        // An answer being saved is only on the listed record so far.
        reviews: listed()?.savingDecision ? listed()!.reviews : current.reviews,
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
          const reasons = createMemo(() => owner.reasons(r()));
          const outcome = createMemo(() =>
            owner.outcomeText({ ...r(), state: state() }),
          );
          const invalid = () => r().refusal?.cause === "invalid";
          const builtin = () => owner.isBuiltin(r().facts.connection);
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
                    <Show
                      when={!owner.isOwnerCall(r())}
                      fallback={owner.requester(r())}
                    >
                      <a
                        class="request-context-link"
                        href={href("agents", r().facts.principal.name)}
                      >
                        {r().facts.principal.name}
                        <Icon name="arrow" />
                      </a>
                    </Show>
                  </dd>
                </div>
                <div>
                  <dt>Connection</dt>
                  <dd>
                    <Show
                      when={
                        !builtin() &&
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
                <div class="request-context-wide">
                  <dt>Review</dt>
                  <dd>
                    <For each={r().reviews}>
                      {(answer) => (
                        <p>
                          {owner.isOwner(answer.by) ? "You" : answer.by}
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
                    <Show when={outcome()}>
                      <p>
                        {outcome()}
                        <Show when={state() === "pending"}>
                          {" "}
                          <ReviewLink record={r()}>Answer it</ReviewLink>
                        </Show>
                      </p>
                    </Show>
                  </dd>
                </div>
                <Show when={reasons().length}>
                  <div class="request-context-wide">
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
              <Show when={owner.isProposal(r())}>
                <ProposalChanges record={r()} />
              </Show>
              <Show
                when={
                  (state() === "refused" ||
                    state() === "denied" ||
                    state() === "revoked") &&
                  r().refusal?.cause !== "precondition" &&
                  m.view()!.config.connections?.[r().facts.connection] &&
                  (invalid() ||
                    ((builtin() || !owner.isDevice(r().facts.principal.name)) &&
                      m.view()!.config.identities?.[r().facts.principal.name]))
                }
              >
                <div class="request-access">
                  <p class="muted">
                    {invalid()
                      ? "Fix the request or client configuration using the error above, then retry."
                      : `Update this ${owner.isDevice(r().facts.principal.name) ? "device" : "bunker"}’s access, then retry the request from it.`}
                  </p>
                  <a
                    class="button"
                    href={
                      builtin()
                        ? href("agents", r().facts.principal.name)
                        : href("connection", r().facts.connection)
                    }
                  >
                    {invalid() ? "View connection setup" : "Change access"}
                    <Icon name="arrow" />
                  </a>
                </div>
              </Show>
              <Show when={state() === "expired"}>
                <ApprovalActions
                  record={r()}
                  shown={full()}
                  saveTitle={owner.saveText(r())}
                  onFailed={() => void refetch()}
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
