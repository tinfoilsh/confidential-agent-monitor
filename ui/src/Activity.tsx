import {
  For,
  Show,
  createMemo,
  createResource,
  lazy,
  onCleanup,
  onMount,
} from "solid-js";
import * as owner from "./owner.js";
import {
  ConnectorIcon,
  Empty,
  Icon,
  ResourceDisclosure,
  href,
} from "./components";
import { useMonitor } from "./monitor";
import { PolicyProposals } from "./PolicyProposals";

const Rules = lazy(() =>
  import("./Settings").then((m) => ({ default: m.Rules })),
);

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

export function Badge(props: { state: string; record?: owner.RequestRecord }) {
  return (
    <span class={`badge status-${props.state}`}>
      <Show when={props.state === "pending"}>
        <Icon name="clock" />
      </Show>
      {props.record
        ? owner.reviewStatus({
            ...props.record,
            state: props.state as owner.RequestState,
          })
        : props.state === "pending"
          ? "Needs your approval"
          : props.state[0].toUpperCase() + props.state.slice(1)}
    </span>
  );
}
export function Activity(props: { scope?: string; name?: string }) {
  const rules = () => props.scope === "rules";
  const proposals = () => props.scope === "proposals";
  const request = () => props.scope === "request" ? props.name : undefined;
  return (
    <>
      <nav class="page-tabs" aria-label="Activity views">
        <a
          href="#activity"
          aria-current={!rules() && !proposals() ? "page" : undefined}
        >
          Requests
        </a>
        <a
          href="#activity/proposals"
          aria-current={proposals() ? "page" : undefined}
        >
          Proposed connection changes
        </a>
        <a href="#activity/rules" aria-current={rules() ? "page" : undefined}>
          Saved Rules
        </a>
      </nav>
      <Show
        when={proposals()}
        fallback={
          <Show
            when={rules()}
            fallback={<Requests scope={props.scope} name={props.name} expanded={request()} />}
          >
            <Rules />
          </Show>
        }
      >
        <PolicyProposals />
      </Show>
    </>
  );
}
function Requests(props: { scope?: string; name?: string; expanded?: string }) {
  const m = useMonitor();
  const scope = () =>
    props.scope === "agent" || props.scope === "account" ? props.scope : "";
  const key = scope() ? `${scope()}/${props.name ?? ""}` : "";
  if (m.activity.scope !== key)
    m.setActivity({ scope: key, page: 0, anchor: 0 });
  const page = () => m.activity.page,
    setPage = (value: number) => m.setActivity("page", value),
    anchor = () => m.activity.anchor;
  const filtered = createMemo(() =>
    owner
      .ordered(m.records(), m.dismissed())
      .filter((r) => !owner.isConnectionProposalRecord(r))
      .filter((r) =>
        scope() === "agent"
          ? r.facts.principal.name === props.name
          : scope() === "account"
            ? r.facts.account === props.name
            : true,
      ),
  );
  // Paging back holds the list at its newest request, so arrivals do not shift the rows being read.
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
      Date.parse(m.records()[0]?.time ?? "") || Date.now(),
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
      <Show when={scope()}>
        <p class="activity-context">
          Requests for <strong>{props.name}</strong>{" "}
          <a href="#activity">All requests</a>
        </p>
      </Show>
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
              title={
                m.records().length ? "No matching requests" : "No requests yet"
              }
              action={
                <Show when={!m.records().length}>
                  <a class="button primary" href="#connections/catalog">
                    <Icon name="plus" />
                    Add connection
                  </a>
                </Show>
              }
            >
              <Show
                when={m.records().length}
                fallback="Requests appear here when a sandbox uses a connection."
              >
                No requests for this{" "}
                {scope() === "agent" ? "agent" : "connection"} yet.
              </Show>
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
                      <ConnectorIcon
                        preset={
                          m.view()!.config.accounts?.[record().facts.account]
                            ?.preset ?? ""
                        }
                      />
                      <span>
                        <strong>{owner.requestTitle(record())}</strong>
                        <small>
                          {record().facts.principal.name} ·{" "}
                          {record().facts.account || "Policy"}
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
  const source = createMemo(
    () => ({
      api: m.api()!,
      id: props.id,
      segment: listed()?.segment,
      state: listed()?.state,
      reviews: listed()?.reviews?.length ?? 0,
      saving: !!listed()?.savingDecision,
    }),
    undefined,
    {
      equals: (a, b) =>
        !!a &&
        a.api === b.api &&
        a.id === b.id &&
        a.state === b.state &&
        a.reviews === b.reviews &&
        a.saving === b.saving,
    },
  );
  // Closing a disclosure pauses updates while retaining the loaded request.
  // Reopening unchanged details should not fetch the same large body again.
  const selected = createMemo(
    (previous: ReturnType<typeof source> | undefined) =>
      props.active === false || listed()?.savingDecision ? previous : source(),
  );
  const lifetime = new AbortController();
  onCleanup(() => lifetime.abort());
  const [full, { refetch }] = createResource(selected, (s) =>
    s.segment
      ? s.api.archived(s.segment, s.id, lifetime.signal)
      : s.api.request(s.id, lifetime.signal),
  );
  const record = createMemo(() => {
    if (full.error) return;
    const current = full() ?? listed();
    return (
      current && {
        ...current,
        state: listed()?.state ?? current.state,
        reviewer: listed() ? listed()!.reviewer : current.reviewer,
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
          const reasons = createMemo(() =>
            [...new Set([...(r().deny ?? []), ...owner.reasons(r())])].map(
              (reason) =>
                reason === "this agent may not do this on the account"
                  ? "This sandbox does not have permission for this action."
                  : reason,
            ),
          );
          const destination = createMemo(() => {
            const http = r().facts.details?.http;
            return http
              ? `${http.host}${http.path === "/" ? "" : http.path}`
              : r()
                  .facts.title?.match(
                    /^(?:GET|POST|PUT|PATCH|DELETE|HEAD|OPTIONS|CONNECT|TRACE) (.+)$/,
                  )?.[1]
                  .replace(/\/$/, "");
          });
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
                  <dt>Sandbox</dt>
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
                  <dt>Connection</dt>
                  <dd>
                    <Show
                      when={m.view()!.config.accounts?.[r().facts.account]}
                      fallback={r().facts.account || "Policy"}
                    >
                      {(account) => (
                        <a
                          class="request-context-link"
                          href={href("connection", r().facts.account)}
                        >
                          <ConnectorIcon preset={account().preset} />
                          {r().facts.account}
                          <Icon name="arrow" />
                        </a>
                      )}
                    </Show>
                    <Show when={destination()}>
                      <div class="request-destination">{destination()}</div>
                    </Show>
                  </dd>
                </div>
                <div>
                  <dt>Requested</dt>
                  <dd>
                    <time dateTime={r().time}>
                      {requestDate.format(new Date(r().time))}
                    </time>
                  </dd>
                </div>
              </dl>
              <Show when={state() === "pending"}>
                <p class="muted request-time-left">
                  {owner.timeLeft(r(), m.now())} left to respond
                </p>
              </Show>
              <div class="request-reasons">
                <h3>Review</h3>
                <Show
                  when={r().reviews?.length}
                  fallback={
                    <p>
                      {state() === "pending"
                        ? "Waiting for you."
                        : state() === "refused"
                          ? "Blocked by policy. No one was asked."
                          : state() === "expired"
                            ? "Nobody answered in time."
                            : state() === "outdated"
                              ? "Settings affecting this connection changed before review."
                              : state() === "approved"
                                ? owner.isConnectionProposalRecord(r())
                                  ? "Proposal approved."
                                  : "Allowed by policy."
                                : state() === "denied" && owner.isConnectionProposalRecord(r())
                                  ? "Proposal rejected."
                                  : "Blocked."}
                    </p>
                  }
                >
                  <For each={r().reviews}>
                    {(answer) => (
                      <p>
                        <strong>
                          {answer.by === "tinfoil" ? "Tinfoil" : "You"}
                        </strong>
                        {answer.decision === "escalate"
                          ? " passed this to you"
                          : answer.decision === "once"
                            ? " approved it once"
                            : answer.decision === "deny"
                              ? owner.isConnectionProposalRecord(r())
                                ? " rejected it"
                                : " denied it"
                              : " approved it and saved a rule"}
                        <Show when={answer.reason}>: {answer.reason}</Show>
                      </p>
                    )}
                  </For>
                </Show>
              </div>
              <Show when={reasons().length}>
                <div class="request-reasons">
                  <h3>Details</h3>
                  <ul>
                    <For each={reasons()}>{(reason) => <li>{reason}</li>}</For>
                  </ul>
                </div>
              </Show>
              <Show
                when={
                  (state() === "refused" || state() === "denied") &&
                  m.view()!.config.accounts?.[r().facts.account] &&
                  (r().invalid ||
                    (!owner.isDevice(r().facts.principal.name) &&
                      m.view()!.config.identities?.[r().facts.principal.name]))
                }
              >
                <div class="request-access">
                  <a
                    class="button"
                    href={href("connection", r().facts.account)}
                  >
                    {r().invalid ? "View connection setup" : "Change access"}
                    <Icon name="arrow" />
                  </a>
                  <p class="muted">
                    {r().invalid
                      ? "Fix the request or client configuration using the error above, then retry."
                      : "Update this sandbox’s connection access, then retry the request from your sandbox."}
                  </p>
                </div>
              </Show>
              <Show when={full.loading}>
                <p class="muted">Loading request details…</p>
              </Show>
              <Show when={r().facts.details?.policy}>
                {(policy) => (
                  <>
                    <h3>Source changes</h3>
                    <pre>{policy().source_diff}</pre>
                    <Show when={!owner.isConnectionProposalRecord(r()) && policy().effective_diff}>
                      {(effective) => <><h3>Expanded configuration changes</h3><pre>{effective()}</pre></>}
                    </Show>
                  </>
                )}
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
                    Save rule and retry
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
                <Show when={owner.draftable(m.view()!, r())}>
                  {(preset) => (
                    <a href={href("preset", preset(), r().id)}>
                      Draft operation in preset
                    </a>
                  )}
                </Show>
              </div>
            </section>
          );
        }}
      </Show>
    </div>
  );
}
