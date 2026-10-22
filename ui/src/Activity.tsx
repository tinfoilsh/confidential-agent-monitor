import {
  For,
  Show,
  batch,
  createMemo,
  createResource,
  onCleanup,
} from "solid-js";
import * as owner from "./owner.js";
import {
  ConnectorIcon,
  Empty,
  Icon,
  LazyDetails,
  ResourceDisclosure,
  Search,
  href,
} from "./components";
import { useMonitor } from "./monitor";

const PAGE = 50;
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
  const m = useMonitor();
  if (props.scope === "agent" || props.scope === "account")
    m.setFilters(props.scope, props.name ?? "");
  const query = () => m.filters.query,
    setQuery = (value: string) => m.setFilters("query", value),
    state = () => m.filters.state,
    setState = (value: string) => m.setFilters("state", value),
    agent = () => m.filters.agent,
    setAgent = (value: string) => m.setFilters("agent", value),
    account = () => m.filters.account,
    setAccount = (value: string) => m.setFilters("account", value),
    page = () => m.filters.page,
    setPage = (value: number) => m.setFilters("page", value),
    anchor = () => m.filters.anchor;
  const networkingOff = () => owner.networkingOff(m.view()!);
  const ordered = createMemo(() => owner.ordered(m.records(), m.dismissed()));
  const searchText = createMemo(
    () =>
      new Map(
        m
          .records()
          .map((r) => [
            r.id,
            `${owner.requestTitle(r)} ${r.facts.principal.name} ${r.facts.account}`.toLowerCase(),
          ]),
      ),
  );
  const filtered = createMemo(() => {
    const search = query().toLowerCase(),
      status = state(),
      principal = agent(),
      connection = account();
    return ordered().filter(
      (r) =>
        (!status ||
          (status === "pending"
            ? owner.needsOwner(r)
            : status === "reviewing"
              ? r.state === "pending" && !!r.reviewer
              : r.state === status)) &&
        (!principal || r.facts.principal.name === principal) &&
        (!connection || r.facts.account === connection) &&
        (!search || searchText().get(r.id)!.includes(search)),
    );
  });
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
  const latest = () => m.setFilters({ page: 0, anchor: 0 });
  const next = async () => {
    if (!anchor())
      m.setFilters(
        "anchor",
        Date.parse(m.records()[0]?.time ?? "") || Date.now(),
      );
    const end = (current() + 1) * PAGE,
      full = held().length >= end;
    if (held().length <= end) await m.loadOlder();
    if (full) setPage(current() + 1);
  };
  const change = (set: (value: string) => void, value: string) => {
    batch(() => {
      set(value);
      latest();
    });
  };
  return (
    <>
      <Show when={networkingOff()}>
        <div class="network-off-notice">
          <Icon name="close" />
          <span>
            <strong>Networking is off.</strong> You can still see activity,
            but nothing is allowed through.
          </span>
          <button
            disabled={m.busy()}
            onClick={() =>
              m.edit(owner.edits.setNetworking(m.view()!, true))
            }
          >
            Turn networking on
          </button>
        </div>
      </Show>
      <div id="toolbar">
        <Search
          label="Search activity"
          value={query()}
          onInput={(value) => change(setQuery, value)}
        />
        <select
          aria-label="All statuses"
          value={state()}
          onChange={(e) => change(setState, e.currentTarget.value)}
        >
          <option value="">All statuses</option>
          <For
            each={[
              "pending",
              "reviewing",
              "allowed",
              "approved",
              "denied",
              "refused",
              "expired",
            ]}
          >
            {(s) => (
              <option value={s}>
                {s === "pending"
                  ? "Needs your approval"
                  : s === "reviewing"
                    ? "Tinfoil is reviewing"
                    : s.charAt(0).toUpperCase() + s.slice(1)}
              </option>
            )}
          </For>
        </select>
        <select
          aria-label="All identities"
          value={agent()}
          onChange={(e) => change(setAgent, e.currentTarget.value)}
        >
          <option value="">
            All identities (
            {Object.keys(m.view()!.config.identities ?? {}).length})
          </option>
          <For
            each={[
              ...new Set([
                ...Object.keys(m.view()!.config.identities ?? {}),
                ...m.records().map((r) => r.facts.principal.name),
              ]),
            ].sort()}
          >
            {(name) => <option>{name}</option>}
          </For>
        </select>
        <select
          aria-label="All connections"
          value={account()}
          onChange={(e) => change(setAccount, e.currentTarget.value)}
        >
          <option value="">
            All connections (
            {Object.keys(m.view()!.config.accounts ?? {}).length})
          </option>
          <For
            each={[
              ...new Set([
                ...Object.keys(m.view()!.config.accounts ?? {}),
                ...m.records().map((r) => r.facts.account),
              ]),
            ]
              .filter(Boolean)
              .sort()}
          >
            {(name) => <option>{name}</option>}
          </For>
        </select>
        <Show when={query() || state() || agent() || account()}>
          <button
            onClick={() =>
              m.setFilters({
                query: "",
                state: "",
                agent: "",
                account: "",
                page: 0,
                anchor: 0,
              })
            }
          >
            Clear filters
          </button>
        </Show>
      </div>
      <div id="list" class="resource-list">
        <div class="resource-heading">
          <h2>
            Requests{" "}
            <span class="count">
              {filtered().length}
              <Show when={filtered().length !== m.records().length}>
                {" "}
                of {m.records().length}
              </Show>
            </span>
          </h2>
          <Show when={anchor()} fallback={<span>Updates every 5 seconds</span>}>
            <button onClick={latest}>Back to latest</button>
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
                  <a class="button primary" href="#catalog">
                    <Icon name="plus" />
                    Add connection
                  </a>
                </Show>
              }
            >
              <Show
                when={m.records().length}
                fallback="Requests appear here when an identity uses a connection."
              >
                Try another search or clear the filters.
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
                summaryClass="request-row"
                summary={
                  <>
                    <span class="resource-link">
                      <ConnectorIcon
                        preset={
                          m.view()!.config.accounts?.[record().facts.account]
                            ?.preset ?? "custom"
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
                  ? "This identity does not have permission for this action."
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
                  <dt>Identity</dt>
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
                          href={href("account", r().facts.account)}
                        >
                          <ConnectorIcon preset={account().preset} />
                          {r().facts.account}
                          <Icon name="arrow" />
                        </a>
                      )}
                    </Show>
                  </dd>
                </div>
                <Show when={destination()}>
                  <div>
                    <dt>Destination</dt>
                    <dd>{destination()}</dd>
                  </div>
                </Show>
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
              <Show when={r().reviews?.length}>
                <div class="request-reasons">
                  <h3>Review</h3>
                  <For each={r().reviews}>
                    {(answer) => (
                      <p>
                        <strong>
                          {answer.by === "tinfoil" ? "Tinfoil" : "You"}
                        </strong>
                        {answer.decision === "escalate"
                          ? " asked for your decision"
                          : answer.decision === "once"
                            ? " approved"
                            : answer.decision === "deny"
                              ? " denied"
                              : " saved a rule"}
                        <Show when={answer.reason}>: {answer.reason}</Show>
                      </p>
                    )}
                  </For>
                </div>
              </Show>
              <Show when={reasons().length}>
                <div class="request-reasons">
                  <h3>
                    {r().invalid
                      ? "Why the request was rejected"
                      : state() === "refused" || state() === "denied"
                        ? "Why it was blocked"
                        : state() === "pending"
                          ? "Approval needed"
                          : "Policy review"}
                  </h3>
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
                  <a class="button" href={href("account", r().facts.account)}>
                    {r().invalid ? "View connection setup" : "Change access"}
                    <Icon name="arrow" />
                  </a>
                  <p class="muted">
                    {r().invalid
                      ? "Fix the request or client configuration using the error above, then retry."
                      : "Update this identity’s connection access, then retry the request from your identity."}
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
                    <h3>Effective changes</h3>
                    <pre>
                      {policy().effective_diff || "No effective changes."}
                    </pre>
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
              <LazyDetails
                class="request-technical"
                data-disclosure="request"
                summaryClass="request-technical-toggle"
                summary={
                  <>
                    <span>View details</span>
                    <Icon name="arrow" />
                  </>
                }
              >
                {() => (
                  <div class="request-technical-body">
                    <Show when={r().facts.details?.http}>
                      {(http) => (
                        <p class="mono">
                          {http().method} {http().host}
                          {http().path}
                        </p>
                      )}
                    </Show>
                    <h3>Policy facts</h3>
                    <pre>{JSON.stringify(r().facts, null, 2)}</pre>
                    <Show when={r().grant}>
                      <h3>Approval scope</h3>
                      <pre>{JSON.stringify(r().grant, null, 2)}</pre>
                    </Show>
                    <Show when={m.view()!.config.accounts?.[r().facts.account]}>
                      {(account) => (
                        <a
                          class="request-preset-link"
                          href={href("preset", account().preset, r().id)}
                        >
                          Edit preset
                          <Icon name="arrow" />
                        </a>
                      )}
                    </Show>
                  </div>
                )}
              </LazyDetails>
            </section>
          );
        }}
      </Show>
    </div>
  );
}
