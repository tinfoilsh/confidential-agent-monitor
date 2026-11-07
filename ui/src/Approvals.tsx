import {
  For,
  Index,
  Show,
  createEffect,
  createMemo,
  createRoot,
  getOwner,
  onCleanup,
  type JSX,
} from "solid-js";
import { Toaster, toast } from "solid-sonner";
import * as owner from "./owner.js";
import {
  ConnectorIcon,
  Empty,
  Icon,
  LazyDetails,
  RemoveRule,
  ResourceDisclosure,
  RuleText,
  createRecord,
  href,
} from "./components";
import { useMonitor } from "./monitor";
import { ConnectionProposals } from "./PolicyProposals";

type ToolChange = owner.Review["changes"][number];
// Below the 64px top bar that holds the menu on narrow screens.
const MOBILE_TOAST_TOP = 72;

// Allow once and Deny sit together; Allow always, which saves a rule, stands apart.
export function ApprovalActions(props: {
  record: owner.RequestRecord;
  saveTitle?: string;
  onDismiss?: () => void;
}) {
  const m = useMonitor();
  const can = () => owner.decisions(props.record, m.now());
  return (
    <Show when={Object.values(can()).some(Boolean)}>
      <div class="decision-buttons">
        <Show when={can().once}>
          <button
            class="allow"
            onClick={() => void m.decide(props.record, "once")}
          >
            Allow once
          </button>
        </Show>
        <Show when={can().deny}>
          <button
            class="danger"
            onClick={() => void m.decide(props.record, "deny")}
          >
            Deny
          </button>
        </Show>
        <Show when={can().dismiss && props.onDismiss}>
          {(dismiss) => <button onClick={() => dismiss()()}>Dismiss</button>}
        </Show>
        <Show when={can().save}>
          <button
            class="primary"
            title={props.saveTitle}
            onClick={() => void m.decide(props.record, "save")}
          >
            Allow always
          </button>
        </Show>
      </div>
    </Show>
  );
}

function ApprovalNotice(props: {
  icon: JSX.Element;
  title: string;
  meta: JSX.Element;
  onClose?: () => void;
  children: JSX.Element;
}) {
  return (
    <article class="approval-card" aria-label={props.title}>
      {props.icon}
      <strong class="approval-title" title={props.title}>
        {props.title}
      </strong>
      <p class="approval-meta">{props.meta}</p>
      {props.children}
      <Show when={props.onClose}>
        {(close) => (
          <button
            type="button"
            class="icon-button approval-close"
            aria-label="Hide this notice"
            title="Hide"
            onClick={() => close()()}
          >
            <Icon name="close" />
          </button>
        )}
      </Show>
    </article>
  );
}

// The full record adds what Allow always would save and, in lists, why the
// request asks. Toasts keep to the summary: Sonner sizes a toast as it mounts.
function RequestApproval(props: {
  record: owner.RequestRecord;
  icon: JSX.Element;
  reasons?: boolean;
  onClose?: () => void;
}) {
  const m = useMonitor();
  const [full] = createRecord(() => ({
    api: m.api()!,
    id: props.record.id,
    segment: props.record.segment,
  }));
  const loaded = () => (full.error ? undefined : full());
  return (
    <ApprovalNotice
      icon={props.icon}
      title={owner.requestTitle((props.reasons && loaded()) || props.record)}
      meta={
        <>
          {props.record.facts.principal.name} ·{" "}
          {props.record.facts.connection || "Policy"} ·{" "}
          <span class="approval-time">
            {owner.timeLeft(props.record, m.now())} left
          </span>
        </>
      }
      onClose={props.onClose}
    >
      <For each={props.reasons && loaded() ? owner.reasons(loaded()!) : []}>
        {(reason) => <p class="approval-reason">{reason}</p>}
      </For>
      <ApprovalActions
        record={props.record}
        saveTitle={loaded() && owner.saveText(loaded()!)}
      />
    </ApprovalNotice>
  );
}

function ProposalApproval(props: {
  proposal: owner.RequestRecord;
  onClose: () => void;
}) {
  return (
    <ApprovalNotice
      icon={<Icon name="policy" />}
      title={props.proposal.facts.title || "Proposed change"}
      meta={
        <>
          {props.proposal.facts.principal.name} proposes a change to{" "}
          {props.proposal.facts.connection || "policy"}
        </>
      }
      onClose={props.onClose}
    >
      <div class="decision-buttons">
        <a
          class="button"
          href={href("connections", "pending", props.proposal.id)}
        >
          Review change
          <Icon name="arrow" />
        </a>
      </div>
    </ApprovalNotice>
  );
}

// Stacked notices for each pending request and proposal, shown until answered
// or closed. While hidden, they stay in place and new ones wait.
export function ApprovalToasts(props: { hidden: boolean }) {
  const m = useMonitor();
  const parent = getOwner();
  // Toast contents are created up front, so each lives in its own root.
  const shown = new Map<string, () => void>();
  const closed = new Set<string>();
  const release = (id: string) => {
    shown.get(id)?.();
    shown.delete(id);
  };
  const remove = (id: string) => {
    toast.dismiss(id);
    release(id);
  };
  const close = (id: string) => {
    closed.add(id);
    remove(id);
  };
  // The most urgent request comes last, so it lands at the front of the stack.
  const wanted = createMemo(
    () =>
      new Map<string, () => JSX.Element>([
        ...m.pendingProposals().map((proposal) => {
          const id = `proposal:${proposal.id}`;
          return [
            id,
            () => (
              <ProposalApproval
                proposal={m.recordsById().get(proposal.id) ?? proposal}
                onClose={() => close(id)}
              />
            ),
          ] as const;
        }),
        ...[...m.pendingRequests()].reverse().map((record) => {
          const id = `request:${record.id}`;
          return [
            id,
            () => (
              <RequestApproval
                record={m.recordsById().get(record.id) ?? record}
                icon={<Icon name="approval" />}
                onClose={() => close(id)}
              />
            ),
          ] as const;
        }),
      ]),
  );
  // Sonner stacks toasts by the order their heights are measured, so each
  // one is added in its own update, after the last one has mounted, and only
  // while shown, since a hidden toast measures no height.
  const queue: string[] = [];
  let draining = false;
  const next = () => {
    if (props.hidden || !queue.length) return void (draining = false);
    const id = queue.shift()!;
    const content = wanted().get(id);
    if (content && !shown.has(id) && !closed.has(id))
      createRoot((dispose) => {
        shown.set(id, dispose);
        toast.custom(content, {
          id,
          class: "approval-toast",
          duration: Infinity,
          onDismiss: () => {
            closed.add(id);
            release(id);
          },
        });
      }, parent);
    queueMicrotask(next);
  };
  createEffect(() => {
    const current = wanted();
    for (const id of [...shown.keys()]) if (!current.has(id)) remove(id);
    for (const id of current.keys())
      if (!shown.has(id) && !closed.has(id) && !queue.includes(id))
        queue.push(id);
    if (!props.hidden && queue.length && !draining) {
      draining = true;
      queueMicrotask(next);
    }
  });
  onCleanup(() => {
    queue.length = 0;
    [...shown.keys()].forEach(remove);
  });
  return (
    <div hidden={props.hidden}>
      <Toaster
        position="top-right"
        mobileOffset={{ top: MOBILE_TOAST_TOP }}
        gap={8}
        visibleToasts={3}
        containerAriaLabel="Approvals"
      />
    </div>
  );
}

// Everything waiting for the owner: requests, proposed changes, and MCP tools.
export function NeedsApproval(props: { proposal?: string }) {
  const m = useMonitor();
  const tools = createMemo(() => owner.toolReviews(m.view()!));
  const total = () =>
    m.pendingRequests().length + m.pendingProposals().length + tools().length;
  return (
    <>
      <Show
        when={
          props.proposal &&
          !m
            .pendingProposals()
            .some((proposal) => proposal.id === props.proposal)
        }
      >
        <div class="resource-list">
          <Empty
            title="Proposal no longer pending"
            icon="policy"
            action={
              <a class="button" href="#activity/proposals">
                View proposal history
              </a>
            }
          >
            It may have been reviewed, become outdated, or been discarded when
            the Perimeter restarted.
          </Empty>
        </div>
      </Show>
      <Show when={total()}>
        <section
          class="resource-list collection-list approval-list"
          aria-label="Needs approval"
        >
          <div class="resource-heading">
            <h2>
              Needs approval <span class="count">{total()}</span>
            </h2>
          </div>
          <For each={m.pendingRequests().map((record) => record.id)}>
            {(id) => (
              <Show when={m.recordsById().get(id)}>
                {(record) => (
                  <RequestApproval
                    record={record()}
                    icon={
                      <ConnectorIcon connection={record().facts.connection} />
                    }
                    reasons
                  />
                )}
              </Show>
            )}
          </For>
          <ConnectionProposals id={props.proposal} />
          <For each={tools()}>{(name) => <ToolReviewItem name={name} />}</For>
        </section>
      </Show>
    </>
  );
}

function ToolReviewItem(props: { name: string }) {
  const m = useMonitor();
  const review = createMemo(() => owner.review(m.view()!, props.name));
  return (
    <Show when={review()}>
      {(review) => (
        <ResourceDisclosure
          class="approval-tools-item"
          summaryClass="collection-row approval-tools-row"
          summary={
            <>
              <ConnectorIcon connection={props.name} />
              <span class="proposal-summary">
                <strong>{props.name}</strong>
                <small>{owner.connectionStatus(review())?.text}</small>
              </span>
              <span class="collection-chevron">
                <Icon name="arrow" />
              </span>
            </>
          }
        >
          {(active) => (
            <Show when={active()}>
              <div class="approval-tools-body">
                <p class="muted">{owner.toolReviewDescription(review())}</p>
                <ToolReview name={props.name} review={review()} />
              </div>
            </Show>
          )}
        </ResourceDisclosure>
      )}
    </Show>
  );
}

// One line per tool; its description, parameters, and definition open on demand.
export function ToolReview(props: { name: string; review: owner.Review }) {
  const m = useMonitor();
  return (
    <div class="tool-review">
      <ul class="tool-list">
        <Index each={props.review.changes}>
          {(change) => (
            <ToolItem
              change={change()}
              showKind={props.review.previouslyApproved}
            />
          )}
        </Index>
      </ul>
      <div class="tool-review-actions">
        <button
          class="allow"
          disabled={m.busy()}
          onClick={() =>
            void m.edit(owner.edits.approveTools(m.view()!, props.name))
          }
        >
          {props.review.previouslyApproved
            ? "Approve changes"
            : "Approve tools"}
        </button>
      </div>
    </div>
  );
}

const KIND_BADGE: Record<string, string> = {
  New: "status-approved",
  Changed: "status-pending",
  Removed: "status-denied",
};
const firstSentence = (text: string) =>
  text.trim().split(/(?<=[.!?])\s|\n/)[0] ?? "";

function ToolItem(props: { change: ToolChange; showKind: boolean }) {
  const description = () => props.change.tool?.description?.trim() ?? "";
  return (
    <li>
      <LazyDetails
        class="tool-item"
        summaryClass="tool-item-summary"
        summary={
          <>
            <span class="tool-item-text">
              <Show
                when={!props.change.instructions}
                fallback={<strong>Server instructions</strong>}
              >
                <code class="tool-name">{props.change.name}</code>
              </Show>
              <span class="tool-summary">
                {props.change.instructions
                  ? "What the server tells agents about its tools"
                  : firstSentence(description())}
              </span>
            </span>
            <span class="tool-badges">
              <Show when={props.change.tool?.annotations?.destructiveHint}>
                <span class="badge effect-delete">Destructive</span>
              </Show>
              <Show when={props.change.tool?.annotations?.readOnlyHint}>
                <span
                  class="badge"
                  title="The server says this tool only reads. The Perimeter treats it as a read, but cannot check that it changes nothing."
                >
                  Read-only
                </span>
              </Show>
              <Show when={props.showKind}>
                <span class={`badge ${KIND_BADGE[props.change.kind] ?? ""}`}>
                  {props.change.kind}
                </span>
              </Show>
            </span>
            <span class="collection-chevron">
              <Icon name="arrow" />
            </span>
          </>
        }
      >
        {() => <ToolDetails change={props.change} />}
      </LazyDetails>
    </li>
  );
}

function ToolDetails(props: { change: ToolChange }) {
  return (
    <div class="tool-item-body">
      <Show
        when={props.change.tool}
        fallback={
          <Show when={props.change.text}>
            <pre>{props.change.text}</pre>
          </Show>
        }
      >
        {(tool) => (
          <>
            <Show when={tool().description}>
              <p class="tool-source">Description from the service</p>
              <p class="tool-description">{tool().description}</p>
            </Show>
            <Show when={props.change.changedFields.length}>
              <div class="tool-detail">
                <h4>What changed</h4>
                <ul class="tool-field-changes">
                  <For each={props.change.changedFields}>
                    {(field) => (
                      <li>
                        {field.kind}: <code>{field.name}</code>
                      </li>
                    )}
                  </For>
                </ul>
              </div>
            </Show>
            <Show when={props.change.parameters.length}>
              <details class="tool-inputs">
                <summary>
                  Parameters{" "}
                  <span class="count">{props.change.parameters.length}</span>
                </summary>
                <dl class="tool-parameters">
                  <For each={props.change.parameters}>
                    {(parameter) => (
                      <div>
                        <dt>
                          <code>{parameter.name}</code>
                          <span class="muted">
                            {[
                              parameter.type,
                              parameter.required ? "required" : "optional",
                            ]
                              .filter(Boolean)
                              .join(" · ")}
                          </span>
                        </dt>
                        <Show when={parameter.description}>
                          <dd>{parameter.description}</dd>
                        </Show>
                      </div>
                    )}
                  </For>
                </dl>
              </details>
            </Show>
            <details class="tool-definition">
              <summary>Full definition</summary>
              <pre>{props.change.text || JSON.stringify(tool(), null, 2)}</pre>
            </details>
          </>
        )}
      </Show>
    </div>
  );
}

export function SavedRules() {
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
            Choose Allow always on a request to allow matching requests from
            then on.
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
