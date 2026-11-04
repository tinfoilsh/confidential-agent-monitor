import {
  For,
  Show,
  createMemo,
  createResource,
  createSignal,
  onCleanup,
} from "solid-js";
import * as owner from "./owner.js";
import {
  ConnectorIcon,
  Empty,
  Icon,
  LazyDetails,
  createDialogMotion,
  download,
  href,
} from "./components";
import { useMonitor } from "./monitor";

export function Settings(props: {
  theme: string;
  onThemeChange: (theme: string) => void;
}) {
  const m = useMonitor();
  return (
    <div id="pane">
      <p>Permissions save automatically.</p>
      <section class="settings-section">
        <h2>Appearance</h2>
        <div class="setting-row">
          <span>Color theme</span>
          <span class="seg" role="group" aria-label="Color theme">
            <For
              each={[
                ["system", "System", "devices"],
                ["light", "Light", "sun"],
                ["dark", "Dark", "moon"],
              ]}
            >
              {([theme, title, icon]) => (
                <button
                  type="button"
                  classList={{ primary: props.theme === theme }}
                  aria-label={`${title} theme`}
                  aria-pressed={props.theme === theme}
                  title={`${title} theme`}
                  onClick={() => props.onThemeChange(theme)}
                >
                  <Icon name={icon} />
                </button>
              )}
            </For>
          </span>
        </div>
      </section>
      <section class="settings-section">
        <h2>Payments</h2>
        <label class="setting-row">
          <span>
            Ask before any payment
            <small>
              A sandbox must get your approval for anything that spends
              money.
            </small>
          </span>
          <input
            type="checkbox"
            role="switch"
            checked={(m.view()!.config.effects?.pay ?? "ask") !== "allow"}
            onChange={(e) =>
              void m.edit(
                owner.edits.setEffect(
                  {},
                  "pay",
                  e.currentTarget.checked ? "ask" : "allow",
                ),
              )
            }
          />
        </label>
        <label class="setting-row">
          <span>
            Allow AI inference without asking
            <small>
              Paid model calls (Tinfoil, OpenAI, …) go through without
              approval. Other payments still ask.
            </small>
          </span>
          <input
            type="checkbox"
            role="switch"
            checked={m.view()!.config.allow_paid_inference}
            onChange={(e) =>
              void m.edit(owner.edits.setPaidInference(e.currentTarget.checked))
            }
          />
        </label>
      </section>
      <section class="settings-section settings-danger">
        <h2>Dangerous</h2>
        <label class="setting-row">
          <span>
            Allow everything
            <small>
              Ignore connections. Every sandbox can reach any host on any
              port, and nothing asks.
            </small>
          </span>
          <input
            type="checkbox"
            role="switch"
            checked={owner.networkingOpen(m.view()!)}
            onChange={(e) => {
              const open = e.currentTarget.checked;
              if (
                open &&
                !confirm(
                  "Allow everything? Sandboxes will be able to reach any host without asking.",
                )
              ) {
                e.currentTarget.checked = false;
                return;
              }
              void m.edit(owner.edits.setNetworkingOpen(m.view()!, open));
            }}
          />
        </label>
      </section>
    </div>
  );
}
export function Rules() {
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
              <a class="resource-link" href={href("connection", rule().account)}>
                <ConnectorIcon
                  preset={
                    m.view()!.config.accounts?.[rule().account]?.preset ?? ""
                  }
                />
                <span>
                  <strong>{owner.ruleTitle(m.view()!, rule())}</strong>
                  <small class="rule-scope">
                    {(() => {
                      const text = owner.scopeText(
                        m.view()!,
                        rule().account,
                        rule().scope ?? {},
                      );
                      return typeof text === "string" ? (
                        <code title={text}>{text}</code>
                      ) : (
                        <For each={text} fallback="Any request">
                          {(t) => <code title={t}>{t}</code>}
                        </For>
                      );
                    })()}
                  </small>
                  <small>
                    {name} · {rule().account}
                    {rule().operation
                      ? ""
                      : " · Inactive: saved before approvals named an operation"}
                  </small>

                </span>
              </a>
              <button
                disabled={m.busy()}
                onClick={() => void m.edit(owner.edits.removeRule(name, id))}
              >
                Remove
              </button>
            </div>
          );
        }}
      </For>
    </div>
  );
}
export function Policy() {
  const m = useMonitor();
  const lifetime = new AbortController();
  onCleanup(() => lifetime.abort());
  const [file, { refetch }] = createResource(() =>
    m.api()!.policy(false, lifetime.signal),
  );
  return (
    <div id="pane">
      <a class="button back-button" href="#settings">
        <Icon name="arrow" />
        Back to settings
      </a>
      <Show when={file.error}>
        <p role="alert">{String(file.error)}</p>
        <button onClick={() => void refetch()}>Retry</button>
      </Show>
      <Show
        when={!file.error && file()}
        keyed
        fallback={!file.error && <p>Loading policy…</p>}
      >
        {(saved) => (
          <PolicyEditor saved={saved} reload={() => void refetch()} />
        )}
      </Show>
    </div>
  );
}
function PolicyEditor(props: {
  saved: { source: string; effective?: string };
  reload: () => void;
}) {
  const m = useMonitor(),
    [source, setSource] = createSignal(props.saved.source),
    [preview, setPreview] = createSignal<{
      source: string;
      diff: owner.PolicyDiff;
    }>();
  const [checking, setChecking] = createSignal(false);
  const [error, setError] = createSignal("");
  const dirty = () => source() !== props.saved.source;
  const lifetime = new AbortController();
  onCleanup(() => lifetime.abort());
  let dialog!: HTMLDialogElement;
  const reviewed = createMemo<ReturnType<typeof preview>>(
    (previous) => preview() ?? previous,
  );
  createDialogMotion(
    () => dialog,
    () => !!preview(),
  );
  const closeReview = () => {
    if (!m.busy()) setPreview(undefined);
  };
  const review = async () => {
    if (checking() || m.busy() || !dirty()) return;
    const draft = source();
    setChecking(true);
    setError("");
    setPreview(undefined);
    try {
      const diff = await m.api()!.previewPolicy(draft, lifetime.signal);
      if (source() === draft) setPreview({ source: draft, diff });
    } catch (cause) {
      if (!lifetime.signal.aborted && source() === draft)
        setError(cause instanceof Error ? cause.message : String(cause));
    } finally {
      setChecking(false);
    }
  };
  const apply = async () => {
    const change = preview();
    if (!change || change.source !== source() || m.busy()) return;
    setError("");
    if (
      await m.perform(
        (client) => client.applyPolicy(change.source),
      )
    ) {
      setPreview(undefined);
      props.reload();
    } else {
      setError(m.error());
    }
  };
  return (
    <>
      <section class="policy-editor" aria-labelledby="policy-source-label">
        <header class="policy-editor-toolbar">
          <div class="policy-editor-title">
            <Icon name="policy" />
            <label id="policy-source-label" for="policy-source">
              policy.toml
            </label>
          </div>
          <div class="form-actions">
            <button
              class="icon-button"
              aria-label="Reload active policy"
              title="Reload active policy"
              disabled={checking() || m.busy()}
              onClick={() => {
                if (
                  !dirty() ||
                  confirm("Discard this draft and reload the active policy?")
                )
                  props.reload();
              }}
            >
              <Icon name="refresh" />
            </button>
            <button
              class="icon-button"
              aria-label="Download active policy.toml"
              title="Download active policy.toml"
              onClick={() =>
                void m
                  .api()!
                  .policy()
                  .then(
                    (file) =>
                      download(file.source, "policy.toml", "application/toml"),
                    m.report,
                  )
              }
            >
              <Icon name="download" />
            </button>
          </div>
        </header>
        <p class="policy-editor-description" id="policy-source-description">
          Manage your monitor’s permissions. Changes in Settings are reflected
          here too.
        </p>
        <textarea
          id="policy-source"
          aria-describedby="policy-source-description"
          aria-invalid={!!error() && !preview()}
          aria-errormessage={error() && !preview() ? "policy-error" : undefined}
          rows={22}
          wrap="off"
          spellcheck={false}
          value={source()}
          onInput={(e) => {
            setSource(e.currentTarget.value);
            setPreview(undefined);
            setError("");
          }}
        />
        <Show when={error() && !preview()}>
          <p class="policy-error" id="policy-error" role="alert">
            {error()}
          </p>
        </Show>
        <footer class="policy-editor-footer">
          <Show when={dirty()}>
            <span class="policy-save-status" role="status">
              Unsaved changes
            </span>
          </Show>
          <button
            class="primary"
            disabled={!dirty() || checking() || m.busy()}
            aria-busy={checking()}
            onClick={() => void review()}
          >
            <Icon name="rules" />
            {checking() ? "Validating…" : "Review & apply"}
          </button>
        </footer>
      </section>
      <p class="policy-editor-note">
        Changes are validated before you apply them. Credentials are stored
        separately.
      </p>
      <section class="policy-effective">
        <LazyDetails
          summary={
            <>
              Effective policy
              <span class="muted">Includes preset definitions</span>
            </>
          }
        >
          {() => <EffectivePolicy />}
        </LazyDetails>
      </section>
      <dialog
        ref={dialog}
        id="policy-review-dialog"
        aria-labelledby="policy-review-title"
        aria-describedby="policy-review-description"
        onCancel={(event) => {
          event.preventDefault();
          closeReview();
        }}
      >
        <header class="dialog-header">
          <div>
            <h1 id="policy-review-title">Review policy changes</h1>
            <p id="policy-review-description">
              Validation passed. Review your changes before applying them.
            </p>
          </div>
          <button
            class="dialog-close icon-button"
            aria-label="Close review"
            disabled={m.busy()}
            onClick={closeReview}
          >
            <Icon name="close" />
          </button>
        </header>
        <div class="dialog-body">
          <Show when={reviewed()}>
            {(change) => (
              <>
                <h2>Changes to policy.toml</h2>
                <PolicyChanges
                  diff={change().diff.source_diff}
                  empty="No source changes."
                />
                <LazyDetails summary="Effective permission changes">
                  {() => (
                    <PolicyChanges
                      diff={change().diff.effective_diff}
                      empty="No effective permission changes."
                    />
                  )}
                </LazyDetails>
              </>
            )}
          </Show>
          <Show when={error()}>
            <p class="policy-error" role="alert">
              {error()}
            </p>
          </Show>
        </div>
        <footer class="policy-editor-footer">
          <button disabled={m.busy()} onClick={closeReview}>
            Keep editing
          </button>
          <button
            class="primary"
            disabled={
              m.busy() ||
              !preview() ||
              (!preview()!.diff.source_diff && !preview()!.diff.effective_diff)
            }
            aria-busy={m.busy()}
            onClick={() => void apply()}
          >
            {m.busy() ? "Applying…" : "Apply changes"}
          </button>
        </footer>
      </dialog>
    </>
  );
}
function PolicyChanges(props: { diff: string; empty: string }) {
  return (
    <Show when={props.diff} fallback={<p class="muted">{props.empty}</p>}>
      <pre class="policy-diff">
        <For each={props.diff.split("\n")}>
          {(line) => (
            <span
              classList={{
                "diff-added": line.startsWith("+"),
                "diff-removed": line.startsWith("-"),
                "diff-heading": line.startsWith("@@"),
              }}
            >
              {line || " "}
            </span>
          )}
        </For>
      </pre>
    </Show>
  );
}
function EffectivePolicy() {
  const m = useMonitor(),
    lifetime = new AbortController();
  onCleanup(() => lifetime.abort());
  const [file, { refetch }] = createResource(() =>
    m.api()!.policy(true, lifetime.signal),
  );
  return (
    <Show
      when={!file.error}
      fallback={
        <>
          <p role="alert">{String(file.error)}</p>
          <button onClick={() => void refetch()}>Retry</button>
        </>
      }
    >
      <Show when={file()} fallback={<p>Loading effective policy…</p>}>
        {(value) => <pre>{value().effective}</pre>}
      </Show>
    </Show>
  );
}
export function Integrations(props: { page: string }) {
  const m = useMonitor();
  const page = () =>
    Object.hasOwn(owner.INTEGRATION_PAGES, props.page) ? props.page : "start";
  return (
    <>
      <nav class="integration-nav" aria-label="Integration guides">
        <For each={Object.entries(owner.INTEGRATION_PAGES)}>
          {([key, title]) => (
            <a
              href={href("integrations", key)}
              aria-current={page() === key ? "page" : undefined}
            >
              {title}
            </a>
          )}
        </For>
      </nav>
      {/* The shared guide escapes inserted values and emits our static markup. */}
      <article
        class="integration-guide"
        innerHTML={owner.integrationGuide(
          m.view()!,
          page(),
          ([kind, ...args]) => href(kind, ...args),
        )}
        onClick={(e) => {
          const button = (e.target as HTMLElement).closest<HTMLButtonElement>(
            "button[data-copy]",
          );
          const code = button?.previousElementSibling;
          if (code)
            void navigator.clipboard.writeText(code.textContent ?? "").then(
              () => m.notify("Copied"),
              () => {
                const range = document.createRange(),
                  selection = window.getSelection();
                range.selectNodeContents(code);
                selection?.removeAllRanges();
                selection?.addRange(range);
                m.notify("Text selected. Press Cmd-C or Ctrl-C to copy.");
              },
            );
        }}
      />
    </>
  );
}
