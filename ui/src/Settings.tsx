import { For, Show, createResource, createSignal, onCleanup } from "solid-js";
import * as owner from "./owner.js";
import {
  ConnectorIcon,
  Effects,
  Empty,
  Icon,
  LazyDetails,
  download,
  href,
} from "./components";
import { useMonitor } from "./monitor";

export function Settings(props: {
  theme: string;
  onThemeChange: (theme: string) => void;
}) {
  const m = useMonitor(),
    [networks, setNetworks] = createSignal(
      (m.view()!.config.allow_networks ?? []).join("\n"),
    );
  return (
    <div id="pane">
      <p>Permissions and guardrails save automatically.</p>
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
        <h2>Default permissions</h2>
        <label class="setting-row">
          <span>
            Allow paid AI inference
            <small>
              Use paid AI models without payment approval. Provider charges and
              explicit payment settings still apply.
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
        <Effects />
        <details class="settings-help">
          <summary>How defaults work</summary>
          <p>
            These defaults apply to all identities. Connections and identities can
            override them. Select an active permission again to use the
            inherited setting.
          </p>
          <p>
            Explicit payment settings also apply to paid AI inference. Access
            permissions, guardrails, and custom rules still apply.
          </p>
        </details>
      </section>
      <section class="settings-section">
        <h2>Guardrails</h2>
        <For each={["confidentiality", "integrity"] as const}>
          {(lattice) => (
            <label class="setting-row">
              <span>
                {lattice === "confidentiality"
                  ? "Confidentiality"
                  : "Integrity"}
                <small>
                  {lattice === "confidentiality"
                    ? "Restrict where identities can send private data."
                    : "Restrict sensitive actions after identities read untrusted content."}
                </small>
              </span>
              <input
                type="checkbox"
                role="switch"
                checked={owner.lattices(m.view()!)[lattice]}
                onChange={(e) =>
                  void m.edit(
                    owner.edits.setLattice(lattice, e.currentTarget.checked),
                  )
                }
              />
            </label>
          )}
        </For>
        <details class="settings-help">
          <summary>About guardrails</summary>
          <p>
            Applies to all identities and connector requests. Confidentiality is on
            by default; integrity is off by default.
          </p>
          <p>
            Labels keep their history while enforcement is off. Access
            permissions, explicit approvals, and custom rules still apply.
          </p>
        </details>
      </section>
      <section class="settings-section">
        <h2>Advanced</h2>
        <form
          class="settings-network-editor"
          onSubmit={(e) => {
            e.preventDefault();
            try {
              void m.edit(owner.edits.setNetworks(networks()));
            } catch (cause) {
              m.report(cause);
            }
          }}
        >
          <label>
            Private networks
            <textarea
              rows={4}
              aria-label="Private networks"
              placeholder="Networks the monitor may reach, one per line"
              value={networks()}
              onInput={(e) => setNetworks(e.currentTarget.value)}
            />
          </label>
          <button disabled={m.busy()}>Save networks</button>
        </form>
        <a class="setting-row settings-link" href="#policy">
          Policy editor <span>›</span>
        </a>
        <a class="setting-row settings-link" href="#presets">
          Connection preset editor <span>›</span>
        </a>
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
              <a class="resource-link" href={href("account", rule().account)}>
                <ConnectorIcon
                  preset={
                    m.view()!.config.accounts?.[rule().account]?.preset ??
                    "custom"
                  }
                />
                <span>
                  <strong>{owner.ruleTitle(m.view()!, rule())}</strong>
                  <small>
                    {name} · {rule().account}
                  </small>
                  <small class="rule-scope">
                    <For
                      each={Object.entries(rule().scope ?? {})}
                      fallback="Any request"
                    >
                      {([key, value]) => {
                        const text = `${key}: ${typeof value === "string" ? value : JSON.stringify(value)}`;
                        return <code title={text}>{text}</code>;
                      }}
                    </For>
                  </small>
                  <small>
                    {rule().operation
                      ? `Skips ${owner.ruleWaives(rule()).join(", ")}`
                      : "Inactive: saved before approvals named an operation"}
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
      <a href="#settings">Back to settings</a>
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
  const review = async () => {
    const draft = source();
    setChecking(true);
    setPreview(undefined);
    try {
      const diff = await m.api()!.previewPolicy(draft);
      if (source() === draft) setPreview({ source: draft, diff });
    } catch (cause) {
      m.report(cause);
    } finally {
      setChecking(false);
    }
  };
  return (
    <>
      <section>
        <p>
          This file controls saved permissions. Changes made elsewhere in
          Monitor update it too. Credentials are stored separately.
        </p>
        <div class="credential-actions">
          <button
            onClick={() => {
              if (
                source() === props.saved.source ||
                confirm("Discard this draft and reload the active policy?")
              )
                props.reload();
            }}
          >
            Reload active file
          </button>
          <button
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
            Download active policy.toml
          </button>
        </div>
      </section>
      <section>
        <label>
          policy.toml
          <textarea
            rows={30}
            spellcheck={false}
            value={source()}
            onInput={(e) => {
              setSource(e.currentTarget.value);
              setPreview(undefined);
            }}
          />
        </label>
      </section>
      <section>
        <div class="credential-actions">
          <button
            disabled={checking() || m.busy()}
            onClick={() => void review()}
          >
            Validate and review diff
          </button>
          <button
            class="primary"
            disabled={!preview() || checking() || m.busy()}
            onClick={async () => {
              const reviewed = preview();
              if (
                reviewed &&
                reviewed.source === source() &&
                (await m.perform((client) =>
                  client.applyPolicy(reviewed.source),
                ))
              ) {
                setPreview(undefined);
                props.reload();
              }
            }}
          >
            Apply reviewed change
          </button>
        </div>
      </section>
      <Show when={preview()}>
        {(reviewed) => (
          <section>
            <h2>Source changes</h2>
            <pre>{reviewed().diff.source_diff || "No source changes."}</pre>
            <h2>Effective changes</h2>
            <pre>
              {reviewed().diff.effective_diff || "No effective changes."}
            </pre>
          </section>
        )}
      </Show>
      <section>
        <LazyDetails summary="Effective policy, including preset definitions">
          {() => <EffectivePolicy />}
        </LazyDetails>
      </section>
    </>
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
export function PresetEditor(props: { name: string; request?: string }) {
  const m = useMonitor();
  const [request, setRequest] = createSignal<owner.RequestRecord>();
  const lifetime = new AbortController();
  onCleanup(() => lifetime.abort());
  const [file, { refetch }] = createResource(async () => {
    const [file, context] = await Promise.all([
      props.name
        ? m.api()!.preset(props.name, lifetime.signal)
        : owner.NEW_PRESET,
      props.request
        ? m.api()!.request(props.request, lifetime.signal)
        : undefined,
    ]);
    setRequest(context);
    return owner.withDraft(file, context);
  });
  return (
    <div id="pane">
      <a href="#presets">Back to presets</a>
      <Show when={file.error}>
        <p role="alert">{String(file.error)}</p>
        <button onClick={() => void refetch()}>Retry</button>
      </Show>
      <Show
        when={!file.error && file()}
        keyed
        fallback={!file.error && <p>Loading preset…</p>}
      >
        {(previous) => {
          const [name, setName] = createSignal(props.name),
            [text, setText] = createSignal(owner.presetText(previous));
          return (
            <section>
              <p class="muted">
                Changes apply to every connection using this preset:{" "}
                {Object.entries(m.view()!.config.accounts ?? {})
                  .filter(([, account]) => account.preset === props.name)
                  .map(([name]) => name)
                  .join(", ") || "none yet"}
                .
              </p>
              <Show when={request()}>
                {(record) => (
                  <>
                    <h2>{owner.requestTitle(record())}</h2>
                    <ul>
                      <For each={record().deny ?? []}>
                        {(reason) => <li>{reason}</li>}
                      </For>
                    </ul>
                    <p>
                      Review the request and its settings, then retry from your
                      identity after saving corrections.
                    </p>
                    <p>
                      <a href={href("request", record().id)}>Back to request</a>{" "}
                      ·{" "}
                      <a href={href("account", record().facts.account)}>
                        Connection settings
                      </a>
                    </p>
                  </>
                )}
              </Show>
              <form
                onSubmit={async (e) => {
                  e.preventDefault();
                  try {
                    if (
                      await m.edit(
                        owner.edits.savePreset(name(), text(), previous),
                      )
                    )
                      location.hash = href("preset", name());
                  } catch (cause) {
                    m.report(cause);
                  }
                }}
              >
                <label>
                  Preset name
                  <input
                    required
                    value={name()}
                    disabled={!!props.name}
                    onInput={(e) => setName(e.currentTarget.value)}
                  />
                </label>
                <label>
                  Preset JSON
                  <textarea
                    rows={30}
                    spellcheck={false}
                    value={text()}
                    onInput={(e) => setText(e.currentTarget.value)}
                  />
                </label>
                <div class="credential-actions">
                  <button class="primary" disabled={m.busy()}>
                    Save preset
                  </button>
                  <button
                    type="button"
                    onClick={() =>
                      download(
                        text(),
                        `${name() || "preset"}.json`,
                        "application/json",
                      )
                    }
                  >
                    Download preset
                  </button>
                  <Show
                    when={props.name && m.view()!.config.presets?.[props.name]}
                  >
                    <button
                      type="button"
                      class="danger"
                      disabled={m.busy()}
                      onClick={async () => {
                        if (
                          confirm(`Remove custom preset ${props.name}?`) &&
                          (await m.edit(owner.edits.removePreset(props.name)))
                        )
                          location.hash = "#presets";
                      }}
                    >
                      Remove custom preset
                    </button>
                  </Show>
                </div>
              </form>
            </section>
          );
        }}
      </Show>
    </div>
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
