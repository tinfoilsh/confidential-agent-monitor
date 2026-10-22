import {
  For,
  Show,
  Suspense,
  createMemo,
  createSignal,
  createUniqueId,
  lazy,
} from "solid-js";
import { createStore } from "solid-js/store";
import * as owner from "./owner.js";
import {
  ConnectorIcon,
  Copy,
  DataPermissions,
  Effects,
  Empty,
  Field,
  Icon,
  LazyDetails,
  ResourceDisclosure,
  Search,
  createDialogMotion,
  href,
} from "./components";
import { useMonitor } from "./monitor";
import { AgentConnectionAccess } from "./Agents";

const Browser = lazy(() =>
  import("./Browser").then((m) => ({ default: m.Browser })),
);

export function DeviceSignInDialog(props: {
  attempt: (owner.DeviceSignIn & { title: string; preset: string }) | undefined;
}) {
  const m = useMonitor();
  // Retain the code and provider while the dialog fades out.
  const attempt = createMemo<typeof props.attempt>(
    (previous) => props.attempt ?? previous,
  );
  let dialog!: HTMLDialogElement, code!: HTMLElement;
  createDialogMotion(
    () => dialog,
    () => !!props.attempt,
  );
  return (
    <dialog
      ref={dialog}
      id="device-sign-in-dialog"
      aria-labelledby="device-sign-in-title"
      aria-describedby="device-sign-in-description"
      onCancel={(event) => {
        event.preventDefault();
        m.cancelSignIn();
      }}
    >
      <Show when={attempt()} keyed>
        {(attempt) => (
          <>
            <header class="device-sign-in-heading">
              <ConnectorIcon preset={attempt.preset} />
              <h1 id="device-sign-in-title">Sign in with {attempt.title}</h1>
              <button
                class="dialog-close icon-button"
                aria-label="Cancel sign-in"
                onClick={m.cancelSignIn}
              >
                <Icon name="close" />
              </button>
            </header>
            <div class="dialog-body device-sign-in-body">
              <p id="device-sign-in-description">
                Enter this code on the sign-in page.
              </p>
              <div class="device-sign-in-code">
                <code
                  ref={code}
                  id="device-sign-in-code"
                  aria-label="One-time code"
                >
                  {attempt.user_code}
                </code>
                <Copy
                  text={attempt.user_code}
                  label="Copy one-time code"
                  target={() => code}
                  icon
                />
              </div>
              <a
                class="button primary device-sign-in-continue"
                href={attempt.url}
                target="_blank"
                rel="noopener noreferrer"
              >
                Continue to {attempt.title}
                <Icon name="external" />
              </a>
            </div>
          </>
        )}
      </Show>
    </dialog>
  );
}

export function Connections(props: { expanded?: string }) {
  const m = useMonitor(),
    [query, setQuery] = m.search("accounts");
  if (props.expanded) setQuery("");
  const searchable = createMemo(() =>
    Object.keys(m.view()!.config.accounts ?? {})
      .sort()
      .map((name) => ({
        name,
        search:
          `${name} ${owner.presetOf(m.view()!, name).title}`.toLowerCase(),
      })),
  );
  const names = createMemo(() => {
    const search = query().toLowerCase();
    return searchable()
      .filter((entry) => entry.search.includes(search))
      .map((entry) => entry.name);
  });
  return (
    <>
      <div id="toolbar">
        <Search label="Search connections" value={query()} onInput={setQuery} />
      </div>
      <div class="resource-list collection-list">
        <div class="resource-heading">
          <h2>
            Connections <span class="count">{names().length}</span>
          </h2>
        </div>
        <For
          each={names()}
          fallback={
            <Empty
              title={query() ? "No matching connections" : "No connections yet"}
              action={
                <Show when={!query()}>
                  <a class="button primary" href="#catalog">
                    <Icon name="plus" />
                    Add connection
                  </a>
                </Show>
              }
            >
              Add a connection to give your identities access to a service.
            </Empty>
          }
        >
          {(name) => {
            const status = createMemo(() =>
              owner.accountStatus(m.view()!, name),
            );
            return (
              <ResourceDisclosure
                class="connection-item"
                open={props.expanded === name}
                summary={
                  <>
                    <ConnectorIcon
                      preset={m.view()!.config.accounts![name].preset}
                    />
                    <strong class="collection-name" title={name}>
                      {m.view()!.config.accounts![name].preset === "tcp"
                        ? owner.presetOf(m.view()!, name).title
                        : name}
                    </strong>
                    <span class="collection-description">
                      {m.view()!.config.accounts![name].preset === "tcp"
                        ? name
                        : owner.presetOf(m.view()!, name).title}
                    </span>
                    <span class="resource-meta">
                      <span
                        class={`badge${status().state === "connecting" ? "" : ` status-${status().state === "error" ? "denied" : status().blocked ? "pending" : "approved"}`}`}
                      >
                        {status().blocked
                          ? `${status().blocked} tools await review`
                          : status().state === "error"
                            ? "Connection error"
                            : status().state === "connecting"
                              ? "Connecting…"
                              : "Configured"}
                      </span>
                    </span>
                    <span class="collection-chevron">
                      <Icon name="arrow" />
                    </span>
                  </>
                }
              >
                {(expanded) => (
                  <div class="connection-inline">
                    <Connection name={name} active={expanded()} />
                  </div>
                )}
              </ResourceDisclosure>
            );
          }}
        </For>
      </div>
    </>
  );
}
export function Catalog(props: { edit?: boolean }) {
  let catalog!: HTMLDivElement;
  const m = useMonitor(),
    [query, setQuery] = m.search(props.edit ? "presets" : "catalog");
  const groups = createMemo(() => owner.catalog(m.view()!));
  const filtered = createMemo(() => {
    const search = query().toLowerCase();
    return new Map(
      groups().map((group) => [
        group.group,
        {
          ...group,
          presets: group.presets.filter((p) =>
            `${p.name} ${p.title} ${group.title}`
              .toLowerCase()
              .includes(search),
          ),
        },
      ]),
    );
  });
  return (
    <div ref={catalog}>
      <div class="catalog-toolbar">
        <Search
          label={props.edit ? "Search presets" : "Search services"}
          value={query()}
          onInput={setQuery}
          autofocus={!props.edit}
          onEnter={() =>
            catalog
              .querySelector<HTMLAnchorElement>("details[open] .collection-row")
              ?.click()
          }
        />
      </div>
      <For each={groups().map((g) => g.group)}>
        {(id) => {
          const group = () => filtered().get(id)!;
          const presets = createMemo(
            () => new Map(group().presets.map((p) => [p.name, p])),
          );
          return (
            <Show when={group().presets.length}>
              <details open class="resource-list collection-list">
                <summary class="resource-heading">
                  <span class="collection-chevron">
                    <Icon name="arrow" />
                  </span>
                  <h2>
                    {group().title}{" "}
                    <span class="count">{group().presets.length}</span>
                  </h2>
                </summary>
                <div class="collection-rows">
                  <For each={[...presets().keys()]}>
                    {(name) => (
                      <a
                        class="resource-row collection-row"
                        href={href(props.edit ? "preset" : "add", name)}
                      >
                        <ConnectorIcon preset={name} />
                        <strong
                          class="collection-name"
                          title={m.view()!.presets[name].title}
                        >
                          {m.view()!.presets[name].title}
                        </strong>
                        <span class="resource-meta">
                          <Show when={presets().get(name)?.accounts}>
                            {(count) => (
                              <span class="muted">
                                {count()}{" "}
                                {count() === 1 ? "connection" : "connections"}
                              </span>
                            )}
                          </Show>
                        </span>
                        <Icon name="arrow" />
                      </a>
                    )}
                  </For>
                </div>
              </details>
            </Show>
          );
        }}
      </For>
      <Show when={![...filtered().values()].some((g) => g.presets.length)}>
        <Empty title="No matching services">Try a different search.</Empty>
      </Show>
    </div>
  );
}
const answers = (a?: Partial<owner.AccountAnswers>): owner.AccountAnswers => ({
  contents: a?.contents ?? "me",
  sends: a?.sends ?? "me",
  strangers: !!a?.strangers,
});
function ApiFields(props: {
  value: owner.ApiSettings;
  onChange: (value: owner.ApiSettings) => void;
}) {
  const field = (key: keyof owner.ApiSettings, value: string) =>
    props.onChange({ ...props.value, [key]: value });
  return (
    <>
      <label>
        API URL
        <input
          type="url"
          required
          placeholder="https://api.example.com"
          value={props.value.url}
          onInput={(e) => field("url", e.currentTarget.value)}
        />
      </label>
      <p class="muted">
        The credential is used only at this address and its paths.
      </p>
      <label>
        Authentication
        <select
          value={props.value.auth}
          onChange={(e) => field("auth", e.currentTarget.value)}
        >
          <option value="bearer">Bearer token</option>
          <option value="header">API key in a header</option>
          <option value="query">API key in a query parameter</option>
        </select>
      </label>
      <Show when={props.value.auth === "header"}>
        <label>
          Header name
          <input
            value={props.value.header}
            onInput={(e) => field("header", e.currentTarget.value)}
          />
        </label>
        <label>
          Prefix, if required
          <input
            value={props.value.prefix}
            onInput={(e) => field("prefix", e.currentTarget.value)}
          />
        </label>
      </Show>
      <Show when={props.value.auth === "query"}>
        <label>
          Parameter name
          <input
            value={props.value.query}
            onInput={(e) => field("query", e.currentTarget.value)}
          />
        </label>
      </Show>
    </>
  );
}
export function AddConnection(props: { preset: string }) {
  const m = useMonitor();
  const preset = m.view()!.presets[props.preset];
  const fields = owner.setupFields(m.view()!, props.preset);
  const [name, setName] = createSignal(
    props.preset === "custom_api" ? "" : props.preset,
  );
  const [values, setValues] = createStore<Record<string, string>>(
    Object.fromEntries(
      fields.map((f) => [f.key, owner.fieldText(f, f.default)]),
    ),
  );
  const [tokens, setTokens] = createStore<Record<string, boolean>>({});
  const signIns = () => fields.filter((f) => f.oauth && !tokens[f.key]);
  const [sharing, setSharing] = createSignal(answers(preset?.defaults));
  const [api, setApi] = createSignal(owner.apiSettings(m.view()!)),
    [token, setToken] = createSignal("");
  const names = () =>
    Object.keys(m.view()!.config.identities ?? {}).filter(
      (name) => !owner.isDevice(name),
    );
  const [agent, setAgent] = createSignal(
      names().length === 1 ? names()[0] : "",
    ),
    [level, setLevel] = createSignal<owner.Level>("ask");
  const add = async (signInKey?: string) => {
    try {
      const account = name().trim();
      const changes =
        props.preset === "custom_api"
          ? owner.edits.addCustomApi(m.view()!, {
              name: account,
              api: api(),
              token: token(),
              agent: agent(),
              level: level(),
              answers: sharing(),
            })
          : owner.edits.addAccount(m.view()!, props.preset, {
              name: account,
              answers: sharing(),
              values: Object.fromEntries(
                fields.map((f) => [f.key, owner.readField(f, values[f.key])]),
              ),
              oauth: fields
                .filter((f) => f.oauth && !tokens[f.key])
                .map((f) => f.key),
            });
      if (!(await m.edit(changes, href("account", account)))) return;
      if (signInKey) {
        const field = owner
          .credentialFields(m.view()!, account)
          .find(
            (f) =>
              f.key === signInKey ||
              f.path.join("/") ===
                owner
                  .fieldPaths(fields.find((f) => f.key === signInKey)!)[0]
                  .join("/"),
          );
        if (field) await m.signIn(account, field);
      }
    } catch (cause) {
      m.report(cause);
    }
  };
  return (
    <Show when={preset} fallback={<Empty title="Preset not found" />}>
      <form
        class="connection-fields"
        onSubmit={(e) => {
          e.preventDefault();
          void add();
        }}
      >
        <label>
          Name
          <input
            required
            value={name()}
            onInput={(e) => setName(e.currentTarget.value)}
            autocomplete="off"
          />
        </label>
        <Show
          when={props.preset === "custom_api"}
          fallback={
            <For each={fields}>
              {(field) => {
                const id = createUniqueId();
                return (
                  <>
                    <div id={id} hidden={!!field.oauth && !tokens[field.key]}>
                      <Field
                        field={
                          field.oauth
                            ? {
                                ...field,
                                label: "Access token",
                                hint: "Paste your access token here",
                              }
                            : field
                        }
                        value={values[field.key]}
                        onInput={(value) => setValues(field.key, value)}
                      />
                      <Show when={field.secret}>
                        <p class="muted field-help">
                          Leave blank to configure later.
                        </p>
                      </Show>
                    </div>
                    <Show when={field.oauth}>
                      <button
                        type="button"
                        class="link"
                        aria-controls={id}
                        aria-expanded={!!tokens[field.key]}
                        onClick={() => {
                          setTokens(field.key, !tokens[field.key]);
                          if (tokens[field.key])
                            document
                              .getElementById(id)
                              ?.querySelector<
                                HTMLInputElement | HTMLTextAreaElement
                              >("input, textarea")
                              ?.focus();
                        }}
                      >
                        {tokens[field.key]
                          ? "Use sign-in instead"
                          : "Use an access token instead"}
                      </button>
                    </Show>
                  </>
                );
              }}
            </For>
          }
        >
          <ApiFields value={api()} onChange={setApi} />
          <Field
            field={{ key: "token", label: "API key or token", secret: true }}
            value={token()}
            onInput={setToken}
          />
          <p class="muted field-help">Leave blank to configure later.</p>
          <label>
            Identity
            <select
              value={agent()}
              onChange={(e) => setAgent(e.currentTarget.value)}
            >
              <option value="">Set up access later</option>
              <For each={names()}>{(name) => <option>{name}</option>}</For>
            </select>
          </label>
          <label>
            Access
            <select
              value={level()}
              onChange={(e) => setLevel(e.currentTarget.value as owner.Level)}
            >
              <option value="ask">Ask before each request</option>
              <option value="allow">Allow all API requests</option>
            </select>
          </label>
        </Show>
        <ResourceDisclosure
          class="connection-advanced"
          summary={
            <span class="connection-advanced-text">
              <span class="connection-advanced-heading">
                <strong class="connection-advanced-title">Advanced</strong>
                <span class="collection-chevron">
                  <Icon name="arrow" />
                </span>
              </span>
              <small>Data sharing</small>
            </span>
          }
        >
          {() => (
            <div class="connection-advanced-content">
              <fieldset class="data-permissions">
                <legend>Data sharing</legend>
                <DataPermissions value={sharing()} onChange={setSharing} />
              </fieldset>
            </div>
          )}
        </ResourceDisclosure>
        <div class="credential-actions">
          <button
            classList={{ primary: !signIns().length }}
            disabled={m.busy()}
          >
            {signIns().length ? "Add without signing in" : "Add connection"}
          </button>
          <For each={signIns()}>
            {(field) => (
              <button
                type="button"
                class="primary"
                disabled={m.busy()}
                onClick={() => void add(field.key)}
              >
                {owner.signInLabel(m.view()!, props.preset)}
              </button>
            )}
          </For>
        </div>
      </form>
    </Show>
  );
}
function ConnectionForm(props: { name: string }) {
  const m = useMonitor(),
    initial = m.view()!.config.accounts![props.name];
  let form!: HTMLFormElement;
  const fields = owner.plainFields(m.view()!, props.name);
  const [values, setValues] = createStore<Record<string, string>>(
    Object.fromEntries(fields.map((f) => [f.key, owner.fieldText(f, f.value)])),
  );
  const [drafts, setDrafts] = createStore<Record<string, string | undefined>>(
    {},
  );
  const credentials = createMemo(
    () =>
      new Map(
        owner
          .credentialFields(m.view()!, props.name)
          .map((field) => [field.key, field]),
      ),
  );
  const [api, setApi] = createSignal(owner.apiSettings(m.view()!, props.name));
  const save = async () => {
    if (!form.reportValidity()) return;
    const entered = { ...drafts };
    try {
      const changes = owner.edits.saveAccount(m.view()!, props.name, {
        api: initial.preset === "custom_api" ? api() : undefined,
        values: Object.fromEntries(
          fields.map((f) => [f.key, owner.readField(f, values[f.key])]),
        ),
        credentials: Object.fromEntries(
          [...credentials().values()].map((field) => [
            field.key,
            {
              mode: entered[field.key] ? "replace" : "keep",
              value: entered[field.key]
                ? owner.readField(field, entered[field.key]!)
                : undefined,
            },
          ]),
        ),
      });
      if (!changes.length || !(await m.edit(changes))) return;
      // A completed save must not clear a newer credential draft.
      for (const [key, text] of Object.entries(entered))
        if (drafts[key] === text) setDrafts(key, undefined);
    } catch (cause) {
      m.report(cause);
    }
  };
  return (
    <form
      ref={form}
      class="connection-fields"
      onSubmit={(event) => {
        event.preventDefault();
        void save();
      }}
      onFocusOut={(event) => {
        if (
          event.target instanceof HTMLInputElement ||
          event.target instanceof HTMLTextAreaElement ||
          event.target instanceof HTMLSelectElement
        )
          void save();
      }}
      onChange={(event) => {
        if (event.target instanceof HTMLSelectElement) void save();
      }}
    >
      <Show when={initial.preset === "custom_api"}>
        <ApiFields value={api()} onChange={setApi} />
      </Show>
      <For each={fields}>
        {(field) => (
          <Field
            field={field}
            value={values[field.key]}
            onInput={(value) => setValues(field.key, value)}
          />
        )}
      </For>
      <For each={[...credentials().keys()]}>
        {(key) => {
          const field = () => credentials().get(key)!;
          const collapsed = () =>
            drafts[key] === undefined &&
            (field().signIn || field().kind !== "unset");
          const status = () =>
            field().status + (field().account ? ` · ${field().account}` : "");
          const signIn = () => (
            <Show when={field().signIn}>
              <button
                type="button"
                disabled={m.busy()}
                onClick={() => void m.signIn(props.name, field())}
              >
                {owner.signInLabel(m.view()!, initial.preset)}
              </button>
            </Show>
          );
          return (
            <div class="credential">
              <Show
                when={!collapsed()}
                fallback={
                  <div class="setting-row">
                    <div>
                      <span>{field().label}</span>
                      <p>{status()}</p>
                    </div>
                    <div class="credential-actions">
                      {signIn()}
                      <button type="button" onClick={() => setDrafts(key, "")}>
                        {field().kind === "unset" ||
                        field().kind === "oauth-required"
                          ? "Enter credential"
                          : "Replace"}
                      </button>
                    </div>
                  </div>
                }
              >
                <Field
                  field={{
                    ...field(),
                    hint:
                      field().kind === "unset"
                        ? field().hint
                        : "Leave blank to keep the current credential",
                  }}
                  value={drafts[key] ?? ""}
                  onInput={(text) => setDrafts(key, text)}
                />
                <div class="credential-header">
                  <p class="muted field-help">{status()}</p>
                  <div class="credential-actions">{signIn()}</div>
                </div>
              </Show>
            </div>
          );
        }}
      </For>
      <Show
        when={
          !fields.length &&
          !credentials().size &&
          initial.preset !== "custom_api"
        }
      >
        <p class="muted">
          This connection does not require additional configuration.
        </p>
      </Show>
    </form>
  );
}

function Connection(props: { name: string; active: boolean }) {
  const m = useMonitor(),
    account = () => m.view()!.config.accounts?.[props.name];
  const actors = () =>
    Object.keys(m.view()!.config.identities ?? {}).filter(
      (name) => !owner.isDevice(name),
    );
  const [policy, setPolicy] = createSignal(
    m.view()!.config.policies?.[props.name] ?? "",
  );
  const setups = createMemo(() => {
    const groups = new Map<
      string,
      NonNullable<ReturnType<typeof owner.apiSetup>>[]
    >();
    for (const [key, kinds] of Object.entries(account()?.connections ?? {})) {
      const slots = Object.values(kinds)[0]?.slots;
      if (!Array.isArray(slots)) continue;
      for (let index = 0; index < slots.length; index++) {
        const setup = owner.apiSetup(m.view()!, props.name, key, index);
        if (!setup) continue;
        const id = JSON.stringify([setup.connection, setup.credential]);
        const group = groups.get(id);
        if (group) group.push(setup);
        else groups.set(id, [setup]);
      }
    }
    return [...groups.values()];
  });
  const codex = () => owner.codexSetup(m.view()!, props.name);
  const tinfoil = createMemo(() => owner.tinfoilSetup(m.view()!, props.name));
  return (
    <div class="connection-detail">
      <Show when={account()} fallback={<Empty title="Connection not found" />}>
        <For
          each={owner
            .reviews(m.view()!, props.name)
            .filter(
              (review) =>
                review.error || review.blocked || review.state === "connecting",
            )}
        >
          {(review) => (
            <section>
              <h2>{review.name}</h2>
              <p role={review.error ? "alert" : undefined}>
                {review.error
                  ? `Can't connect: ${review.error}`
                  : review.state === "connecting"
                    ? "Connecting…"
                    : `${owner.presetOf(m.view()!, props.name).title} changed its tools: ${review.added} new, ${review.changed} changed, ${review.removed} removed.`}
              </p>
              <Show when={review.blocked}>
                <details>
                  <summary>{review.blocked} tools await review</summary>
                  <pre>{review.changes.join("\n\n")}</pre>
                </details>
                <button
                  disabled={m.busy()}
                  onClick={() =>
                    void m.edit(
                      owner.edits.approveTools(
                        m.view()!,
                        props.name,
                        review.key,
                      ),
                    )
                  }
                >
                  Approve tools
                </button>
              </Show>
            </section>
          )}
        </For>
        <Show when={account()!.preset === "tcp"}>
          <section class="connection-explainer">
            <p class="muted">
              The catch-all. Anything an identity tries to reach that isn't
              one of your other connections lands here.
            </p>
          </section>
        </Show>
        <Show when={account()!.preset !== "tcp"}>
          <section class="connection-explainer">
            <h3>Using this connection</h3>
            <p class="muted">
              What to paste into a tool on the identity's side. The real
              credential never leaves the Monitor.
            </p>

              <ConnectionForm name={props.name} />
              <Show when={tinfoil().length}>
                <div class="agent-setup-body">
                  <For each={tinfoil()}>
                    {(setup) => (
                      <div class="agent-setup-item">
                        <h4>
                          {setup.mcp ? "Web search (MCP)" : "Inference API"}
                        </h4>
                        <div class="secret-input">
                          <input
                            class="mono"
                            aria-label={
                              setup.mcp
                                ? "Web-search MCP URL"
                                : "Tinfoil API base URL"
                            }
                            readonly
                            value={setup.url}
                            onClick={(e) => e.currentTarget.select()}
                          />
                          <Copy
                            text={setup.url}
                            label={`Copy ${setup.connection} URL`}
                          />
                        </div>
                      </div>
                    )}
                  </For>
                </div>
              </Show>
          </section>
        </Show>
        <ResourceDisclosure
          class="connection-advanced"
          summary={
            <>
              <span class="connection-advanced-text">
                <span class="connection-advanced-heading">
                  <strong class="connection-advanced-title">
                    Identity access
                  </strong>
                  <span class="count">
                    {
                      owner
                        .accountUsers(m.view()!, props.name)
                        .filter(({ name }) => !owner.isDevice(name)).length
                    }
                  </span>
                  <span class="collection-chevron">
                    <Icon name="arrow" />
                  </span>
                </span>
                <small>Who can use this connection</small>
              </span>
            </>
          }
        >
          {() => (
            <div class="connection-advanced-content">
              <For each={actors()} fallback={<a href="#pair">Add an identity</a>}>
                {(name) => (
                  <AgentConnectionAccess
                    name={name}
                    account={props.name}
                    title={name}
                  />
                )}
              </For>
            </div>
          )}
        </ResourceDisclosure>
        <Show when={owner.liveConnection(m.view()!, props.name)}>
          {(connection) => (
            <Suspense fallback={<p role="status">Loading browser…</p>}>
              <Browser name={connection()} active={props.active} />
            </Suspense>
          )}
        </Show>
              <Show when={setups().length}>
                <div class="agent-setup-body">
                  <For each={setups()}>
                    {(group) => {
                      const setup = group[0];
                      let input!: HTMLInputElement;
                      const id = createUniqueId();
                      return (
                        <div class="agent-setup-item">
                          <Show when={setups().length > 1}>
                            <h3>
                              {setup.connection} · {setup.credential}
                            </h3>
                          </Show>
                          <label for={id}>Identity placeholder</label>
                          <div class="secret-input">
                            <input
                              ref={input}
                              id={id}
                              class="mono"
                              readonly
                              value={setup.placeholder}
                              onClick={(e) => e.currentTarget.select()}
                            />
                            <Copy
                              text={setup.placeholder}
                              label={`Copy placeholder for ${setup.connection} ${setup.credential}`}
                              target={() => input}
                            />
                          </div>
                          <details class="agent-setup-usage">
                            <summary>Where this placeholder is used</summary>
                            <Show when={group.length > 1}>
                              <p>
                                The same placeholder works in each of these
                                formats. Use the format your tool expects.
                              </p>
                            </Show>
                            <For each={group}>
                              {(use) => (
                                <dl class="agent-setup-details">
                                  <dt>Address</dt>
                                  <dd>
                                    <code>{use.address}</code>
                                  </dd>
                                  <dt>
                                    {use.header
                                      ? "Header"
                                      : use.query
                                        ? "Query parameter"
                                        : "Authentication"}
                                  </dt>
                                  <dd>
                                    <code>
                                      {use.header
                                        ? `${use.header}: ${use.value}`
                                        : use.query
                                          ? `${use.query}=${use.value}`
                                          : use.placement}
                                    </code>
                                  </dd>
                                </dl>
                              )}
                            </For>
                          </details>
                        </div>
                      );
                    }}
                  </For>
                </div>
              </Show>
              <Show when={codex()}>
                {(text) => {
                  let code!: HTMLPreElement;
                  return (
                    <ResourceDisclosure
                      class="connection-disclosure"
                      summary={
                        <>
                          <span class="collection-chevron">
                            <Icon name="arrow" />
                          </span>
                          <span>Codex setup</span>
                        </>
                      }
                    >
                      {() => (
                        <div class="agent-setup-body">
                          <p>
                            Save this in <code>~/.codex/config.toml</code>, then
                            run Codex in your Monitor-connected sandbox or with{" "}
                            <code>monitor run -- codex</code>. Choose a model
                            available to your ChatGPT account. Grant your identity
                            access to this connection and review pending
                            requests in Activity.
                          </p>
                          <pre ref={code}>{text()}</pre>
                          <Copy text={text()} target={() => code} />
                          <p>
                            <a
                              href="https://chatgpt.com/#settings/Usage"
                              target="_blank"
                              rel="noopener noreferrer"
                            >
                              Manage ChatGPT usage
                            </a>
                          </p>
                        </div>
                      )}
                    </ResourceDisclosure>
                  );
                }}
              </Show>
        <ResourceDisclosure
          class="connection-advanced"
          summary={
            <span class="connection-advanced-text">
              <span class="connection-advanced-heading">
                <strong class="connection-advanced-title">Advanced</strong>
                <span class="collection-chevron">
                  <Icon name="arrow" />
                </span>
              </span>
              <small>Sharing, effects, and policy</small>
            </span>
          }
        >
          {() => (
            <div class="connection-advanced-content">
              <section>
                <h3>Data sharing</h3>
                <DataPermissions
                  value={answers(account())}
                  onChange={(value) => {
                    const changes = owner
                      .sourceChanges({ accounts: { [props.name]: value } })
                      .filter(
                        (change) =>
                          account()?.[
                            change.path[2] as keyof owner.AccountAnswers
                          ] !== change.value,
                      );
                    if (changes.length) void m.edit(changes);
                  }}
                />
              </section>
              <section>
                <h3>Effects</h3>
                <Effects scope={{ account: props.name }} />
              </section>
              <section>
                <h3>Custom policy</h3>
                <form
                  class="connection-fields"
                  onSubmit={(e) => {
                    e.preventDefault();
                    void m.edit(
                      owner.edits.setAccountPolicy(props.name, policy()),
                    );
                  }}
                >
                  <textarea
                    aria-label="Custom policy"
                    rows={6}
                    placeholder={`package sentinel

deny contains "reason shown in Activity" if {
  "pay" in input.facts.operation.effects
}`}
                    value={policy()}
                    onInput={(e) => setPolicy(e.currentTarget.value)}
                  />
                  <p class="muted field-help">
                    Define <code>deny</code> to block requests or{" "}
                    <code>approvals</code> to require review, in package{" "}
                    <code>sentinel</code>.
                  </p>
                  <button disabled={m.busy()}>Save policy</button>
                </form>
              </section>
            </div>
          )}
        </ResourceDisclosure>
        <section>
          <div class="connection-footer">
            <a class="button" href={href("preset", account()!.preset)}>
              Edit connection preset
            </a>
            <button
              class="danger"
              disabled={m.busy()}
              onClick={async () => {
                if (
                  confirm(`Remove connection ${props.name}?`) &&
                  (await m.edit(
                    owner.edits.removeAccount(m.view()!, props.name),
                  ))
                )
                  location.hash = "#accounts";
              }}
            >
              Remove connection
            </button>
          </div>
        </section>
      </Show>
    </div>
  );
}

function ConnectionActions(props: { nodes: owner.ActionNode[] }) {
  const nodes = createMemo(
    () => new Map(props.nodes.map((node) => [node.key, node])),
  );
  return (
    <For
      each={[...nodes().keys()]}
      fallback={
        <p class="muted">This preset doesn't define any actions yet.</p>
      }
    >
      {(key) => {
        const node = () => nodes().get(key)!;
        const row = () => (
          <>
            <span class="capability-name">
              {node().title}{" "}
              <Show when={node().total}>
                <small class="count">{node().total}</small>
              </Show>
            </span>
            <Show when={!node().children.length}>
              <span class="effects" aria-label="Effects">
                <For
                  each={node().effects}
                  fallback={<span class="muted">No effects</span>}
                >
                  {(effect) => (
                    <span class={`badge effect-${effect}`}>
                      {effect.charAt(0).toUpperCase() + effect.slice(1)}
                    </span>
                  )}
                </For>
              </span>
            </Show>
          </>
        );
        return (
          <Show
            when={node().children.length}
            fallback={<div class="capability">{row()}</div>}
          >
            <LazyDetails
              class="action-group"
              summaryClass="capability"
              summary={row()}
            >
              {() => (
                <div class="action-children">
                  <ConnectionActions nodes={node().children} />
                </div>
              )}
            </LazyDetails>
          </Show>
        );
      }}
    </For>
  );
}
