import {
  For,
  Index,
  Show,
  createMemo,
  createSignal,
  createUniqueId,
} from "solid-js";
import { createStore } from "solid-js/store";
import * as owner from "./owner.js";
import {
  ConnectorIcon,
  Copy,
  Empty,
  DisclosureHeading,
  SectionHeading,
  Field,
  Icon,
  ResourceDisclosure,
  Search,
  createDialogMotion,
  href,
} from "./components";
import { useMonitor } from "./monitor";
import { AgentConnectionAccess } from "./Agents";


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

export function Connections(props: { catalog?: boolean; expanded?: string }) {
  return (
    <>
      <nav class="page-tabs" aria-label="Connection views">
        <a
          href="#connections"
          aria-current={!props.catalog ? "page" : undefined}
        >
          Mine
        </a>
        <a
          href="#connections/catalog"
          aria-current={props.catalog ? "page" : undefined}
        >
          Catalog
        </a>
      </nav>
      <Show
        when={props.catalog}
        fallback={<MyConnections expanded={props.expanded} />}
      >
        <Catalog />
      </Show>
    </>
  );
}
function MyConnections(props: { expanded?: string }) {
  const m = useMonitor(),
    // Mine and Catalog share one search: switching tabs keeps the term.
    [query, setQuery] = m.search("connections");
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
  // The search also peeks into the catalog, so typing a service you do not
  // have yet points at the Catalog tab instead of a dead end. Best matches
  // first (title starts with the query), top three only; adding happens on
  // the Catalog tab, which opens with the same search.
  const CATALOG_MATCH_LIMIT = 3;
  const catalogMatches = createMemo(() => {
    const search = query().trim().toLowerCase();
    if (!search) return { shown: [], total: 0 };
    const all = owner
      .catalog(m.view()!)
      .flatMap((group) =>
        group.presets.map((p) => ({ ...p, groupTitle: group.title })),
      )
      .filter((p) =>
        `${p.name} ${p.title} ${p.groupTitle}`.toLowerCase().includes(search),
      );
    const rank = (p: (typeof all)[number]) =>
      p.title.toLowerCase().startsWith(search)
        ? 0
        : p.title.toLowerCase().includes(search)
          ? 1
          : 2;
    all.sort((a, b) => rank(a) - rank(b) || a.title.localeCompare(b.title));
    return { shown: all.slice(0, CATALOG_MATCH_LIMIT), total: all.length };
  });
  return (
    <>
      <div id="toolbar">
        <Search
          label="Search connections and services"
          autofocus
          value={query()}
          onInput={setQuery}
        />
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
              title={query() ? "None match" : "No connections yet"}
              action={
                <Show when={!query()}>
                  <a class="button primary" href="#connections/catalog">
                    <Icon name="plus" />
                    Add connection
                  </a>
                </Show>
              }
            >
              <Show when={!query()}>
                Add a connection to give your sandboxes access to a service.
              </Show>
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
                      {name}
                    </strong>
                    <span class="collection-description">
                      {owner.presetOf(m.view()!, name).title}
                    </span>
                    <span class="resource-meta">
                      <Show when={status().state}>
                        <span
                          class={`badge${status().state === "connecting" ? "" : ` status-${status().state === "error" ? "denied" : "pending"}`}`}
                        >
                          {status().blocked
                            ? `${status().blocked} tools await review`
                            : status().state === "error"
                              ? "Connection error"
                              : "Connecting…"}
                        </span>
                      </Show>
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
      <Show when={catalogMatches().shown.length}>
        <div class="resource-list collection-list catalog-peek">
          <div class="resource-heading">
            <a href="#connections/catalog">
              From the catalog{" "}
              <span class="count">{catalogMatches().total}</span>
              <Icon name="arrow" />
            </a>
          </div>
          <For each={catalogMatches().shown}>
            {(p) => (
              <div class="catalog-peek-row">
                <ConnectorIcon preset={p.name} />
                <span class="collection-name">{p.title}</span>
                <Show when={p.accounts}>
                  {(count) => <span class="muted">added ({count()})</span>}
                </Show>
              </div>
            )}
          </For>
        </div>
      </Show>
    </>
  );
}
// One catalog service: expands in place to its add form.
function CatalogRow(props: { name: string; added?: number }) {
  const m = useMonitor();
  return (
    <ResourceDisclosure
      class="catalog-item"
      summaryClass="resource-row collection-row catalog-row"
      summary={
        <>
          <ConnectorIcon preset={props.name} />
          <strong
            class="collection-name"
            title={m.view()!.presets[props.name].title}
          >
            {m.view()!.presets[props.name].title}
          </strong>
          <span class="resource-meta">
            <Show when={props.added}>
              {(count) => <span class="muted">added ({count()})</span>}
            </Show>
          </span>
          <span class="collection-chevron">
            <Icon name="arrow" />
          </span>
        </>
      }
    >
      {(active) => (
        <Show when={active()}>
          <div class="catalog-entry">
            <h3 class="catalog-add-title">
              New {m.view()!.presets[props.name].title} connection
            </h3>
            <AddConnection preset={props.name} />
          </div>
        </Show>
      )}
    </ResourceDisclosure>
  );
}
function Catalog() {
  let catalog!: HTMLDivElement;
  const m = useMonitor(),
    [query, setQuery] = m.search("connections");
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
          label="Search services"
          autofocus
          value={query()}
          onInput={setQuery}
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
              <details
                open={id === "common" || !!query()}
                class="resource-list collection-list"
              >
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
                      <CatalogRow
                        name={name}
                        added={presets().get(name)?.accounts}
                      />
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
  const urlId = createUniqueId();
  const field = (key: keyof owner.ApiSettings, value: string) =>
    props.onChange({ ...props.value, [key]: value });
  return (
    <>
      <div class="field">
        <label for={urlId}>API URL</label>
        <input
          id={urlId}
          type="url"
          required
          placeholder="https://api.example.com"
          value={props.value.url}
          onInput={(e) => field("url", e.currentTarget.value)}
        />
        <p class="muted field-help">
          The credential is used only at this address and its paths.
        </p>
      </div>
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
  // Keep the preset's data-flow defaults even though this editor is hidden.
  const sharing = () => answers(preset?.defaults);
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
      if (!(await m.edit(changes, href("connection", account)))) return;
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
        class="form-fields"
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
                        help={
                          field.secret
                            ? "Leave blank to configure later."
                            : undefined
                        }
                      />
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
            help="Leave blank to configure later."
          />
          <label>
            Sandbox
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
        <div class="form-actions">
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
    <Show
      when={
        fields.length || credentials().size || initial.preset === "custom_api"
      }
    >
      <section class="connection-section connection-config">
        <SectionHeading title="Configuration" />
        <form
          ref={form}
          class="form-fields"
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
                field().status +
                (field().account ? ` · ${field().account}` : "");
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
                        <div class="form-actions">
                          {signIn()}
                          <button
                            type="button"
                            onClick={() => setDrafts(key, "")}
                          >
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
                      <div class="form-actions">{signIn()}</div>
                    </div>
                  </Show>
                </div>
              );
            }}
          </For>
        </form>
      </section>
    </Show>
  );
}

const TOOL_CHANGES: Record<string, string> = {
  "+": "New",
  "~": "Changed",
  "-": "Removed",
};
function ToolChange(props: { change: ReturnType<typeof owner.toolChange> }) {
  return (
    <li class="tool-change">
      <header>
        <span class="badge">{TOOL_CHANGES[props.change.sign]}</span>
        <code>{props.change.name}</code>
        <Show when={props.change.tool}>
          <span class="muted">{props.change.parameters.length} parameters</span>
        </Show>
        <Show when={props.change.tool?.annotations?.readOnlyHint}>
          <span class="badge effect-read">Treated as read-only</span>
        </Show>
        <Show when={props.change.tool?.annotations?.destructiveHint}>
          <span class="badge effect-delete">Marked destructive</span>
        </Show>
      </header>
      <Show
        when={props.change.tool}
        fallback={
          <Show when={props.change.text}>
            <details>
              <summary>View details</summary>
              <pre>{props.change.text}</pre>
            </details>
          </Show>
        }
      >
        {(tool) => (
          <>
            <Show when={props.change.changedFields.length}>
              <ul class="tool-field-changes">
                <For each={props.change.changedFields}>
                  {(field) => <li>{field.kind}: <code>{field.name}</code></li>}
                </For>
              </ul>
            </Show>
            <Show when={props.change.parameters.length}>
              <dl>
                <For each={props.change.parameters}>
                  {(parameter) => (
                    <div>
                      <dt>
                        <code>{parameter.name}</code>
                        <span class="muted">
                          {[parameter.type, parameter.required ? "required" : "optional"]
                            .filter(Boolean)
                            .join(" · ")}
                        </span>
                      </dt>
                    </div>
                  )}
                </For>
              </dl>
            </Show>
            <Show when={tool().description || props.change.parameters.some((p) => p.description)}>
              <details>
                <summary>Descriptions</summary>
                <Show when={tool().description}>
                  <p class="tool-description">{tool().description}</p>
                </Show>
                <dl>
                  <For each={props.change.parameters.filter((p) => p.description)}>
                    {(parameter) => (
                      <div>
                        <dt><code>{parameter.name}</code></dt>
                        <dd>{parameter.description}</dd>
                      </div>
                    )}
                  </For>
                </dl>
              </details>
            </Show>
            <details>
              <summary>Full definition</summary>
              <pre>{props.change.text || JSON.stringify(tool(), null, 2)}</pre>
            </details>
          </>
        )}
      </Show>
    </li>
  );
}

function Connection(props: { name: string; active: boolean }) {
  const m = useMonitor(),
    account = () => m.view()!.config.accounts?.[props.name];
  const agents = () =>
    Object.keys(m.view()!.config.identities ?? {}).filter(
      (name) => !owner.isDevice(name),
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
  const reviews = createMemo(() =>
    owner
      .reviews(m.view()!, props.name)
      .filter(
        (review) =>
          review.error || review.blocked || review.state === "connecting",
      ),
  );
  return (
    <div class="connection-detail">
      <Show when={account()} fallback={<Empty title="Connection not found" />}>
        <Show when={owner.isRawNetwork(m.view()!, props.name)}>
          <section class="connection-section">
            <p class="raw-network-note">
              General network access is a raw connection. The Monitor can see
              where a sandbox connects (host and port) but not what it sends.
              Prefer a named connection when one exists.
            </p>
          </section>
        </Show>
        <Show when={reviews().length}>
          <section class="connection-section" aria-label="Connection status">
            <Index each={reviews()}>
              {(review) => (
                <div class="settings-group">
                  <Show
                    when={review().blocked}
                    fallback={
                      <div class="setting-row" role="status">
                        <span>{review().name}</span>
                        <span
                          class="badge"
                          classList={{ "status-denied": !!review().error }}
                        >
                          {review().error ? "Connection error" : "Connecting…"}
                        </span>
                      </div>
                    }
                  >
                    <SectionHeading
                      title="Review tool changes"
                      description={`${review().blocked} ${review().blocked === 1 ? "tool on" : "tools on"} ${review().name} ${review().blocked === 1 ? "is" : "are"} blocked until you approve these changes.`}
                    />
                  </Show>
                  <Show when={review().error}>
                    <p class="muted" role="alert">
                      Can't connect: {review().error}
                    </p>
                  </Show>
                  <Show when={review().blocked}>
                    <ResourceDisclosure
                      class="section-disclosure"
                      summary={
                        <DisclosureHeading
                          title="View changes"
                          description={[
                            review().added && `${review().added} new`,
                            review().changed && `${review().changed} changed`,
                            review().removed && `${review().removed} removed`,
                          ]
                            .filter(Boolean)
                            .join(", ")}
                          small
                        />
                      }
                    >
                      {() => (
                        <ul class="section-content tool-changes">
                          <For each={review().changes}>
                            {(change) => (
                              <ToolChange
                                change={owner.toolChange(
                                  change,
                                  review().tools,
                                  review().previousTools,
                                )}
                              />
                            )}
                          </For>
                        </ul>
                      )}
                    </ResourceDisclosure>
                    <div class="form-actions">
                      <button
                        class="primary"
                        disabled={m.busy()}
                        onClick={() =>
                          void m.edit(
                            owner.edits.approveTools(
                              m.view()!,
                              props.name,
                              review().key,
                            ),
                          )
                        }
                      >
                        Approve changes
                      </button>
                    </div>
                  </Show>
                </div>
              )}
            </Index>
          </section>
        </Show>
        <section class="connection-section">
          <SectionHeading
            title="Sandbox access"
            description="Who can use this connection"
          />
          <div class="connection-access">
            <For
              each={agents()}
              fallback={
                <p class="muted">Enrol a sandbox to use this connection.</p>
              }
            >
              {(name) => (
                <AgentConnectionAccess
                  name={name}
                  account={props.name}
                  title={name}
                />
              )}
            </For>
          </div>
        </section>
        <Show when={tinfoil().length || setups().length || codex()}>
          <section class="connection-section connection-setup">
            <SectionHeading
              title="Details"
              description="URLs, sandbox placeholders, and setup instructions"
            />
            <Show when={tinfoil().length}>
              <div class="settings-group">
                <For each={tinfoil()}>
                  {(setup) => (
                    <div class="setting-row">
                      <div>
                        <span>
                          {setup.mcp ? "Web search (MCP)" : "Inference API"}
                        </span>
                        <p class="mono">{setup.url}</p>
                      </div>
                      <Copy
                        text={setup.url}
                        label={`Copy ${setup.connection} URL`}
                      />
                    </div>
                  )}
                </For>
              </div>
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
                        <label for={id}>Sandbox placeholder</label>
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
                    class="section-disclosure setup-disclosure"
                    summary={<DisclosureHeading title="Codex setup" small />}
                  >
                    {() => (
                      <div class="agent-setup-body">
                        <p>
                          Save this in <code>~/.codex/config.toml</code>, then
                          run Codex in your Monitor-connected sandbox or with{" "}
                          <code>monitor run -- codex</code>. Choose a model
                          available to your ChatGPT account. Grant your sandbox
                          access to this connection and review pending requests
                          in Activity.
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
          </section>
        </Show>
        <ConnectionForm name={props.name} />
        <div class="connection-footer">
          <button
            class="danger"
            disabled={m.busy()}
            onClick={async () => {
              if (
                confirm(`Remove connection ${props.name}?`) &&
                (await m.edit(owner.edits.removeAccount(m.view()!, props.name)))
              )
                location.hash = "#connections";
            }}
          >
            Remove connection
          </button>
        </div>
      </Show>
    </div>
  );
}
