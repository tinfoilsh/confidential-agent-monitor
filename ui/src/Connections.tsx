import { For, Show, createMemo, createSignal, createUniqueId } from "solid-js";
import { createStore } from "solid-js/store";
import * as owner from "./owner.js";
import {
  askConfirm,
  ConnectorIcon,
  Copy,
  Empty,
  DisclosureHeading,
  SectionHeading,
  Field,
  Icon,
  Modal,
  ResourceDisclosure,
  Search,
  createDialogMotion,
  href,
  TabBar,
} from "./components";
import { useMonitor } from "./monitor";
import { AgentConnectionAccess } from "./Agents";
import { NeedsApproval, SavedRules, ToolReview } from "./Approvals";

const inCatalog =
  (search: string, group: { title: string }) =>
  (p: { name: string; title: string }) =>
    `${p.name} ${p.title} ${group.title}`.toLowerCase().includes(search);

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
      class="dialog-panel"
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

export function Connections(props: {
  view?: "catalog" | "rules";
  expanded?: string;
  proposal?: string;
}) {
  return (
    <>
      <TabBar
        class="page-tabs"
        label="Permission views"
        value={props.view ?? "mine"}
        options={[
          { value: "mine", label: "Mine", href: "#connections" },
          { value: "catalog", label: "Catalog", href: "#connections/catalog" },
          { value: "rules", label: "Saved rules", href: "#connections/rules" },
        ]}
      />
      <Show
        when={props.view}
        fallback={
          <MyConnections expanded={props.expanded} proposal={props.proposal} />
        }
      >
        <Show when={props.view === "catalog"} fallback={<SavedRules />}>
          <Catalog />
        </Show>
      </Show>
    </>
  );
}
function MyConnections(props: { expanded?: string; proposal?: string }) {
  const m = useMonitor(),
    [query, setQuery] = m.search("connections");
  if (props.expanded) setQuery("");
  const searchable = createMemo(() =>
    Object.keys(m.view()!.config.connections ?? {})
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
  const CATALOG_MATCH_LIMIT = 3;
  const catalogMatches = createMemo(() => {
    const search = query().trim().toLowerCase();
    if (!search) return { shown: [], total: 0 };
    const all = owner
      .catalog(m.view()!)
      .flatMap((group) => group.presets.filter(inCatalog(search, group)));
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
      <NeedsApproval proposal={props.proposal} />
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
            Services <span class="count">{names().length}</span>
          </h2>
        </div>
        <For
          each={names()}
          fallback={
            <Empty
              title={query() ? "None match" : "No services yet"}
              action={
                <Show when={!query()}>
                  <a class="button primary" href="#connections/catalog">
                    <Icon name="plus" />
                    Add a service
                  </a>
                </Show>
              }
            >
              <Show when={!query()}>
                Add a service from the catalog to let your bunkers use it.
              </Show>
            </Empty>
          }
        >
          {(name) => {
            const status = createMemo(() =>
              owner.connectionStatus(owner.review(m.view()!, name)),
            );
            return (
              <ResourceDisclosure
                class="connection-item"
                open={props.expanded === name}
                summary={
                  <>
                    <ConnectorIcon connection={name} />
                    <strong class="collection-name" title={name}>
                      {name}
                    </strong>
                    <span class="collection-description">
                      {owner.presetOf(m.view()!, name).title}
                    </span>
                    <span class="resource-meta">
                      <Show when={status()}>
                        {(status) => (
                          <span
                            class={`badge${status().state === "connecting" ? "" : ` status-${status().state === "error" ? "denied" : "pending"}`}`}
                          >
                            {status().text}
                          </span>
                        )}
                      </Show>
                    </span>
                    <span class="collection-chevron">
                      <Icon name="arrow" />
                    </span>
                  </>
                }
              >
                {() => (
                  <div class="connection-inline">
                    <Connection name={name} />
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
                <Show when={p.connections}>
                  {(count) => <span class="muted">added ({count()})</span>}
                </Show>
              </div>
            )}
          </For>
        </div>
      </Show>
      <Show when={!query()}>
        <GlobalPermissions />
      </Show>
    </>
  );
}
// Account-wide rules that apply to every bunker and service.
function GlobalPermissions() {
  const m = useMonitor();
  return (
    <div class="settings">
      <section class="settings-section">
        <h2>Payments</h2>
        <label class="settings-card setting-toggle">
          <span>
            <span class="setting-title">Ask before any payment</span>
            <small>
              A bunker must get your approval for anything that spends money.
            </small>
          </span>
          <input
            type="checkbox"
            role="switch"
            checked={owner.effectMode(m.view()!, "pay") !== "allow"}
            onChange={(e) =>
              void m.edit(
                owner.edits.setEffect(
                  "pay",
                  e.currentTarget.checked ? undefined : "allow",
                ),
              )
            }
          />
        </label>
        <label class="settings-card setting-toggle">
          <span>
            <span class="setting-title">Allow AI inference without asking</span>
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
        <label class="settings-card setting-toggle">
          <span>
            <span class="setting-title">Allow everything</span>
            <small>
              Ignore these permissions. Every bunker can reach any host on any
              port, and nothing asks.
            </small>
          </span>
          <input
            type="checkbox"
            role="switch"
            checked={owner.networkingOpen(m.view()!)}
            onChange={async (e) => {
              const toggle = e.currentTarget,
                open = toggle.checked;
              if (
                open &&
                !(await askConfirm({
                  title: "Allow everything?",
                  description:
                    "Bunkers will be able to reach any host without asking.",
                  confirmLabel: "Allow everything",
                  destructive: true,
                }))
              ) {
                toggle.checked = false;
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
function CatalogRow(props: {
  name: string;
  added?: number;
  onOpen: () => void;
}) {
  const m = useMonitor();
  return (
    <button
      type="button"
      class="resource-row collection-row catalog-row"
      onClick={() => props.onOpen()}
    >
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
    </button>
  );
}
function CatalogDialog(props: { preset?: string; onClose: () => void }) {
  const m = useMonitor();
  // Keep the chosen service while the dialog fades out.
  const shown = createMemo<string | undefined>(
    (previous) => props.preset ?? previous,
  );
  return (
    <Modal
      id="catalog-dialog"
      class="dialog-panel"
      aria-labelledby="catalog-dialog-title"
      open={!!props.preset}
      onClose={props.onClose}
    >
      <Show when={shown()} keyed>
        {(preset) => (
          <>
            <header class="dialog-header">
              <div>
                <h1 id="catalog-dialog-title">
                  <ConnectorIcon preset={preset} />
                  Add {m.view()!.presets[preset].title}
                </h1>
              </div>
              <button
                class="dialog-close icon-button"
                aria-label="Close dialog"
                onClick={props.onClose}
              >
                <Icon name="close" />
              </button>
            </header>
            <div class="dialog-body">
              <AddConnection preset={preset} />
            </div>
            <Show when={m.message(location.hash)}>
              {(text) => (
                <p class="dialog-notice" role="status">
                  {text()}
                </p>
              )}
            </Show>
          </>
        )}
      </Show>
    </Modal>
  );
}
function Catalog() {
  let catalog!: HTMLDivElement;
  const m = useMonitor(),
    [query, setQuery] = m.search("connections");
  const [chosen, setChosen] = createSignal<string>();
  const groups = createMemo(() => owner.catalog(m.view()!));
  const filtered = createMemo(() => {
    const search = query().toLowerCase();
    return new Map(
      groups().map((group) => [
        group.group,
        {
          ...group,
          presets: group.presets.filter(inCatalog(search, group)),
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
              .querySelector<HTMLButtonElement>("details[open] .collection-row")
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
                        added={presets().get(name)?.connections}
                        onOpen={() => setChosen(name)}
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
      <CatalogDialog preset={chosen()} onClose={() => setChosen()} />
    </div>
  );
}
function ConnectionWarning(props: { warning?: string }) {
  return <Show when={props.warning}>
    {(warning) => <p class="connection-warning" role="note">{warning()}</p>}
  </Show>;
}

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
  const [api, setApi] = createSignal(owner.apiSettings(m.view()!)),
    [token, setToken] = createSignal("");
  const names = () => owner.sandboxNames(m.view()!);
  const [agent, setAgent] = createSignal(
      names().length === 1 ? names()[0] : "",
    ),
    [level, setLevel] = createSignal<owner.Level>("ask");
  const add = async (signInKey?: string) => {
    try {
      const connection = name().trim();
      const { changes, credentials } =
        props.preset === "custom_api"
          ? owner.edits.addCustomApi(m.view()!, {
              name: connection,
              api: api(),
              token: token(),
              agent: agent(),
              level: level(),
              answers: preset.defaults,
            })
          : owner.edits.addConnection(m.view()!, props.preset, {
              name: connection,
              answers: preset.defaults,
              values: Object.fromEntries(
                fields.map((f) => [f.key, owner.readField(f, values[f.key])]),
              ),
              oauth: fields
                .filter((f) => f.oauth && !tokens[f.key])
                .map((f) => f.key),
            });
      if (
        !(await m.edit(changes, href("connection", connection), {
          [connection]: credentials,
        }))
      )
        return;
      if (signInKey) {
        const field = owner
          .credentialFields(m.view()!, connection)
          .find((f) => f.key === signInKey);
        if (field) await m.signIn(connection, field);
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
        <ConnectionWarning warning={preset?.warning} />
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
            Bunker
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
            {signIns().length ? "Add without signing in" : "Add service"}
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
    initial = m.view()!.config.connections![props.name];
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
      const { changes, credentials: stored } = owner.edits.saveConnection(
        m.view()!,
        props.name,
        {
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
        },
      );
      if (
        (!changes.length && !Object.keys(stored).length) ||
        !(await m.edit(changes, undefined, { [props.name]: stored }))
      )
        return;
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
                drafts[key] === undefined && (field().signIn || field().stored);
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
                            {field().ready ? "Replace" : "Enter credential"}
                          </button>
                        </div>
                      </div>
                    }
                  >
                    <Field
                      field={{
                        ...field(),
                        hint: field().stored
                          ? "Leave blank to keep the current credential"
                          : field().hint,
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

function Connection(props: { name: string }) {
  const m = useMonitor(),
    connection = () => m.view()!.config.connections?.[props.name];
  const setups = createMemo(() => {
    const groups = new Map<
      string,
      NonNullable<ReturnType<typeof owner.apiSetup>>[]
    >();
    const slots = owner.setupOf(connection())?.slots;
    for (let index = 0; Array.isArray(slots) && index < slots.length; index++) {
      const setup = owner.apiSetup(m.view()!, props.name, index);
      if (!setup) continue;
      const group = groups.get(setup.credential);
      if (group) group.push(setup);
      else groups.set(setup.credential, [setup]);
    }
    return [...groups.values()];
  });
  const codex = () => owner.codexSetup(m.view()!, props.name);
  const tinfoil = createMemo(() => owner.tinfoilSetup(m.view()!, props.name));
  const review = createMemo(() => {
    const review = owner.review(m.view()!, props.name);
    return owner.connectionStatus(review) && review;
  });
  return (
    <div class="connection-detail">
      <Show
        when={connection()}
        fallback={<Empty title="Service not found" />}
      >
        <Show when={owner.presetOf(m.view()!, props.name).warning}>
          {(warning) => <section class="connection-section">
            <ConnectionWarning warning={warning()} />
          </section>}
        </Show>
        <Show when={review()}>
          {(review) => (
            <section class="connection-section" aria-label="Connection status">
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
                        {owner.connectionStatus(review())!.text}
                      </span>
                    </div>
                  }
                >
                  <SectionHeading
                    title="MCP tools to review"
                    description={owner.toolReviewDescription(review())}
                  />
                </Show>
                <Show when={review().error}>
                  <p class="muted" role="alert">
                    Can't connect: {review().error}
                  </p>
                </Show>
                <Show when={review().blocked}>
                  <ToolReview name={props.name} review={review()} />
                </Show>
              </div>
            </section>
          )}
        </Show>
        <section class="connection-section">
          <SectionHeading
            title="Bunker access"
            description="Who can use this service"
          />
          <div class="connection-access">
            <For
              each={owner.sandboxNames(m.view()!)}
              fallback={
                <p class="muted">Enrol a bunker to use this service.</p>
              }
            >
              {(name) => (
                <AgentConnectionAccess
                  name={name}
                  connection={props.name}
                  title={name}
                />
              )}
            </For>
          </div>
        </section>
        <Show when={tinfoil() || setups().length || codex()}>
          <section class="connection-section connection-setup">
            <SectionHeading
              title="Details"
              description="URLs, bunker placeholders, and setup instructions"
            />
            <Show when={tinfoil()}>
              {(setup) => (
                <div class="settings-group">
                  <div class="setting-row">
                    <div>
                      <span>
                        {setup().mcp ? "Web search (MCP)" : "Inference API"}
                      </span>
                      <p class="mono">{setup().url}</p>
                    </div>
                    <Copy text={setup().url} label={`Copy ${props.name} URL`} />
                  </div>
                </div>
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
                        <label for={id}>Bunker placeholder</label>
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
                          run Codex in your Perimeter-connected bunker or with{" "}
                          <code>monitor run -- codex</code>. Choose a model
                          available to your ChatGPT account. Grant your bunker
                          access to this service, then approve its requests when
                          asked.
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
                (await askConfirm({
                  title: `Remove ${props.name}?`,
                  description:
                    "Bunkers lose access to this service, and its saved credentials are deleted.",
                  confirmLabel: "Remove service",
                  destructive: true,
                })) &&
                (await m.edit(
                  owner.edits.removeConnection(m.view()!, props.name),
                ))
              )
                location.hash = "#connections";
            }}
          >
            Remove service
          </button>
        </div>
      </Show>
    </div>
  );
}
