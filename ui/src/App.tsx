import {
  ErrorBoundary,
  For,
  Match,
  Show,
  Switch,
  createEffect,
  createMemo,
  createSignal,
  lazy,
  onCleanup,
  onMount,
  untrack,
  type JSX,
} from "solid-js";
import * as owner from "./owner.js";
import { MonitorProvider, useMonitor, type MonitorOptions } from "./monitor";
import { Activity, RequestDetail } from "./Activity";
import { Agents, AddAgent } from "./Agents";
import { Connections, DeviceSignInDialog } from "./Connections";
import {
  AuthCard,
  AuthScreen,
  Empty,
  Icon,
  type IconName,
  Loading,
  Modal,
  href,
} from "./components";
import { THEME, applyTheme, savedTheme } from "./theme";

const Settings = lazy(() =>
  import("./Settings").then((m) => ({ default: m.Settings })),
);
const SandboxTerminal = lazy(() => import("./SandboxTerminal"));
const headings: Record<string, [title: string, description: string]> = {
  activity: ["Activity", "Review requests and manage saved approval rules."],
  agents: [
    "Sandboxes",
    "Your sandboxes and the devices that may reach them. The monitor can always be accessed by you.",
  ],
  connections: [
    "Connections",
    "Connect services and control how sandboxes use their data.",
  ],
  settings: ["Settings", "Manage policy and preferences."],
  request: ["Request", ""],
};
const SECTION_OF: Record<string, string> = {
  connection: "connections",
  request: "activity",
};
const parse = (path: string) => {
  try {
    return path.split("/").map(decodeURIComponent);
  } catch {
    return ["connections"];
  }
};

export default function App(props: MonitorOptions) {
  return (
    <ErrorBoundary
      fallback={(error) => (
        <div class="start-page">
          <AuthScreen id="gate" title="Could not show Monitor">
            <AuthCard icon={<Icon name="warning" />}>
              <p role="alert">{String(error)}</p>
              <button class="primary" onClick={() => location.reload()}>
                Reload
              </button>
            </AuthCard>
          </AuthScreen>
        </div>
      )}
    >
      <MonitorProvider {...props}>
        <Shell />
      </MonitorProvider>
    </ErrorBoundary>
  );
}
function Shell() {
  const m = useMonitor();
  const initial = location.hash.slice(1) || "agents";
  const [route, setRoute] = createSignal(initial),
    [page, setPage] = createSignal(initial === "pair" ? "agents" : initial);
  const [mobile, setMobile] = createSignal(false),
    [theme, setTheme] = createSignal(savedTheme());
  const media = matchMedia("(prefers-color-scheme: dark)"),
    [dark, setDark] = createSignal(media.matches);
  const pairing = () => route() === "pair";
  const kind = () => parse(page())[0];
  const section = () => SECTION_OF[kind()] ?? kind();
  const heading = () => headings[kind()] ?? headings[section()];
  const count = (section: string) =>
    section === "activity"
      ? m.pendingCount()
      : Object.keys(
          (section === "agents"
            ? m.view()?.config.identities
            : section === "connections"
              ? m.view()?.config.connections
              : {}) ?? {},
        ).length;
  // The open shell is a sidebar tab; other pages keep its session running.
  const shellShown = () => {
    const [kind, name, view] = parse(page());
    return kind === "agents" && view === "terminal" && name === m.shell();
  };
  const closeShell = () => {
    const shown = shellShown();
    m.setShell();
    if (shown) location.hash = "agents";
  };
  const NavItem = (props: { key: IconName }) => (
    <a
      class="nav-item"
      classList={{ on: section() === props.key && !shellShown() }}
      aria-current={
        section() === props.key && !shellShown() ? "page" : undefined
      }
      href={href(props.key)}
    >
      <Icon name={props.key} />
      <span>{headings[props.key][0]}</span>
      <Show when={count(props.key)}>
        <small class="nav-count">{count(props.key)}</small>
      </Show>
    </a>
  );
  const close = () => {
    location.hash = page();
  };
  onMount(() => {
    const hash = () => {
      // A restarted SSH tunnel can reuse this origin with a new owner session.
      if (new URLSearchParams(location.hash.slice(1)).has("session")) {
        location.reload();
        return;
      }
      const next = location.hash.slice(1) || "agents";
      setRoute(next);
      if (next !== "pair") setPage(next);
      setMobile(false);
    };
    const changed = (event: MediaQueryListEvent) => setDark(event.matches);
    window.addEventListener("hashchange", hash);
    media.addEventListener("change", changed);
    onCleanup(() => {
      window.removeEventListener("hashchange", hash);
      media.removeEventListener("change", changed);
    });
  });
  createEffect(() => {
    const [kind, name, view] = parse(page());
    if (kind === "agents" && view === "terminal") m.setShell(name);
  });
  const ready = () => m.view() && !m.locked() && owner.onboarded(m.view()!);
  createEffect(() => {
    applyTheme(theme(), dark());
    localStorage.setItem(THEME, theme());
  });
  return (
    <>
      <Show when={ready()} fallback={<Gate />}>
        <div class="app-frame">
          <div id="app" classList={{ "navigation-open": mobile() }}>
            <aside id="navigation" aria-label="Monitor navigation">
              <a class="brand" href="#activity">
                <img
                  src={import.meta.env.BASE_URL + "icons/tinfoil.svg"}
                  alt="Tinfoil"
                />
                <Show when={m.options.product}>
                  {(product) => (
                    <span class="brand-name">
                      {product().name}
                      <small>{product().tagline}</small>
                    </span>
                  )}
                </Show>
              </a>
              <button
                class="mobile-toggle"
                aria-label="Toggle navigation"
                aria-controls="tree"
                aria-expanded={mobile()}
                onClick={() => setMobile(!mobile())}
              >
                Menu
              </button>
              <nav id="tree" aria-label="Management">
                <For
                  each={
                    ["agents", "activity", "connections", "settings"] as const
                  }
                >
                  {(key) => <NavItem key={key} />}
                </For>
                <Show when={m.shell()}>
                  {(name) => (
                    <div
                      class="nav-item nav-shell"
                      classList={{ on: shellShown() }}
                    >
                      <a
                        href={href("agents", name(), "terminal")}
                        aria-current={shellShown() ? "page" : undefined}
                        title={name()}
                      >
                        <Icon name="terminal" />
                        <span>{name()}</span>
                      </a>
                      <button
                        type="button"
                        class="icon-button nav-shell-close"
                        aria-label={`Close shell in ${name()}`}
                        title="Close shell"
                        onClick={closeShell}
                      >
                        <Icon name="close" />
                      </button>
                    </div>
                  )}
                </Show>
              </nav>
              <MonitorFooter />
            </aside>
            <main
              id="workspace"
              tabIndex={-1}
              classList={{ "shell-shown": shellShown() }}
            >
              <Show when={!shellShown()}>
                <header id="page-header">
                  <div class="page-heading">
                    <div>
                      <h1>{heading()?.[0] ?? "Monitor"}</h1>
                      <p>{heading()?.[1]}</p>
                    </div>
                    <div class="header-actions">
                      <button
                        aria-label="Refresh monitor"
                        aria-busy={m.loading()}
                        onClick={() => void m.refresh()}
                      >
                        <Icon name="refresh" />
                        Refresh
                      </button>
                    </div>
                  </div>
                </header>
                <div id="page-content">
                  <Show when={page()} keyed>
                    {(path) => (
                      <Page
                        path={path}
                        theme={theme()}
                        onThemeChange={setTheme}
                      />
                    )}
                  </Show>
                  <div id="notices">
                    <ApprovalBar />
                    <Show when={m.message() && !pairing()}>
                      <div id="toast" role="status">
                        {m.message()}
                      </div>
                    </Show>
                  </div>
                </div>
              </Show>
              <Show when={m.shell()} keyed>
                {(name) => (
                  <section class="shell-view" hidden={!shellShown()}>
                    <Show
                      when={untrack(() => m.shellFor(name))}
                      fallback={
                        <Empty title="Shell unavailable">
                          This Monitor cannot open a shell in {name}.
                        </Empty>
                      }
                    >
                      {(open) => (
                        <SandboxTerminal
                          open={open()}
                          name={name}
                          active={shellShown()}
                        />
                      )}
                    </Show>
                  </section>
                )}
              </Show>
              <Show when={m.shell()} keyed>
                {(name) => {
                  const [dismissed, setDismissed] = createSignal(false);
                  return (
                    <Show
                      when={shellShown() && m.pendingCount() && !dismissed()}
                    >
                      <div class="shell-notices">
                        <ApprovalBar />
                        <button
                          type="button"
                          class="icon-button dialog-close"
                          aria-label={`Dismiss approvals in ${name}`}
                          title="Dismiss"
                          onClick={() => setDismissed(true)}
                        >
                          <Icon name="close" />
                        </button>
                      </div>
                    </Show>
                  );
                }}
              </Show>
            </main>
            <PairDialog open={pairing()} close={close} />
            <DeviceSignInDialog attempt={m.deviceSignIn()} />
          </div>
        </div>
      </Show>
      <Show when={m.busy()}>
        <div id="saving" role="status">
          Saving…
        </div>
      </Show>
    </>
  );
}
function ApprovalBar() {
  const m = useMonitor();
  const pending = m.pendingRequests;
  const proposals = m.pendingProposals;
  const total = m.pendingCount;
  return (
    <Show when={total()}>
      <div class="approval-bar" role="status" aria-label="Pending approvals">
        <Icon name="activity" />
        <div class="approval-copy">
          <strong>
            {total() === 1
              ? "1 item needs your approval"
              : `${total()} items need your approval`}
          </strong>
          <p>
            {proposals().length
              ? `${proposals().length} proposed change${proposals().length === 1 ? "" : "s"}${pending().length ? ` · ${pending().length} request${pending().length === 1 ? "" : "s"}` : ""}`
              : `${pending()[0].facts.principal.name} · ${owner.requestTitle(pending()[0])}`}
          </p>
        </div>
        <div class="approval-actions">
          <Show when={proposals().length}>
            <a
              class="button"
              href={
                proposals().length === 1
                  ? href("connections", "pending", proposals()[0].id)
                  : "#connections/pending"
              }
            >
              {proposals().length === 1 ? "Review change" : "Review changes"}{" "}
              <Icon name="arrow" />
            </a>
          </Show>
          <Show when={pending().length}>
            <a
              class="button"
              onClick={() => m.setActivity({ page: 0, anchor: 0 })}
              href={
                pending().length === 1
                  ? href("activity", "request", pending()[0].id)
                  : "#activity"
              }
            >
              {pending().length === 1 ? "Review request" : "Review requests"}{" "}
              <Icon name="arrow" />
            </a>
          </Show>
        </div>
      </div>
    </Show>
  );
}

function MonitorFooter() {
  const m = useMonitor();
  return (
    <Show when={m.options.backTo}>
      {(back) => (
        <footer class="monitor-footer">
          <a class="nav-item back-terminal" href={back()} link>
            <Icon name="arrow" />
            <span>Back</span>
          </a>
        </footer>
      )}
    </Show>
  );
}

function Page(props: {
  path: string;
  theme: string;
  onThemeChange: (theme: string) => void;
}) {
  const [kind, name = "", request] = parse(props.path);
  return (
    <Switch
      fallback={
        <Empty title="Page not found">
          <a href="#connections">Open connections</a>
        </Empty>
      }
    >
      <Match when={kind === "activity"}>
        <Activity scope={name} name={request} />
      </Match>
      <Match when={kind === "agents"}>
        <Agents expanded={name} />
      </Match>
      <Match when={kind === "connections"}>
        <Connections
          catalog={name === "catalog"}
          proposal={name === "pending" ? request : undefined}
        />
      </Match>
      <Match when={kind === "connection"}>
        <Connections expanded={name} />
      </Match>
      <Match when={kind === "request"}>
        <RequestDetail id={name} />
      </Match>
      <Match when={kind === "settings"}>
        <Settings theme={props.theme} onThemeChange={props.onThemeChange} />
      </Match>
    </Switch>
  );
}
function PairDialog(props: { open: boolean; close: () => void }) {
  const m = useMonitor();
  // Keep the contents mounted through the native dialog's exit transition.
  const opened = createMemo(
    (previous: boolean) => props.open || previous,
    false,
  );
  return (
    <Modal
      id="creation-dialog"
      aria-labelledby="creation-title"
      aria-describedby="creation-description"
      open={props.open}
      onClose={props.close}
    >
      <header class="dialog-header">
        <div>
          <h1 id="creation-title">Add a trusted device</h1>
          <p id="creation-description">
            Paste the SSH public key of a computer that may reach your
            sandboxes.
          </p>
        </div>
        <button
          class="dialog-close icon-button"
          aria-label="Close dialog"
          onClick={props.close}
        >
          <Icon name="close" />
        </button>
      </header>
      <div class="dialog-body">
        <Show when={opened()}>
          <AddAgent />
        </Show>
      </div>
      <Show when={m.message("#pair")}>
        <p class="dialog-notice" role="status">
          {m.message("#pair")}
        </p>
      </Show>
    </Modal>
  );
}
function Gate() {
  const m = useMonitor(),
    // Local dev (bun run dev) only: a prefilled passphrase so the dev
    // server unlocks with one click. Stripped from production builds.
    [key, setKey] = createSignal(import.meta.env.DEV ? "testtesttesttest" : "");
  const finish = (tinfoilApiKey?: () => Promise<string> | string) =>
    m.busy() ||
    m.perform(async (client) =>
      client.onboard(m.view()!, await tinfoilApiKey?.()),
    );
  const error = () => (
    <Show when={m.error()}>
      <p role="alert">{m.error()}</p>
    </Show>
  );
  return (
    <div class="start-page">
      {m.options.header}
      <Switch
        fallback={
          <AuthScreen
            id="gate"
            title={m.error() ? "Could not load Monitor" : undefined}
          >
            <Show
              when={m.error()}
              fallback={<Loading label="Loading Monitor…" />}
            >
              <AuthCard icon={<Icon name="warning" />}>
                {error()}
                <button class="primary" onClick={() => location.reload()}>
                  Reload
                </button>
              </AuthCard>
            </Show>
          </AuthScreen>
        }
      >
        <Match when={m.locked()}>
          <AuthScreen id="gate" title="Monitor is locked">
            <AuthCard icon={<Icon name="lock" />}>
              <p>Unlock the monitor to continue.</p>
              <button
                class="primary"
                disabled={m.busy()}
                onClick={() => void m.unlock()}
              >
                Unlock
              </button>
            </AuthCard>
          </AuthScreen>
        </Match>
        <Match when={m.mode() && !m.credential()}>
          <AuthScreen id="gate" title="Open Monitor">
            <AuthCard
              icon={<Icon name={m.mode() === "ssh" ? "terminal" : "key"} />}
            >
              <Show
                when={m.mode() === "ssh"}
                fallback={
                  <form
                    class="form-fields"
                    onSubmit={(e) => {
                      e.preventDefault();
                      m.login(key());
                    }}
                  >
                    <label>
                      Owner passphrase
                      <input
                        type="password"
                        required
                        autocomplete="current-password"
                        value={key()}
                        onInput={(e) => setKey(e.currentTarget.value)}
                      />
                    </label>
                    <button class="primary">Continue</button>
                  </form>
                }
              >
                <p>
                  Open this monitor through the attested owner SSH connection.
                </p>
                <pre>tinfoil monitor</pre>
              </Show>
              {error()}
            </AuthCard>
          </AuthScreen>
        </Match>
        <Match when={m.view() && !owner.onboarded(m.view()!)}>
          <AuthScreen
            id="gate"
            title="Connect Tinfoil to your sandbox"
            description="Use Tinfoil models in your sandbox for end-to-end confidential workloads."
          >
            <Onboarding
              busy={m.busy()}
              generate={m.options.tinfoilApiKey}
              error={error()}
              onFinish={finish}
            />
          </AuthScreen>
        </Match>
      </Switch>
    </div>
  );
}
function Onboarding(props: {
  busy: boolean;
  generate?: () => Promise<string>;
  error: JSX.Element;
  onFinish(tinfoilApiKey?: () => Promise<string> | string): void;
}) {
  const [tinfoilKey, setTinfoilKey] = createSignal("");
  return (
    <>
      <form
        class="auth-card onboarding"
        onSubmit={(e) => {
          e.preventDefault();
          props.onFinish(props.generate ?? tinfoilKey);
        }}
      >
        <span class="auth-icon">
          <span class="connector-icon" aria-hidden="true">
            <img
              class="dark-icon"
              src={import.meta.env.BASE_URL + "icons/tinfoil.dark.svg"}
              alt=""
            />
            <img
              class="light-icon"
              src={import.meta.env.BASE_URL + "icons/tinfoil.svg"}
              alt=""
            />
          </span>
        </span>
        <h2>Tinfoil API key</h2>
        <Show
          when={!props.generate}
          fallback={
            <p>Your key stays in Monitor, hidden from your sandboxes.</p>
          }
        >
          <fieldset class="onboarding-key" disabled={props.busy}>
            <div class="onboarding-key-label">
              <label for="tinfoil-api-key">API key</label>
              <a
                href="https://dash.tinfoil.sh/?tab=api-keys"
                target="_blank"
                rel="noopener noreferrer"
              >
                Get an API key
                <Icon name="external" />
              </a>
            </div>
            <input
              id="tinfoil-api-key"
              type="password"
              required
              autofocus
              pattern={".*\\S.*"}
              title="Enter your Tinfoil API key"
              placeholder="tk-…"
              autocomplete="off"
              spellcheck={false}
              aria-describedby="tinfoil-key-help"
              value={tinfoilKey()}
              onInput={(e) => setTinfoilKey(e.currentTarget.value)}
            />
            <p id="tinfoil-key-help" class="onboarding-key-help">
              <Icon name="rules" />
              Your key stays in Monitor, hidden from your sandboxes.
            </p>
          </fieldset>
        </Show>
        {props.error}
        <button class="primary" disabled={props.busy}>
          {props.busy
            ? "Saving…"
            : props.generate
              ? "Generate an API key automatically"
              : "Add the Tinfoil connection"}
        </button>
      </form>
      <button
        type="button"
        class="link auth-link"
        disabled={props.busy}
        onClick={() => props.onFinish()}
      >
        Skip for now
      </button>
    </>
  );
}
