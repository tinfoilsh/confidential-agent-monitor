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
import { ApprovalToasts } from "./Approvals";
import { Agents, AddAgent } from "./Agents";
import { Connections, DeviceSignInDialog } from "./Connections";
import { Onboarding } from "./Onboarding";
import {
  AuthCard,
  AuthScreen,
  ConfirmDialog,
  Empty,
  Icon,
  type IconName,
  Loading,
  Modal,
  href,
} from "./components";
import { THEME, applyTheme, savedTheme } from "./theme";

const SandboxTerminal = lazy(() => import("./SandboxTerminal"));
const headings: Record<string, [title: string, description: string]> = {
  activity: [
    "Activity",
    "Requests from your bunkers and how each was answered.",
  ],
  agents: [
    "Bunkers",
    "Your bunkers and the devices that may reach them. The Perimeter can always be accessed by you.",
  ],
  connections: [
    "Permissions",
    "Choose what your bunkers can reach and what needs your approval.",
  ],
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
          <AuthScreen id="gate" title="Could not show Perimeter">
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
  const approvals = () =>
    m.pendingCount() + (m.view() ? owner.toolReviews(m.view()!).length : 0);
  const count = (section: string) =>
    section === "connections"
      ? approvals()
      : section === "agents"
        ? Object.keys(m.view()?.config.identities ?? {}).length
        : 0;
  // The open shell is a sidebar tab; other pages keep its session running.
  const shellShown = () => {
    const [kind, name, view] = parse(page());
    return kind === "agents" && view === "terminal" && name === m.shell();
  };
  // The Permissions list shows the same approvals the notices would.
  const approvalsListed = () => {
    const [kind, view] = parse(page());
    return (
      !shellShown() &&
      (kind === "connection" ||
        (kind === "connections" && view !== "catalog" && view !== "rules"))
    );
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
        <small
          class="nav-count"
          classList={{ "nav-attention": props.key === "connections" }}
        >
          {count(props.key)}
          <Show when={props.key === "connections"}>
            <span class="sr-only"> waiting for approval</span>
          </Show>
        </small>
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
            <aside id="navigation" aria-label="Perimeter navigation">
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
                <For each={["agents", "activity", "connections"] as const}>
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
              <MonitorFooter theme={theme()} onThemeChange={setTheme} />
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
                      <h1>{heading()?.[0] ?? "Perimeter"}</h1>
                      <p>{heading()?.[1]}</p>
                    </div>
                  </div>
                </header>
                <div id="page-content">
                  <Show when={page()} keyed>
                    {(path) => <Page path={path} />}
                  </Show>
                  <div id="notices">
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
                          This Perimeter cannot open a shell in {name}.
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
            </main>
            <ApprovalToasts hidden={approvalsListed()} />
            <PairDialog open={pairing()} close={close} />
            <DeviceSignInDialog attempt={m.deviceSignIn()} />
            <ConfirmDialog />
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
const THEMES = [
  ["system", "System theme", "devices"],
  ["light", "Light theme", "sun"],
  ["dark", "Dark theme", "moon"],
] as const;

function MonitorFooter(props: {
  theme: string;
  onThemeChange: (theme: string) => void;
}) {
  const m = useMonitor();
  return (
    <footer class="monitor-footer">
      <Show when={m.options.backTo}>
        {(back) => (
          <a class="nav-item back-terminal" href={back()} link>
            <Icon name="arrow" />
            <span>Back</span>
          </a>
        )}
      </Show>
      <div class="theme-switch" role="group" aria-label="Color theme">
        <For each={THEMES}>
          {([theme, label, icon]) => (
            <button
              type="button"
              aria-label={label}
              title={label}
              aria-pressed={props.theme === theme}
              onClick={() => props.onThemeChange(theme)}
            >
              <Icon name={icon} />
            </button>
          )}
        </For>
      </div>
    </footer>
  );
}

function Page(props: { path: string }) {
  const [kind, name = "", request] = parse(props.path);
  return (
    <Switch
      fallback={
        <Empty title="Page not found">
          <a href="#connections">Open permissions</a>
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
          view={name === "catalog" || name === "rules" ? name : undefined}
          proposal={name === "pending" ? request : undefined}
        />
      </Match>
      <Match when={kind === "connection"}>
        <Connections expanded={name} />
      </Match>
      <Match when={kind === "request"}>
        <RequestDetail id={name} />
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
      class="dialog-panel"
      aria-labelledby="creation-title"
      aria-describedby="creation-description"
      open={props.open}
      onClose={props.close}
    >
      <header class="dialog-header">
        <div>
          <h1 id="creation-title">Add a trusted device</h1>
          <p id="creation-description">
            Paste the SSH public key of a computer that may reach your bunkers.
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
  const finish = async (
    choices: owner.OnboardingChoices,
    signIns: string[],
  ) => {
    const existing = new Set(Object.keys(m.view()!.config.connections ?? {}));
    if (
      m.busy() ||
      !(await m.perform((client) => client.onboard(m.view()!, choices)))
    )
      return;
    // Setup continues into the first sign-in; any others wait in Permissions.
    const view = m.view()!;
    for (const preset of signIns) {
      const name = Object.keys(view.config.connections ?? {}).find(
        (name) =>
          !existing.has(name) &&
          view.config.connections![name].preset === preset,
      );
      const field =
        name && owner.credentialFields(view, name).find((f) => f.signIn);
      if (field) return void m.signIn(name, field);
    }
  };
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
            title={m.error() ? "Could not load Perimeter" : undefined}
          >
            <Show
              when={m.error()}
              fallback={<Loading label="Loading Perimeter…" />}
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
          <AuthScreen id="gate" title="Perimeter is locked">
            <AuthCard icon={<Icon name="lock" />}>
              <p>Unlock the Perimeter to continue.</p>
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
          <AuthScreen id="gate" title="Open Perimeter">
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
                  Open this Perimeter through the attested owner SSH connection.
                </p>
                <pre>tinfoil perimeter open NAME</pre>
              </Show>
              {error()}
            </AuthCard>
          </AuthScreen>
        </Match>
        <Match when={m.view() && !owner.onboarded(m.view()!)}>
          <Onboarding busy={m.busy()} error={error()} onFinish={finish} />
        </Match>
      </Switch>
    </div>
  );
}
