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
} from "solid-js";
import * as owner from "./owner.js";
import { MonitorProvider, useMonitor } from "./monitor";
import { Activity, RequestDetail } from "./Activity";
import { Agents, AddAgent } from "./Agents";
import { AddConnection, Connections, DeviceSignInDialog } from "./Connections";
import {
  ConnectorIcon,
  Empty,
  Icon,
  createDialogMotion,
  href,
} from "./components";

const Settings = lazy(() =>
  import("./Settings").then((m) => ({ default: m.Settings })),
);
const Integrations = lazy(() =>
  import("./Settings").then((m) => ({ default: m.Integrations })),
);
const Policy = lazy(() =>
  import("./Settings").then((m) => ({ default: m.Policy })),
);
const PresetEditor = lazy(() =>
  import("./Settings").then((m) => ({ default: m.PresetEditor })),
);

const sections: Record<string, [string, string]> = {
  activity: ["Activity", "Review requests and manage saved approval rules."],
  agents: ["Sandboxes", "Your sandboxes and the devices that may reach them."],
  connections: [
    "Connections",
    "Connect services and control how sandboxes use their data.",
  ],
  settings: ["Settings", "Manage guardrails, policy, and monitor preferences."],
  integrations: [
    "Integrations",
    "Connect commands, shells, and MCP clients through Monitor.",
  ],
  policy: ["Policy", "Validate and review changes to your monitor's policy."],
};
const parse = (path: string) => {
  try {
    return path.split("/").map(decodeURIComponent);
  } catch {
    return ["connections"];
  }
};
const isDialog = (path: string) => ["pair", "add"].includes(parse(path)[0]);

export default function App() {
  return (
    <ErrorBoundary
      fallback={(error) => (
        <div id="gate">
          <h1>Could not show Monitor</h1>
          <p>{String(error)}</p>
          <button onClick={() => location.reload()}>Reload</button>
        </div>
      )}
    >
      <MonitorProvider>
        <Shell />
      </MonitorProvider>
    </ErrorBoundary>
  );
}
function Shell() {
  const m = useMonitor();
  const initial = location.hash.slice(1) || "connections";
  const [route, setRoute] = createSignal(initial),
    [page, setPage] = createSignal(
      isDialog(initial)
        ? initial === "pair"
          ? "agents"
          : "connections/catalog"
        : initial,
    );
  const [mobile, setMobile] = createSignal(false),
    [theme, setTheme] = createSignal(
      localStorage.getItem("monitor-theme") || "system",
    );
  const media = matchMedia("(prefers-color-scheme: dark)"),
    [dark, setDark] = createSignal(media.matches);
  const dialogRoute = createMemo(() => (isDialog(route()) ? route() : ""));
  const kind = () => parse(page())[0],
    args = () => parse(page()).slice(1);
  const section = () =>
    ({
      agent: "agents",
      "agent-settings": "agents",
      accounts: "connections",
      account: "connections",
      connection: "connections",
      catalog: "connections",
      request: "activity",
      rules: "activity",
      policy: "settings",
      presets: "connections",
      preset: "connections",
    })[kind()] ?? kind();
  const title = () =>
    sections[
      ["agent", "agent-settings"].includes(kind())
        ? "agents"
        : kind() === "rules"
          ? "activity"
          : [
                "account",
                "accounts",
                "connection",
                "catalog",
                "presets",
              ].includes(kind())
            ? "connections"
            : kind()
    ]?.[0] ??
    (kind() === "request"
      ? "Request"
      : kind() === "preset"
        ? `Preset: ${args()[0] || "New preset"}`
        : args()[0] || "Monitor");
  const count = (section: string) =>
    section === "activity"
      ? m.pendingCount()
      : Object.keys(
          (section === "agents"
            ? m.view()?.config.identities
            : section === "connections"
              ? m.view()?.config.accounts
              : {}) ?? {},
        ).length;
  const NavItem = (props: { key: string }) => (
    <a
      class="nav-item"
      classList={{ on: section() === props.key }}
      aria-current={section() === props.key ? "page" : undefined}
      href={href(props.key)}
    >
      <Icon name={props.key} />
      <span>{sections[props.key][0]}</span>
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
      const next = location.hash.slice(1) || "connections";
      setRoute(next);
      if (!isDialog(next)) setPage(next);
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
    document.documentElement.dataset.theme =
      theme() === "system" ? (dark() ? "dark" : "light") : theme();
    localStorage.setItem("monitor-theme", theme());
  });
  return (
    <>
      <Show
        when={m.view() && !m.locked() && owner.onboarded(m.view()!)}
        fallback={<Gate />}
      >
        <div id="app" classList={{ "navigation-open": mobile() }}>
          <aside id="navigation" aria-label="Monitor navigation">
            <a class="brand" href="#activity">
              <img src="/app/icons/tinfoil-white.svg" alt="Tinfoil" />
              <span>Monitor</span>
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
              <For each={["agents", "activity", "connections", "settings"]}>
                {(key) => <NavItem key={key} />}
              </For>
            </nav>
          </aside>
          <main id="workspace" tabIndex={-1}>
            <header id="page-header">
              <div class="page-heading">
                <div>
                  <h1>{title()}</h1>
                  <p>
                    {
                      sections[
                        ["agent", "agent-settings"].includes(kind())
                          ? "agents"
                          : kind() === "rules"
                            ? "activity"
                            : [
                                  "account",
                                  "accounts",
                                  "connection",
                                  "catalog",
                                  "presets",
                                ].includes(kind())
                              ? "connections"
                              : kind()
                      ]?.[1]
                    }
                  </p>
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
                  <Page path={path} theme={theme()} onThemeChange={setTheme} />
                )}
              </Show>
            </div>
          </main>
        </div>
        <CreationDialog path={dialogRoute()} close={close} />
        <DeviceSignInDialog attempt={m.deviceSignIn()} />
      </Show>
      <Show when={m.message() && !dialogRoute()}>
        <div id="toast" role="status">
          {m.message()}
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
      <Match when={kind === "activity" || kind === "rules"}>
        <Activity scope={kind === "rules" ? "rules" : name} name={request} />
      </Match>
      <Match
        when={
          kind === "agents" || kind === "agent" || kind === "agent-settings"
        }
      >
        <Agents expanded={name} />
      </Match>
      <Match
        when={
          kind === "connections" || kind === "accounts" || kind === "catalog"
        }
      >
        <Connections catalog={kind === "catalog" || name === "catalog"} />
      </Match>
      <Match when={kind === "connection" || kind === "account"}>
        <Connections expanded={name} />
      </Match>
      <Match when={kind === "request"}>
        <RequestDetail id={name} />
      </Match>
      <Match when={kind === "settings"}>
        <Settings theme={props.theme} onThemeChange={props.onThemeChange} />
      </Match>
      <Match when={kind === "integrations"}>
        <Integrations page={name} />
      </Match>
      <Match when={kind === "policy"}>
        <Policy />
      </Match>
      <Match when={kind === "presets"}>
        <Connections catalog />
      </Match>
      <Match when={kind === "preset"}>
        <PresetEditor name={name} request={request} />
      </Match>
    </Switch>
  );
}
function CreationDialog(props: { path: string; close: () => void }) {
  const m = useMonitor();
  let dialog!: HTMLDialogElement;
  // Keep the contents mounted through the native dialog's exit transition.
  const path = createMemo((previous: string) => props.path || previous, "");
  const kind = () => parse(path())[0],
    preset = () => parse(path())[1] ?? "";
  createDialogMotion(
    () => dialog,
    () => !!props.path,
  );
  return (
    <dialog
      ref={dialog}
      id="creation-dialog"
      aria-labelledby="creation-title"
      aria-describedby={kind() === "pair" ? "creation-description" : undefined}
      onCancel={(e) => {
        e.preventDefault();
        props.close();
      }}
      onClick={(e) => {
        if (e.target === dialog) {
          const r = dialog.getBoundingClientRect();
          if (
            e.clientX < r.left ||
            e.clientX > r.right ||
            e.clientY < r.top ||
            e.clientY > r.bottom
          )
            props.close();
        }
      }}
    >
      <header class="dialog-header">
        <Show when={kind() === "add"}>
          <button
            type="button"
            class="icon-button dialog-back"
            aria-label="Choose another service"
            title="Choose another service"
            onClick={() => {
              location.hash = "#connections/catalog";
            }}
          >
            <Icon name="arrow" />
          </button>
        </Show>
        <div>
          <h1 id="creation-title">
            <Show when={kind() === "add"}>
              <ConnectorIcon preset={preset()} />
            </Show>
            {kind() === "pair"
              ? "Add a trusted device"
              : "Add " + (m.view()!.presets[preset()]?.title ?? "connection")}
          </h1>
          <Show when={kind() === "pair"}>
            <p id="creation-description">
              Paste the SSH public key of a computer that may reach your
              sandboxes.
            </p>
          </Show>
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
        <Show when={path()} keyed>
          {(path) =>
            parse(path)[0] === "pair" ? (
              <AddAgent />
            ) : (
              <AddConnection preset={parse(path)[1]} />
            )
          }
        </Show>
      </div>
      <Show when={m.message("#" + path())}>
        <p class="dialog-notice" role="status">
          {m.message("#" + path())}
        </p>
      </Show>
    </dialog>
  );
}
function Gate() {
  const m = useMonitor(),
    // Local dev (bun run dev) only: a prefilled passphrase so the dev
    // server unlocks with one click. Stripped from production builds.
    [key, setKey] = createSignal(import.meta.env.DEV ? "testtesttesttest" : ""),
    [step, setStep] = createSignal<"policy" | "tinfoil">("policy"),
    [tinfoilKey, setTinfoilKey] = createSignal("");
  let heading!: HTMLHeadingElement, tinfoilInput!: HTMLInputElement;
  const goToStep = (next: "policy" | "tinfoil") => {
    setStep(next);
    (next === "tinfoil" ? tinfoilInput : heading).focus();
  };
  const finish = async (tinfoilApiKey?: string) => {
    if (m.busy()) return;
    if (
      await m.perform(
        (client) =>
          client.onboard(m.view()!, "known_only", undefined, {
            allowPaidInference: true,
            tinfoilApiKey,
          }),
        "Monitor set up",
      )
    )
      setTinfoilKey("");
  };
  return (
    <div id="gate">
      <Switch
        fallback={
          <>
            <h1>Loading Monitor…</h1>
            <Show when={m.error()}>
              <p role="alert">{m.error()}</p>
              <button onClick={() => location.reload()}>Reload</button>
            </Show>
          </>
        }
      >
        <Match when={m.locked()}>
          <h1>Monitor is locked</h1>
          <p>Unlock the monitor to continue.</p>
          <button
            class="primary"
            disabled={m.busy()}
            onClick={() => void m.unlock()}
          >
            Unlock
          </button>
        </Match>
        <Match when={m.mode() && !m.credential()}>
          <h1>Open Monitor</h1>
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
            <p>Open this monitor through the attested owner SSH connection.</p>
            <pre>tinfoil monitor</pre>
          </Show>
          <Show when={m.error()}>
            <p role="alert">{m.error()}</p>
          </Show>
        </Match>
        <Match when={m.view() && !owner.onboarded(m.view()!)}>
          <form
            class="onboarding"
            onSubmit={(e) => {
              e.preventDefault();
              if (step() === "policy") goToStep("tinfoil");
              else void finish(tinfoilKey());
            }}
          >
            <header class="onboarding-heading">
              <ConnectorIcon preset="tinfoil" />
              <h1 ref={heading} tabIndex={-1}>
                {step() === "policy"
                  ? "Set up your monitor"
                  : "Connect Tinfoil"}
              </h1>
              <Show when={step() === "tinfoil"}>
                <p>Use Tinfoil for private AI inference and web search.</p>
              </Show>
            </header>
            <Switch>
              <Match when={step() === "policy"}>
                <section class="onboarding-section">
                  <h2>Networking</h2>
                  <p>
                    Networking is off by default. Nothing in a sandbox can reach
                    anything until you add a <code>connection</code>.
                  </p>
                </section>
                <button class="primary" disabled={m.busy()}>
                  Continue
                  <Icon name="arrow" />
                </button>
              </Match>
              <Match when={step() === "tinfoil"}>
                <fieldset class="onboarding-key" disabled={m.busy()}>
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
                    ref={tinfoilInput}
                    id="tinfoil-api-key"
                    type="password"
                    required
                    autofocus
                    pattern={".*\\S.*"}
                    title="Enter your Tinfoil API key"
                    placeholder="Paste your Tinfoil API key"
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
                <button class="primary" disabled={m.busy()}>
                  {m.busy() ? "Saving…" : "Connect Tinfoil"}
                  <Icon name="arrow" />
                </button>
                <div class="onboarding-actions">
                  <button
                    type="button"
                    class="link onboarding-back"
                    disabled={m.busy()}
                    onClick={() => goToStep("policy")}
                  >
                    <Icon name="arrow" />
                    Back
                  </button>
                  <button
                    type="button"
                    class="link"
                    disabled={m.busy()}
                    onClick={() => void finish()}
                  >
                    Skip for now
                  </button>
                </div>
              </Match>
            </Switch>
          </form>
        </Match>
      </Switch>
    </div>
  );
}
