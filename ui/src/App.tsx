import {
  ErrorBoundary,
  For,
  Match,
  Show,
  Switch,
  createEffect,
  createMemo,
  createSignal,
  onCleanup,
  onMount,
} from "solid-js";
import * as owner from "./owner.js";
import { MonitorProvider, useMonitor } from "./monitor";
import { Activity, RequestDetail } from "./Activity";
import { Agents, AddAgent } from "./Agents";
import { AddConnection, Catalog, Connections } from "./Connections";
import {
  Integrations,
  Policy,
  PresetEditor,
  Rules,
  Settings,
} from "./Settings";
import { ConnectorIcon, Empty, Icon, href } from "./components";

const sections: Record<string, [string, string]> = {
  activity: [
    "Activity",
    "Review requests and follow what your agents are doing.",
  ],
  agents: [
    "Agents",
    "Manage sandboxes, devices, and the actions they can take.",
  ],
  accounts: [
    "Connections",
    "Connect services and control how agents use their data.",
  ],
  rules: ["Saved rules", "Review permissions saved from request approvals."],
  settings: ["Settings", "Manage guardrails, policy, and monitor preferences."],
  integrations: [
    "Integrations",
    "Connect commands, shells, and MCP clients through Monitor.",
  ],
  presets: [
    "Connection preset editor",
    "Edit connection operations, actions, and setup fields.",
  ],
  policy: ["Policy", "Validate and review changes to your monitor's policy."],
};
const parse = (path: string) => {
  try {
    return path.split("/").map(decodeURIComponent);
  } catch {
    return ["accounts"];
  }
};
const isDialog = (path: string) =>
  ["pair", "catalog", "add"].includes(parse(path)[0]);

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
  const initial = location.hash.slice(1) || "accounts";
  const [route, setRoute] = createSignal(initial),
    [page, setPage] = createSignal(
      isDialog(initial)
        ? initial === "pair"
          ? "agents"
          : "accounts"
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
      account: "accounts",
      request: "activity",
      policy: "settings",
      presets: "settings",
      preset: "settings",
    })[kind()] ?? kind();
  const title = () =>
    sections[
      ["agent", "agent-settings"].includes(kind())
        ? "agents"
        : kind() === "account"
          ? "accounts"
          : kind()
    ]?.[0] ??
    (kind() === "request"
      ? "Request"
      : kind() === "preset"
        ? `Preset: ${args()[0] || "New preset"}`
        : args()[0] || "Monitor");
  const count = (section: string) =>
    section === "activity"
      ? m.records().filter((r) => owner.stateAt(r, m.now()) === "pending")
          .length
      : Object.keys(
          (section === "agents"
            ? m.view()?.config.identities
            : section === "accounts"
              ? m.view()?.config.accounts
              : {}) ?? {},
        ).length;
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
      const next = location.hash.slice(1) || "accounts";
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
              <For
                each={["activity", "agents", "accounts", "rules", "settings"]}
              >
                {(key) => (
                  <a
                    class="nav-item"
                    classList={{ on: section() === key }}
                    aria-current={section() === key ? "page" : undefined}
                    href={href(key)}
                  >
                    <Icon name={key} />
                    <span>{sections[key][0]}</span>
                    <Show when={count(key)}>
                      <small class="nav-count">{count(key)}</small>
                    </Show>
                  </a>
                )}
              </For>
            </nav>
            <div class="navigation-footer">
              <div>
                <span class="owner-avatar" aria-hidden="true">
                  M
                </span>
                <span>
                  Monitor owner
                  <small>
                    {m.mode() === "ssh"
                      ? "Local SSH connection"
                      : "Local development"}
                  </small>
                </span>
                <button
                  id="theme-toggle"
                  class="icon-button"
                  aria-label={`Theme: ${theme()}. Change color theme`}
                  onClick={() =>
                    setTheme(
                      ["system", "light", "dark"][
                        (["system", "light", "dark"].indexOf(theme()) + 1) % 3
                      ],
                    )
                  }
                >
                  <Icon
                    name={
                      (theme() === "system" ? dark() : theme() === "dark")
                        ? "sun"
                        : "moon"
                    }
                  />
                </button>
              </div>
            </div>
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
                          : kind() === "account"
                            ? "accounts"
                            : kind()
                      ]?.[1]
                    }
                  </p>
                </div>
                <div class="header-actions">
                  <Show when={section() === "agents"}>
                    <a class="button primary" href="#pair">
                      <Icon name="plus" />
                      Add agent
                    </a>
                  </Show>
                  <Show when={kind() === "accounts" || kind() === "account"}>
                    <a class="button primary" href="#catalog">
                      <Icon name="plus" />
                      Add connection
                    </a>
                  </Show>
                  <Show when={kind() === "presets"}>
                    <a class="button primary" href="#preset">
                      <Icon name="plus" />
                      New preset
                    </a>
                  </Show>
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
                {(path) => <Page path={path} />}
              </Show>
            </div>
          </main>
        </div>
        <CreationDialog path={dialogRoute()} close={close} />
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
function Page(props: { path: string }) {
  const [kind, name = "", request] = parse(props.path);
  return (
    <Switch
      fallback={
        <Empty title="Page not found">
          <a href="#accounts">Open connections</a>
        </Empty>
      }
    >
      <Match when={kind === "activity"}>
        <Activity scope={name} name={request} />
      </Match>
      <Match
        when={
          kind === "agents" || kind === "agent" || kind === "agent-settings"
        }
      >
        <Agents expanded={name} />
      </Match>
      <Match when={kind === "accounts"}>
        <Connections />
      </Match>
      <Match when={kind === "account"}>
        <Connections expanded={name} />
      </Match>
      <Match when={kind === "request"}>
        <RequestDetail id={name} />
      </Match>
      <Match when={kind === "settings"}>
        <Settings />
      </Match>
      <Match when={kind === "integrations"}>
        <Integrations page={name} />
      </Match>
      <Match when={kind === "rules"}>
        <Rules />
      </Match>
      <Match when={kind === "policy"}>
        <Policy />
      </Match>
      <Match when={kind === "presets"}>
        <Catalog edit />
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
  let motion: Animation | undefined;
  // Keep the contents mounted through the native dialog's exit transition.
  const path = createMemo((previous: string) => props.path || previous, "");
  const kind = () => parse(path())[0],
    preset = () => parse(path())[1] ?? "";
  createEffect(() => {
    const opening = !!props.path;
    if (opening && dialog.open && !dialog.hasAttribute("data-closing")) return;
    if (!opening && !dialog.open) return;
    const style = dialog.open ? getComputedStyle(dialog) : undefined;
    const from = {
      opacity: style?.opacity ?? "0",
      transform: style?.transform ?? "scale(.98)",
    };
    motion?.cancel();
    motion = undefined;
    if (opening && !dialog.open) dialog.showModal();
    dialog.toggleAttribute("data-closing", !opening);
    if (matchMedia("(prefers-reduced-motion: reduce)").matches) {
      if (!opening) dialog.close();
      dialog.removeAttribute("data-closing");
      return;
    }
    const next = dialog.animate(
      [
        from,
        {
          opacity: opening ? "1" : "0",
          transform: opening ? "none" : "scale(.98)",
        },
      ],
      {
        duration: 120,
        easing: opening ? "ease-out" : "ease-in",
        fill: "forwards",
      },
    );
    motion = next;
    next.onfinish = () => {
      if (motion !== next) return;
      if (!opening) dialog.close();
      next.cancel();
      motion = undefined;
      dialog.removeAttribute("data-closing");
    };
  });
  onCleanup(() => {
    motion?.cancel();
    dialog.close();
  });
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
              location.hash = "#catalog";
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
              ? "Add an agent"
              : kind() === "catalog"
                ? "Add connection"
                : "Add " + (m.view()!.presets[preset()]?.title ?? "connection")}
          </h1>
          <Show when={kind() === "pair"}>
            <p id="creation-description">
              Give an agent access using its SSH public key.
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
            ) : parse(path)[0] === "catalog" ? (
              <Catalog />
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
    [key, setKey] = createSignal(""),
    [preset, setPreset] = createSignal<owner.PolicyPreset>("known_only"),
    [paid, setPaid] = createSignal(true);
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
              void m.perform(
                (client) =>
                  client.onboard(m.view()!, preset(), undefined, {
                    allowPaidInference: paid(),
                  }),
                "Policy saved",
              );
            }}
          >
            <h1>Set up your monitor</h1>
            <p>Choose how agents can connect to the outside world.</p>
            <fieldset disabled={m.busy()}>
              <legend>Network policy</legend>
              <For each={Object.entries(owner.POLICY_PRESETS)}>
                {([value, option]) => (
                  <label class="policy-choice">
                    <input
                      type="radio"
                      name="network-policy"
                      value={value}
                      checked={preset() === value}
                      onChange={() => setPreset(value as owner.PolicyPreset)}
                    />
                    <span>
                      <strong>{option.title}</strong>
                      <small>{option.description}</small>
                    </span>
                  </label>
                )}
              </For>
            </fieldset>
            <label class="policy-choice">
              <input
                type="checkbox"
                role="switch"
                checked={paid()}
                onChange={(e) => setPaid(e.currentTarget.checked)}
              />
              <span>
                <strong>Allow paid AI inference</strong>
                <small>
                  Use paid AI models without payment approval. Provider charges
                  apply.
                </small>
              </span>
            </label>
            <button class="primary" disabled={m.busy()}>
              Use this policy
            </button>
          </form>
        </Match>
      </Switch>
    </div>
  );
}
