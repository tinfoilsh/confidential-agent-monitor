import type { Clerk } from "@clerk/clerk-js/no-rhc";
import type { PasskeyKeyManager, PasskeyUser } from "@tinfoilsh/passkey-kit";
import {
  For,
  Show,
  batch,
  createEffect,
  createSignal,
  onCleanup,
  onMount,
  type JSX,
} from "solid-js";
import App from "../App";
import {
  Empty,
  Icon,
  ResourceDisclosure,
  Search,
  ShellSplit,
  type ShellTarget,
} from "../components";
import { OwnerError, type Snapshot } from "../owner";
import * as cp from "./controlplane";
import * as keys from "./keys";
import {
  MissingState,
  attestMonitor,
  enrollSandbox,
  initIntents,
  openMonitor,
  ownedMonitor,
  sandboxIdentity,
  sandboxMonitorSSH,
  type AttestMonitor,
  type MonitorSession,
} from "./monitors";
import "./console.css";

// The path names the Monitor: terminal.tinfoil.sh/<monitor>. The hash stays the
// Monitor's own page. Sign-in and connection sign-in return to the same path.
const BASE = import.meta.env.BASE_URL.replace(/\/$/, "");
const routeName = () =>
  decodeURIComponent(
    location.pathname.slice(BASE.length).replace(/^\/+|\/+$/g, ""),
  );
const routeTo = (name: string | undefined, replace = false) => {
  const url = `${BASE}/${name ? encodeURIComponent(name) : ""}${location.hash}`;
  if (url === location.pathname + location.hash) return;
  history[replace ? "replaceState" : "pushState"](null, "", url);
};
const DASHBOARD = "https://dash.tinfoil.sh";
const MEMBERS_PAGE_SIZE = 100;

type Account = { id: string; label: string; user: PasskeyUser };
type Failure = { message: string; cause: unknown; recover?: () => void };
type Kind = "monitor" | "sandbox";
const STATES: Record<cp.Status, [label: string, tone: string]> = {
  created: ["Provisioning", "status-pending"],
  pending: ["Queued", "status-pending"],
  deploying: ["Deploying", "status-pending"],
  started: ["Booting", "status-pending"],
  running: ["Running", "status-allowed"],
  stopping: ["Stopping", "status-pending"],
  stopped: ["Stopped", "status-expired"],
  failed: ["Failed", "status-denied"],
};
const ICONS: Record<Kind, string> = { monitor: "rules", sandbox: "sandboxes" };

const accountOf = (clerk: Clerk): Account | undefined => {
  const user = clerk.user;
  if (!user) return;
  const email = user.primaryEmailAddress?.emailAddress;
  return {
    id: user.id,
    label: email ?? user.id,
    user: {
      id: new TextEncoder().encode(user.id),
      name: email ?? user.id,
      displayName: user.fullName ?? email ?? user.id,
    },
  };
};
const text = (cause: unknown) => keys.passkeyMessage(cause);
const isAbort = (cause: unknown) =>
  cause instanceof DOMException && cause.name === "AbortError";

// Services are injectable so tests can replace the network, attestation and passkey ceremonies.
export default function Console(props: {
  clerk: Clerk;
  attest?: AttestMonitor;
  api?: cp.Controlplane;
  passkeys?: (userId: string) => PasskeyKeyManager;
}) {
  const clerk = props.clerk;
  const [account, setAccount] = createSignal(accountOf(clerk));
  let sessionId = clerk.session?.id;
  const token = async () => (await clerk.session?.getToken()) ?? null;
  const api = props.api ?? cp.controlplane(token);
  const passkeys = props.passkeys ?? keys.passkeys;
  const intents = () => initIntents(localStorage, account()!.id);
  let manager: PasskeyKeyManager | undefined =
    account() && passkeys(account()!.id);
  let accountKey: Uint8Array | undefined, root: Uint8Array | undefined;
  // Aborted on lock, which ends every request, follow and open started while unlocked.
  let work = new AbortController();
  const [unlocked, setUnlocked] = createSignal(false);
  const [session, setSession] = createSignal<MonitorSession>();
  const [snapshot, setSnapshot] = createSignal<Snapshot>();
  const [error, setError] = createSignal("");
  const [busy, setBusy] = createSignal("");
  const [rows, setRows] = createSignal<cp.Container[]>([]);
  const [pending, setPending] = createSignal<Record<string, string>>({});
  const [failures, setFailures] = createSignal<Record<string, Failure>>({});
  const [route, setRoute] = createSignal(routeName());
  const onPop = () => setRoute(routeName());
  addEventListener("popstate", onPop);
  onCleanup(() => removeEventListener("popstate", onPop));
  const [viewing, setViewing] = createSignal(false);
  const [shell, setShell] = createSignal<ShellTarget>();
  const [query, setQuery] = createSignal("");
  const [members, setMembers] = createSignal<Record<string, string>>({});
  const [menu, setMenu] = createSignal(false);
  let opening: { id: string; session: Promise<MonitorSession> } | undefined;
  // Closing the shell pane cancels whatever is still preparing it.
  let preparing: AbortController | undefined;

  const closeMonitor = () => {
    session()?.close();
    opening = undefined;
    setSession(undefined);
    setSnapshot(undefined);
    setViewing(false);
  };
  const closeShell = () => {
    preparing?.abort();
    setShell(undefined);
  };
  const lock = (forget = true) =>
    batch(() => {
      work.abort(new DOMException("Locked.", "AbortError"));
      work = new AbortController();
      closeShell();
      closeMonitor();
      accountKey?.fill(0);
      root?.fill(0);
      accountKey = root = undefined;
      setUnlocked(false);
      setBusy("");
      setPending({});
      setFailures({});
      if (forget) manager?.clearLocalState();
    });
  const stopListening = clerk.addListener(({ user, session }) => {
    if (user?.id === account()?.id && session?.id === sessionId) return;
    sessionId = session?.id;
    batch(() => {
      lock();
      setRows([]);
      setMembers({});
      setError("");
      manager = user ? passkeys(user.id) : undefined;
      setAccount(accountOf(clerk));
    });
    if (user) void unlock(false);
  });
  onCleanup(() => {
    stopListening();
    lock(false);
  });

  async function run(label: string, task: () => Promise<void>) {
    const signal = work.signal;
    setBusy(label);
    setError("");
    try {
      await task();
    } catch (cause) {
      if (!signal.aborted && !isAbort(cause)) setError(text(cause));
    } finally {
      if (!signal.aborted) setBusy("");
    }
  }

  const refresh = async () => {
    const signal = work.signal;
    const list = await api.list(signal);
    if (!signal.aborted) setRows(list);
  };
  // A ceremony can finish after Lock and cache its PRF output; forget it again then.
  const settle = async <T,>(
    signal: AbortSignal,
    owner: PasskeyKeyManager,
    task: Promise<T>,
  ) => {
    try {
      return await task;
    } finally {
      if (signal.aborted) owner.clearLocalState();
    }
  };
  const unlock = (interactive: boolean) =>
    run(interactive ? "Waiting for your passkey…" : "Unlocking…", async () => {
      const me = account(),
        owner = manager;
      if (!me || !owner) return;
      const signal = work.signal;
      const key = await settle(
        signal,
        owner,
        keys.unlockConsole({
          store: keys.keyStore(me.id),
          manager: owner,
          user: me.user,
          interactive,
          signal,
        }),
      );
      if (key) await accept(key, signal);
    });
  onMount(() => account() && void unlock(false));
  async function accept(key: Uint8Array, signal: AbortSignal) {
    if (signal.aborted) return void key.fill(0);
    accountKey = key;
    root = keys.monitorRoot(key);
    setUnlocked(true);
    void loadMembers();
    await refresh();
  }

  // Names are a courtesy; without them rows still say another member created them.
  const loadMembers = async () => {
    const signal = work.signal;
    const list = await clerk.organization
      ?.getMemberships({ pageSize: MEMBERS_PAGE_SIZE })
      .catch(() => undefined);
    if (signal.aborted) return;
    setMembers(
      Object.fromEntries(
        (list?.data ?? []).map(({ publicUserData: user }) => [
          user?.userId ?? "",
          [user?.firstName, user?.lastName].filter(Boolean).join(" ") ||
            (user?.identifier ?? ""),
        ]),
      ),
    );
  };
  // Keys are cleared before Clerk is asked, so a failed sign-out cannot leave them unlocked.
  const signOut = () => {
    lock();
    const signal = work.signal;
    clerk.signOut().catch((cause) => signal.aborted || setError(text(cause)));
  };

  const update = (row: cp.Container) =>
    setRows((list) =>
      list.map((r) => (r.id === row.id ? { ...r, ...row } : r)),
    );
  const act = async (
    id: string,
    label: string,
    task: (signal: AbortSignal) => Promise<void>,
    recover?: () => void,
  ) => {
    const signal = work.signal;
    setPending((p) => ({ ...p, [id]: label }));
    setFailures(({ [id]: _, ...rest }) => rest);
    try {
      await task(signal);
    } catch (cause) {
      if (!signal.aborted && !isAbort(cause))
        setFailures((f) => ({
          ...f,
          [id]: {
            message: text(cause),
            cause,
            recover:
              cause instanceof OwnerError && cause.status === 403
                ? undefined
                : recover,
          },
        }));
    } finally {
      if (!signal.aborted) {
        setPending(({ [id]: _, ...rest }) => rest);
        await refresh().catch(
          (cause) => signal.aborted || setError(text(cause)),
        );
      }
    }
  };
  const start = async (row: cp.Container) => {
    const signal = work.signal;
    await act(row.id, "Starting", async (signal) => {
      await cp.follow(
        api,
        await api.start(row.id, signal),
        "running",
        signal,
        update,
      );
    });
    if (
      !signal.aborted &&
      row.repo === cp.SANDBOX_REPO &&
      sandboxMonitorSSH(row) &&
      !failures()[row.id]
    )
      await enroll(row);
  };
  const stop = (row: cp.Container) =>
    act(row.id, "Stopping", async (signal) => {
      await cp.follow(
        api,
        await api.stop(row.id, signal),
        "stopped",
        signal,
        update,
      );
    });
  // One Monitor session at a time; shells and enrollment reuse it without opening its pages.
  const connect = (monitorId: string, initialize = false) => {
    const current = session();
    if (current?.row.id === monitorId && !current.signal.aborted && !initialize)
      return Promise.resolve(current);
    if (opening?.id === monitorId && !initialize) return opening.session;
    closeMonitor();
    const signal = work.signal;
    const next: Promise<MonitorSession> = api
      .get(monitorId, signal)
      .then((row) =>
        openMonitor({
          row,
          root: root!,
          attest: props.attest ?? attestMonitor,
          intents: intents(),
          initialize,
          signal,
        }),
      )
      .then(
        (opened) => {
          if (opening?.session !== next) {
            opened.close();
            throw new DOMException("Another monitor was opened.", "AbortError");
          }
          opening = undefined;
          setSession(opened);
          return opened;
        },
        (cause) => {
          if (opening?.session === next) opening = undefined;
          throw cause;
        },
      );
    opening = { id: monitorId, session: next };
    return next;
  };
  const open = (row: cp.Container, initialize = false) =>
    act(
      row.id,
      "Opening",
      async (signal) => {
        const { client } = await connect(row.id, initialize);
        setSnapshot(await client.read(signal));
        signal.throwIfAborted();
        routeTo(row.name, true);
        setRoute(row.name);
        setViewing(true);
      },
      () => void open(row, initialize),
    );
  // The sandbox cannot report a blank workspace, so initializing stays the user's call.
  const enroll = (row: cp.Container, initialize = false): Promise<void> =>
    act(
      row.id,
      "Starting",
      async (signal) => {
        const monitorId = cp.attachedMonitor(row)!;
        const monitor = rows().find((r) => r.id === monitorId);
        if (monitor) await cp.follow(api, monitor, "running", signal, update);
        const running = await cp.follow(api, row, "running", signal, update);
        setPending((p) => ({ ...p, [row.id]: "Unlocking" }));
        const { client } = await connect(monitorId);
        await enrollSandbox({
          client,
          row: await api.get(running.id, signal),
          root: root!,
          monitorId,
          intents: intents(),
          initialize,
          signal,
        });
      },
      initialize ? undefined : () => void enroll(row, true),
    );
  const openShell = async (row: cp.Container) => {
    preparing?.abort();
    const op = (preparing = new AbortController());
    const signal = AbortSignal.any([work.signal, op.signal]);
    const name = sandboxIdentity(row.name);
    const show = (state: ShellTarget) => signal.aborted || setShell(state);
    show({ name, message: "Connecting through its monitor…" });
    try {
      if (row.status !== "running")
        throw new Error(`${row.name} is ${row.status}.`);
      if (!sandboxMonitorSSH(row))
        throw new Error(
          "This sandbox uses your SSH key. Connect with the Tinfoil CLI.",
        );
      const { client } = await connect(cp.attachedMonitor(row)!);
      // Setup reinstalls the Monitor credentials and restarts sandbox networking, so
      // opening a shell never repeats it; starting a sandbox enrolls it first.
      show({ name, message: "", client });
    } catch (cause) {
      if (!signal.aborted) show({ name, message: text(cause) });
    }
  };

  const ours = (row: cp.Container) => {
    try {
      return !!ownedMonitor(row, root!);
    } catch {
      return false;
    }
  };
  const mine = (row: cp.Container) => row.clerk_user_id === account()!.id;
  const monitors = () =>
    rows().filter((r) => r.repo === cp.MONITOR_REPO && !r.debug);
  const usable = () => monitors().filter((r) => mine(r) && ours(r));
  const monitorOf = (row: cp.Container) =>
    monitors().find((r) => r.id === cp.attachedMonitor(row));
  const sandboxes = () =>
    rows().filter((r) => r.repo === cp.SANDBOX_REPO && monitorOf(r));
  // The Monitor in the path; with none named and one usable, that one.
  const context = () =>
    route()
      ? monitors().find((r) => r.name === route())
      : usable().length === 1
        ? usable()[0]
        : undefined;
  // A single Monitor claims the bare path, so reloads and links stay on it.
  createEffect(() => {
    const row = context();
    if (!route() && row) {
      routeTo(row.name, true);
      setRoute(row.name);
    }
  });
  const contextSandboxes = () =>
    sandboxes().filter((r) => cp.attachedMonitor(r) === context()?.id);
  // The selected Monitor opens by default; the page outside it covers Monitors this browser cannot open.
  createEffect(() => {
    const row = context();
    if (
      unlocked() &&
      row &&
      !viewing() &&
      mine(row) &&
      ours(row) &&
      row.status === "running" &&
      !pending()[row.id] &&
      !failures()[row.id]
    )
      void open(row);
  });
  const matches = (row: cp.Container) => row.name.includes(query());
  const home = () =>
    batch(() => {
      setViewing(false);
      setMenu(false);
      location.hash = "#agents";
    });

  const navigation = () => (
    <>
      <Show when={!viewing()}>
        <button class="nav-item on" aria-current="page" onClick={home}>
          <Icon name="sandboxes" />
          <span>Sandboxes</span>
          <small class="nav-count">{contextSandboxes().length}</small>
        </button>
      </Show>
      <div class="console-account">
        <Show when={context()}>
          {(row) => (
            <p class="console-account-monitor" title={row().name}>
              <Icon name="rules" />
              {row().name}
              <Show when={viewing() && session()?.verified === false}>
                <small
                  class="console-unverified"
                  title="Local development connection; attestation is disabled."
                >
                  Unverified
                </small>
              </Show>
            </p>
          )}
        </Show>
        <p class="console-account-name" title={account()!.label}>
          {account()!.label}
        </p>
        <button
          class="nav-item"
          title="Require your passkey again"
          onClick={() => lock()}
        >
          Lock
        </button>
        <button
          class="nav-item"
          title="Sign out of your Tinfoil account and require your passkey again"
          onClick={signOut}
        >
          Sign out
        </button>
      </div>
    </>
  );

  const creator = (row: cp.Container) =>
    members()[row.clerk_user_id ?? ""] || "another member of this account";
  const badge = (label: string, tone: string, spinning: boolean) => (
    <span class={`badge ${tone}`} classList={{ "console-busy": spinning }}>
      <Show when={spinning}>
        <Icon name="refresh" />
      </Show>
      {label}
    </span>
  );
  const state = (row: cp.Container) => {
    const [label, tone] = STATES[row.status] ?? [row.status, "status-pending"];
    const acting = pending()[row.id];
    return acting
      ? badge(acting, "status-pending", true)
      : badge(label, tone, tone === "status-pending");
  };
  const controls = (row: cp.Container, owned: boolean) => {
    if (!owned) return;
    const control = (
      icon: string,
      title: string,
      task: (row: cp.Container) => Promise<void>,
      usable: boolean,
    ) => (
      <button
        class="icon-button open-shell"
        aria-label={`${title} ${row.name}`}
        title={title}
        disabled={!usable || !!pending()[row.id]}
        onClick={() => void task(row)}
      >
        <Icon name={icon} />
      </button>
    );
    return ["stopped", "failed"].includes(row.status)
      ? control("play", "Start", start, true)
      : control(
          "stop",
          "Stop",
          stop,
          ["running", "started", "deploying", "pending"].includes(row.status),
        );
  };
  const Alert = (props: { message?: string; children?: JSX.Element }) => (
    <Show when={props.message}>
      <div class="console-alert">
        <p role="alert" class="bad">
          {props.message}
        </p>
        {props.children}
      </div>
    </Show>
  );
  const failure = (row: cp.Container) =>
    failures()[row.id]?.message ??
    (["failed", "stopped"].includes(row.status)
      ? row.last_deploy_attempt_error || row.error_message
      : undefined);
  const Row = (props: {
    row: cp.Container;
    kind: Kind;
    description?: string;
    owned: boolean;
    action?: JSX.Element;
    details?: JSX.Element;
    recovery?: JSX.Element;
  }) => {
    const row = () => props.row;
    return (
      <div class="console-row">
        <ResourceDisclosure
          class="agent-item"
          summary={
            <>
              <Icon name={ICONS[props.kind]} />
              <strong
                class="collection-name"
                classList={{ muted: !mine(row()) }}
                title={row().name}
              >
                {row().name}
              </strong>
              <span class="collection-description">
                {mine(row())
                  ? props.description
                  : `Created by ${creator(row())}`}
              </span>
              <span class="resource-meta">
                {state(row())}
                {controls(row(), props.owned)}
                {props.action}
              </span>
              <span class="collection-chevron">
                <Icon name="arrow" />
              </span>
            </>
          }
        >
          {() => <div class="agent-inline">{props.details}</div>}
        </ResourceDisclosure>
        <Alert message={failure(row())}>{props.recovery}</Alert>
      </div>
    );
  };
  const ownedBox = (box: cp.Container) => {
    const monitor = monitorOf(box)!;
    return mine(box) && mine(monitor) && ours(monitor);
  };
  const ready = (box: cp.Container) =>
    ownedBox(box) && box.status === "running" && !pending()[box.id];
  const shellButton = (box: cp.Container) => (
    <Show when={ownedBox(box) && sandboxMonitorSSH(box)}>
      <button
        class="icon-button open-shell"
        aria-label="Open shell"
        title="Open shell"
        disabled={!ready(box)}
        onClick={() => void openShell(box)}
      >
        <Icon name="integrations" />
      </button>
    </Show>
  );
  const blankRecovery = (box: cp.Container) => (
    <Show when={failures()[box.id]?.recover}>
      <p class="muted">
        If this sandbox's workspace was never set up, initialize it as blank. A
        workspace that holds data is never reformatted.
      </p>
      <button class="link" onClick={failures()[box.id].recover}>
        Initialize a blank workspace
      </button>
    </Show>
  );
  // The opened Monitor's Sandboxes page lists these alongside what it has enrolled.
  const sandboxFor = (name: string) =>
    contextSandboxes().find((r) => sandboxIdentity(r.name) === name);
  const sandboxStatus = (name: string) => (
    <Show when={sandboxFor(name)}>
      {(box) => (
        <>
          {state(box())}
          {controls(box(), ownedBox(box()))}
          {shellButton(box())}
        </>
      )}
    </Show>
  );
  const sandboxActions = (name: string) => (
    <Show when={sandboxFor(name)}>
      {(box) => (
        <div class="console-sandbox-actions">
          {sandboxAccess(box())}
          <Alert message={failure(box())}>{blankRecovery(box())}</Alert>
        </div>
      )}
    </Show>
  );
  const sandboxAccess = (box: cp.Container) => (
    <Show when={!sandboxMonitorSSH(box)}>
      <p class="muted">
        This sandbox uses your SSH key. Run{" "}
        <code>tinfoil attest-ssh --install {box.name}</code> on your computer to
        unlock it, then <code>ssh {box.name}</code> to connect. Its monitor has
        no SSH access.
      </p>
    </Show>
  );
  const sandboxList = () => (
    <Show
      when={contextSandboxes().length || busy()}
      fallback={
        <div class="resource-list">
          <Empty
            icon="sandboxes"
            title="Create your first sandbox"
            action={
              <a
                class="button primary"
                href={DASHBOARD}
                target="_blank"
                rel="noopener noreferrer"
              >
                <Icon name="plus" />
                Create sandbox
                <Icon name="external" />
              </a>
            }
          >
            A sandbox runs your agent in an isolated environment. This monitor
            guards what it can reach and holds its credentials.
          </Empty>
        </div>
      }
    >
      <div class="catalog-toolbar">
        <Search label="Search by name" value={query()} onInput={setQuery} />
      </div>
      <div class="resource-list collection-list">
        <For
          each={contextSandboxes()
            .filter(matches)
            .map((r) => r.id)}
        >
          {(id) => {
            const box = () => rows().find((r) => r.id === id)!;
            return (
              <Row
                row={box()}
                kind="sandbox"
                owned={ownedBox(box())}
                action={shellButton(box())}
                details={sandboxAccess(box())}
                recovery={blankRecovery(box())}
              />
            );
          }}
        </For>
      </div>
    </Show>
  );
  const resources = () => (
    <div id="app" classList={{ "navigation-open": menu() }}>
      <aside id="navigation" aria-label="Console navigation">
        <span class="brand">
          <img
            src={import.meta.env.BASE_URL + "icons/tinfoil-white.svg"}
            alt="Tinfoil"
          />
          <span>Console</span>
        </span>
        <button
          class="mobile-toggle"
          aria-label="Toggle navigation"
          aria-controls="tree"
          aria-expanded={menu()}
          onClick={() => setMenu(!menu())}
        >
          Menu
        </button>
        <nav id="tree" aria-label="Console">
          {navigation()}
        </nav>
      </aside>
      <main id="workspace" tabIndex={-1}>
        <header id="page-header">
          <div class="page-heading">
            <div>
              <h1>Sandboxes</h1>
            </div>
            <div class="header-actions">
              <button
                aria-label="Refresh"
                onClick={() => void run("Refreshing…", refresh)}
                disabled={!!busy()}
              >
                <Icon name="refresh" />
              </button>
              <a
                class="button primary"
                href={DASHBOARD}
                target="_blank"
                rel="noopener noreferrer"
              >
                <Icon name="plus" />
                Create sandbox
                <Icon name="external" />
              </a>
            </div>
          </div>
        </header>
        <div id="page-content">
          <Show when={busy()}>
            <p class="muted">{busy()}</p>
          </Show>
          <Show when={error()}>
            <p role="alert">{error()}</p>
          </Show>
          <Show
            when={context()?.id}
            keyed
            fallback={
              <div class="resource-list">
                <Show
                  when={!route() && monitors().length > 1}
                  fallback={
                    <Empty
                      icon="sandboxes"
                      title={
                        route()
                          ? `No Monitor named ${route()}`
                          : "No sandboxes yet"
                      }
                      action={
                        <a
                          class="button primary"
                          href={DASHBOARD}
                          target="_blank"
                          rel="noopener noreferrer"
                        >
                          <Icon name="plus" />
                          Create sandbox
                          <Icon name="external" />
                        </a>
                      }
                    >
                      A sandbox is an isolated computer for your agent. Create
                      one in the dashboard; your Monitor is set up with it.
                    </Empty>
                  }
                >
                  <div class="collection-list">
                    <For each={monitors()}>
                      {(row) => (
                        <a
                          class="resource-row collection-row"
                          href={`${BASE}/${encodeURIComponent(row.name)}`}
                          onClick={(e) => {
                            e.preventDefault();
                            routeTo(row.name);
                            setRoute(row.name);
                          }}
                        >
                          <Icon name={ICONS.monitor} />
                          <strong
                            class="collection-name"
                            classList={{ muted: !mine(row) }}
                          >
                            {row.name}
                          </strong>
                          <span class="collection-description">
                            {mine(row) ? "" : `Created by ${creator(row)}`}
                          </span>
                          <span class="resource-meta">{state(row)}</span>
                        </a>
                      )}
                    </For>
                  </div>
                </Show>
              </div>
            }
          >
            {(id) => {
              const row = () => rows().find((r) => r.id === id)!;
              return (
                <>
                  <Alert message={failure(row())}>
                    <Show
                      when={failures()[id]?.cause instanceof MissingState}
                      fallback={
                        <Show when={failures()[id]?.recover}>
                          <button class="link" onClick={failures()[id].recover}>
                            Retry
                          </button>
                        </Show>
                      }
                    >
                      <button
                        class="link"
                        onClick={() => void open(row(), true)}
                      >
                        Initialize its encrypted storage
                      </button>
                    </Show>
                  </Alert>
                  {sandboxList()}
                </>
              );
            }}
          </Show>
        </div>
      </main>
    </div>
  );

  return (
    <Show when={account()} fallback={<SignIn clerk={clerk} />}>
      <Show
        when={unlocked()}
        fallback={
          <div id="gate">
            <h1>Unlock your monitors</h1>
            <p>
              A console key protects the monitor and sandbox credentials this
              console uses. It is separate from Tinfoil Chat, and only your
              passkey unlocks it. The first time, this creates the key and its
              passkey.
            </p>
            <p class="muted">
              Your passkey-protected key is saved only in this browser, not
              synced. Clearing this site's data loses access to it.
            </p>
            <Show when={error()}>
              <p role="alert">{error()}</p>
            </Show>
            <div class="console-actions">
              <button
                class="primary"
                disabled={!!busy()}
                onClick={() => void unlock(true)}
              >
                {busy() || "Continue with passkey"}
              </button>
              <button onClick={signOut}>Sign out</button>
            </div>
            <p class="muted">Signed in as {account()!.label}</p>
          </div>
        }
      >
        <ShellSplit shell={shell()} onClose={closeShell}>
          <Show when={viewing() && session()} keyed fallback={resources()}>
            {(s) => (
              <App
                client={s.client}
                brand="Console"
                navigation={navigation}
                snapshot={snapshot()}
                onLock={() => lock()}
                sandboxes={() =>
                  contextSandboxes().map((r) => sandboxIdentity(r.name))
                }
                sandboxStatus={sandboxStatus}
                sandboxActions={sandboxActions}
              />
            )}
          </Show>
        </ShellSplit>
      </Show>
    </Show>
  );
}

function SignIn(props: { clerk: Clerk }) {
  let target!: HTMLDivElement;
  onMount(() =>
    props.clerk.mountSignIn(target, { routing: "hash", withSignUp: true }),
  );
  onCleanup(() => props.clerk.unmountSignIn(target));
  // Clerk replaces the mount node's classes with its own.
  return (
    <div class="console-sign-in">
      <div ref={target} />
    </div>
  );
}
