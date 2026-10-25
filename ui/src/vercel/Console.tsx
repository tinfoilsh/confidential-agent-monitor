import type { Clerk } from "@clerk/clerk-js/no-rhc";
import type { PasskeyKeyManager, PasskeyUser } from "@tinfoilsh/passkey-kit";
import {
  For,
  Show,
  batch,
  createEffect,
  createMemo,
  createSignal,
  onCleanup,
  onMount,
  type JSX,
} from "solid-js";
import App, { Onboarding } from "../App";
import {
  Empty,
  Icon,
  Modal,
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
  createMonitor,
  createSandbox,
  enrollSandbox,
  initIntents,
  openMonitor,
  ownedMonitor,
  sandboxIdentity,
  type AttestMonitor,
  type MonitorSession,
  type SandboxRequest,
} from "./monitors";
import "./console.css";

// Connection sign-in returns to this page; reopen the Monitor that started it.
const REOPEN = "tinfoil-monitor-reopen";
const NAME = /^[a-z0-9]+(-[a-z0-9]+)*$/;
const BYTES_PER_GB = 1e9;
const MEMBERS_PAGE_SIZE = 100;

type Account = { id: string; label: string; user: PasskeyUser };
type Failure = { message: string; cause: unknown; recover?: () => void };
type Kind = "monitor" | "sandbox";
type Adding = { kind: "monitor" } | { kind: "sandbox"; monitor?: string };
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
  const [selected, setSelected] = createSignal(
    sessionStorage.getItem(REOPEN) ?? undefined,
  );
  const [viewing, setViewing] = createSignal(false);
  const [adding, setAdding] = createSignal<Adding>();
  // Keep the last form mounted through the dialog's exit transition.
  const shown = createMemo<Adding | undefined>((last) => adding() ?? last);
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
    sessionStorage.removeItem(REOPEN);
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
      setAdding(undefined);
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
  const addPasskey = () =>
    run("Waiting for your passkey…", () => {
      const signal = work.signal;
      return settle(
        signal,
        manager!,
        keys.addPasskey({
          store: keys.keyStore(account()!.id),
          manager: manager!,
          user: account()!.user,
          key: accountKey!,
          signal,
        }),
      );
    });
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
  const add = (row: cp.Container) =>
    setRows((list) => [...list.filter((r) => r.id !== row.id), row]);
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
    if (!signal.aborted && row.repo === cp.SANDBOX_REPO && !failures()[row.id])
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
  // Resolves with the new Monitor as soon as it exists; it keeps booting and onboarding in its row.
  const create = (name: string, tinfoilApiKey?: string) =>
    new Promise<cp.Container | undefined>((done) => {
      void act(
        `new:monitor:${name}`,
        "Creating",
        async (signal) => {
          const row = await createMonitor({
            api,
            root: root!,
            name,
            tag: await api.latestTag(cp.MONITOR_REPO, signal),
            intents: intents(),
            signal,
          });
          signal.throwIfAborted();
          add(row);
          done(row);
          void act(row.id, "Starting", async (signal) => {
            await cp.follow(api, row, "running", signal, update);
            setPending((p) => ({ ...p, [row.id]: "Setting up" }));
            const { client } = await connect(row.id);
            const { view } = await client.read(signal);
            await client.onboard(view, "known_only", signal, {
              allowPaidInference: true,
              tinfoilApiKey,
            });
          });
        },
        () => void create(name, tinfoilApiKey),
      ).finally(() => done(undefined));
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
        sessionStorage.setItem(REOPEN, row.id);
        setSelected(row.id);
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
  // A retry reuses the request, so after a lost reply it targets the same sandbox.
  const createBox = (
    request: SandboxRequest,
    monitorId: string,
  ): Promise<void> =>
    act(
      `new:sandbox:${request.name}`,
      "Creating",
      async (signal) => {
        const row = await createSandbox({
          api,
          root: root!,
          monitorId,
          tag: await api.latestTag(cp.SANDBOX_REPO, signal),
          request,
          intents: intents(),
          signal,
        });
        signal.throwIfAborted();
        add(row);
        void enroll(row);
      },
      () => void createBox(request, monitorId),
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
      const { client } = await connect(cp.attachedMonitor(row)!);
      // Setup reinstalls the Monitor credentials and restarts sandbox networking, so
      // opening a shell never repeats it; after a reboot, use Unlock.
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
  const context = () =>
    monitors().find((r) => r.id === selected()) ?? usable()[0] ?? monitors()[0];
  const sandboxCount = (monitorId: string) => {
    const n = sandboxes().filter(
      (r) => cp.attachedMonitor(r) === monitorId,
    ).length;
    return `${n} ${n === 1 ? "sandbox" : "sandboxes"}`;
  };
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
  const drafts = (kind: Kind) =>
    [...Object.keys(pending()), ...Object.keys(failures())].filter((id) =>
      id.startsWith(`new:${kind}:`),
    );
  const newSandbox = (monitor?: string) =>
    setAdding(
      usable().length ? { kind: "sandbox", monitor } : { kind: "monitor" },
    );
  const addMonitor = async (name: string, tinfoilApiKey?: string) => {
    setAdding(undefined);
    const row = await create(name, tinfoilApiKey);
    if (row) setSelected(row.id);
  };
  const home = () =>
    batch(() => {
      setViewing(false);
      setMenu(false);
      sessionStorage.removeItem(REOPEN);
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
      <details class="console-account">
        <summary>{account()!.label}</summary>
        <button class="nav-item" onClick={addPasskey} disabled={!!busy()}>
          Add passkey
        </button>
        <button class="nav-item" onClick={() => lock()}>
          Lock
        </button>
        <button class="nav-item" onClick={signOut}>
          Sign out
        </button>
      </details>
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
  const foreignKey = (row: cp.Container) => (
    <Show when={mine(row) && !ours(row)}>
      <dl class="request-context">
        <div>
          <dt>Owner key</dt>
          <dd>
            Created with a different owner key. Open it with{" "}
            <code>tinfoil monitor open {row.name}</code>.
          </dd>
        </div>
      </dl>
    </Show>
  );

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
  const draftName = (id: string) => id.split(":")[2];
  const draftBadge = (id: string) =>
    failures()[id]
      ? badge("Failed", "status-denied", false)
      : badge(pending()[id], "status-pending", true);
  const draftAlert = (id: string) => (
    <Alert message={failures()[id]?.message}>
      <button class="link" onClick={failures()[id].recover}>
        Retry
      </button>
    </Alert>
  );
  const Draft = (props: { id: string; kind: Kind }) => (
    <div class="console-row">
      <div class="resource-row collection-row">
        <Icon name={ICONS[props.kind]} />
        <strong class="collection-name">{draftName(props.id)}</strong>
        <span class="resource-meta">{draftBadge(props.id)}</span>
      </div>
      {draftAlert(props.id)}
    </div>
  );
  const ownedBox = (box: cp.Container) => {
    const monitor = monitorOf(box)!;
    return mine(box) && mine(monitor) && ours(monitor);
  };
  const ready = (box: cp.Container) =>
    ownedBox(box) && box.status === "running" && !pending()[box.id];
  const shellButton = (box: cp.Container) => (
    <Show when={ownedBox(box)}>
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
  const draftFor = (name: string) =>
    drafts("sandbox").find((id) => sandboxIdentity(draftName(id)) === name);
  const sandboxStatus = (name: string) => (
    <Show
      when={sandboxFor(name)}
      fallback={<Show when={draftFor(name)}>{(id) => draftBadge(id())}</Show>}
    >
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
    <Show
      when={sandboxFor(name)}
      fallback={<Show when={draftFor(name)}>{(id) => draftAlert(id())}</Show>}
    >
      {(box) => (
        <div class="console-sandbox-actions">
          <Alert message={failure(box())}>{blankRecovery(box())}</Alert>
        </div>
      )}
    </Show>
  );
  const sandboxList = () => (
    <Show
      when={contextSandboxes().length || busy() || drafts("sandbox").length}
      fallback={
        <div class="resource-list">
          <Empty
            icon="sandboxes"
            title="Create your first sandbox"
            action={
              <button class="primary" onClick={() => newSandbox(context()!.id)}>
                <Icon name="plus" />
                Create sandbox
              </button>
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
                recovery={blankRecovery(box())}
              />
            );
          }}
        </For>
        <For each={drafts("sandbox")}>
          {(id) => <Draft id={id} kind="sandbox" />}
        </For>
      </div>
    </Show>
  );
  const monitorCard = (id: string) => {
    const row = () => rows().find((r) => r.id === id)!;
    const owned = () => mine(row()) && ours(row());
    return (
      <div class="resource-list collection-list console-context-card">
        <Row
          row={row()}
          kind="monitor"
          description={sandboxCount(id)}
          owned={owned()}
          action={
            <Show when={viewing() && session()?.verified === false}>
              <small
                class="console-unverified"
                title="This browser cannot attest monitors yet. Traffic is sealed and signed, but the monitor's identity is not checked."
              >
                Unverified
              </small>
            </Show>
          }
          details={
            <>
              {foreignKey(row())}
              <div class="console-monitors">
                <For each={monitors().filter((r) => r.id !== id)}>
                  {(other) => (
                    <button
                      class="resource-row collection-row"
                      onClick={() => {
                        setSelected(other.id);
                        home();
                      }}
                    >
                      <Icon name={ICONS.monitor} />
                      <strong
                        class="collection-name"
                        classList={{ muted: !mine(other) }}
                      >
                        {other.name}
                      </strong>
                      <span class="collection-description">
                        {mine(other)
                          ? sandboxCount(other.id)
                          : `Created by ${creator(other)}`}
                      </span>
                      <span class="resource-meta">{state(other)}</span>
                    </button>
                  )}
                </For>
                <button
                  class="resource-row collection-row"
                  onClick={() => setAdding({ kind: "monitor" })}
                >
                  <Icon name="plus" />
                  New monitor
                </button>
              </div>
            </>
          }
          recovery={
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
              <button class="link" onClick={() => void open(row(), true)}>
                Initialize its encrypted storage
              </button>
            </Show>
          }
        />
      </div>
    );
  };

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
              <p>
                Isolated environments for your agents, each guarded by a
                monitor.
              </p>
            </div>
            <div class="header-actions">
              <button
                aria-label="Refresh"
                onClick={() => void run("Refreshing…", refresh)}
                disabled={!!busy()}
              >
                <Icon name="refresh" />
              </button>
              <button class="primary" onClick={() => newSandbox(context()?.id)}>
                <Icon name="plus" />
                Create sandbox
              </button>
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
              <Show when={!drafts("monitor").length}>
                <div class="resource-list">
                  <Empty
                    icon="sandboxes"
                    title="Create your first sandbox"
                    action={
                      <button
                        class="primary"
                        onClick={() => setAdding({ kind: "monitor" })}
                      >
                        <Icon name="plus" />
                        Create sandbox
                      </button>
                    }
                  >
                    A sandbox is an isolated computer for your agent. You will
                    set up its monitor first.
                  </Empty>
                </div>
              </Show>
            }
          >
            {(id) => (
              <>
                {monitorCard(id)}
                {sandboxList()}
              </>
            )}
          </Show>
          <For each={drafts("monitor")}>
            {(id) => (
              <div class="resource-list collection-list console-context-card">
                <Draft id={id} kind="monitor" />
              </div>
            )}
          </For>
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
                context={() => monitorCard(s.row.id)}
                snapshot={snapshot()}
                onLock={() => lock()}
                onAddSandbox={() => newSandbox(s.row.id)}
                sandboxes={() => [
                  ...contextSandboxes().map((r) => sandboxIdentity(r.name)),
                  ...drafts("sandbox").map((id) =>
                    sandboxIdentity(draftName(id)),
                  ),
                ]}
                sandboxStatus={sandboxStatus}
                sandboxActions={sandboxActions}
              />
            )}
          </Show>
        </ShellSplit>
        <Modal
          class="console-dialog"
          classList={{ "console-onboarding": shown()?.kind === "monitor" }}
          open={!!adding()}
          onClose={() => setAdding(undefined)}
        >
          <Show when={shown()} keyed>
            {(current) =>
              current.kind === "monitor" ? (
                <NewMonitor
                  onCreate={(name, key) => void addMonitor(name, key)}
                  onClose={() => setAdding(undefined)}
                />
              ) : (
                <NewSandbox
                  api={api}
                  monitors={usable()}
                  monitor={current.monitor}
                  onCreate={(request, monitorId) => {
                    setAdding(undefined);
                    setSelected(monitorId);
                    home();
                    void createBox(request, monitorId);
                  }}
                  onNewMonitor={() => setAdding({ kind: "monitor" })}
                  onClose={() => setAdding(undefined)}
                />
              )
            }
          </Show>
        </Modal>
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

function NewMonitor(props: {
  onCreate(name: string, tinfoilApiKey?: string): void;
  onClose(): void;
}) {
  const [name, setName] = createSignal("");
  return (
    <>
      <button
        type="button"
        class="dialog-close icon-button"
        aria-label="Close dialog"
        onClick={props.onClose}
      >
        <Icon name="close" />
      </button>
      <Onboarding busy={false} onFinish={(key) => props.onCreate(name(), key)}>
        <fieldset class="onboarding-key">
          <label for="monitor-name">Monitor name</label>
          <input
            id="monitor-name"
            value={name()}
            onInput={(event) => setName(event.currentTarget.value.trim())}
            placeholder="my-monitor"
            pattern={NAME.source}
            required
            autofocus
          />
        </fieldset>
      </Onboarding>
    </>
  );
}

function NewSandbox(props: {
  api: cp.Controlplane;
  monitors: cp.Container[];
  monitor?: string;
  onCreate(request: SandboxRequest, monitorId: string): void;
  onNewMonitor(): void;
  onClose(): void;
}) {
  const [name, setName] = createSignal("");
  const [monitor, setMonitor] = createSignal(
    props.monitor ?? props.monitors[0]?.id ?? "",
  );
  const [workspace, setWorkspace] = createSignal("");
  const [volumes, setVolumes] = createSignal<cp.Volume[]>([]);
  const [error, setError] = createSignal("");
  const closed = new AbortController();
  onCleanup(() => closed.abort());
  onMount(() =>
    props.api.volumes(closed.signal).then(
      (all) => setVolumes(all.filter((v) => !v.container_id)),
      (cause) => closed.signal.aborted || setError(text(cause)),
    ),
  );
  return (
    <>
      <DialogHeader
        icon="sandboxes"
        title="Create sandbox"
        onClose={props.onClose}
      />
      <form
        class="dialog-body form-fields"
        onSubmit={(event) => {
          event.preventDefault();
          props.onCreate(
            {
              name: name(),
              workspace: workspace() || undefined,
              instanceId: crypto.randomUUID(),
            },
            monitor(),
          );
        }}
      >
        <label>
          Sandbox name
          <input
            value={name()}
            onInput={(event) => setName(event.currentTarget.value.trim())}
            placeholder="my-sandbox"
            pattern={NAME.source}
            required
            autofocus
          />
        </label>
        <label>
          Monitor
          <select
            value={monitor()}
            onChange={(event) => setMonitor(event.currentTarget.value)}
          >
            <For each={props.monitors}>
              {(row) => (
                <option value={row.id}>
                  {row.name}
                  {row.status === "running" ? "" : ` (${row.status})`}
                </option>
              )}
            </For>
          </select>
        </label>
        <button type="button" class="link" onClick={props.onNewMonitor}>
          Create a new monitor instead
        </button>
        <label>
          Workspace
          <select
            value={workspace()}
            onChange={(event) => setWorkspace(event.currentTarget.value)}
          >
            <option value="">New encrypted workspace</option>
            <For each={volumes()}>
              {(volume) => (
                <option value={volume.id}>
                  {volume.name} ({Math.round(volume.size_bytes / BYTES_PER_GB)}{" "}
                  GB)
                </option>
              )}
            </For>
          </select>
        </label>
        <Show when={workspace()}>
          <p class="muted">
            A reused workspace opens only with the key this console derived for
            it.
          </p>
        </Show>
        <Show when={error()}>
          <p role="alert">{error()}</p>
        </Show>
        <div class="console-actions">
          <button class="primary" disabled={!NAME.test(name()) || !monitor()}>
            Create sandbox
          </button>
        </div>
      </form>
    </>
  );
}

function DialogHeader(props: {
  icon: string;
  title: string;
  onClose(): void;
  children?: JSX.Element;
}) {
  return (
    <header class="dialog-header">
      <Icon name={props.icon} />
      <div>
        <h1>{props.title}</h1>
        <Show when={props.children}>
          <p>{props.children}</p>
        </Show>
      </div>
      <button
        type="button"
        class="dialog-close icon-button"
        aria-label="Close dialog"
        onClick={props.onClose}
      >
        <Icon name="close" />
      </button>
    </header>
  );
}
