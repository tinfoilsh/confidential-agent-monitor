import type { PasskeyKeyManager } from "@tinfoilsh/passkey-kit";
import { useParams } from "@solidjs/router";
import {
  Match,
  Show,
  Switch,
  createEffect,
  createSignal,
  on,
  onCleanup,
} from "solid-js";
import App from "../App";
import { Icon, Loading } from "../components";
import { Header } from "./Console";
import * as keys from "./keys";
import { KeyGate } from "./KeyPanel";
import {
  openMonitor,
  type AttestMonitor,
  type OpenedMonitor,
} from "./monitors";
import {
  RestoreRequired,
  acceptSandbox,
  relinkSandboxes,
  sandboxCandidates,
  shellOpener,
} from "./sandboxes";
import { MONITOR_REPO, type Session } from "./session";
import "./console.css";

const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;
export const capture = () => {};

// A Monitor link names only its resource; inventory and saved keys supply the rest.
export default function Monitor(props: {
  session: Session;
  manager?: PasskeyKeyManager;
  attest?: AttestMonitor;
  open?: typeof openMonitor;
}) {
  const manager = props.manager ?? keys.passkeys();
  const id = decodeURIComponent(useParams().id ?? "");
  const [error, setError] = createSignal("");
  const [notice, setNotice] = createSignal("");
  const [busy, setBusy] = createSignal(false);
  const [cancelled, setCancelled] = createSignal(false);
  const [linking, setLinking] = createSignal(false);
  const [session, setSession] = createSignal<OpenedMonitor>();
  let attempt: AbortController | undefined;
  const cancel = () => {
    attempt?.abort();
    attempt = undefined;
    setBusy(false);
  };
  onCleanup(cancel);
  // Keys opened for one user and account never outlive a switch.
  let opening = true;
  createEffect(
    on([() => props.session.user()?.id, props.session.account], () => {
      cancel();
      opening = true;
      setError("");
      setCancelled(false);
      setNotice("");
      setLinking(false);
      if (session() && !session()!.scope.live()) setSession(undefined);
    }),
  );
  const row = () =>
    props.session
      .inventory()
      .value?.find((r) => r.id === id && r.repo === MONITOR_REPO);
  const inventory = () => props.session.inventory();
  const booting = () =>
    ["created", "pending", "deploying", "started"].includes(
      row()?.status ?? "",
    );
  const title = () => {
    if (!UUID.test(id)) return "Choose a Monitor";
    if (!props.session.user()) return "Sign in to open your Monitor";
    const name = row()?.name ?? "your Monitor";
    if (props.session.keyState().error) return "Could not load your keys";
    if (inventory().error) return "Could not load your Monitor";
    if (error()) return `Could not open ${name}`;
    if (cancelled()) return `Open ${name}`;
    if (booting()) return `Starting ${name}…`;
    if (row() && row()!.status !== "running")
      return `${name} is ${row()!.status}`;
    if (props.session.keyState().value && !props.session.unlocked())
      return props.session.keyState().value!.dek_id
        ? `Unlock keys for ${name}`
        : `Set up keys for ${name}`;
    if (inventory().value && !inventory().loading && !row())
      return "Monitor not found";
    return `Opening ${name}…`;
  };
  // Unlocking opens the Monitor once its boot is ready; a failed open needs a retry.
  createEffect(
    on(
      [props.session.unlocked, () => row()?.status, () => inventory().error],
      ([unlocked, status, readError]) => {
        if (
          opening &&
          unlocked &&
          status === "running" &&
          !readError &&
          !session()
        ) {
          opening = false;
          void open();
        }
      },
    ),
  );

  const open = async () => {
    if (busy() || row()?.status !== "running" || inventory().error) return;
    cancel();
    const current = (attempt = new AbortController());
    setBusy(true);
    setError("");
    setCancelled(false);
    try {
      const opened = await (props.open ?? openMonitor)({
        scope: props.session.bind(),
        id,
        signal: current.signal,
        onCheckpoint: (problem) => setNotice(problem ?? ""),
        attest: props.attest,
      });
      if (!current.signal.aborted && opened.scope.live()) {
        document.title = `${opened.row.name} · Monitor`;
        setSession(opened);
        // Restarted sandboxes are re-linked while the Monitor is already showing.
        setLinking(true);
        void relinkSandboxes(opened)
          .then(
            (failures) => {
              if (opened.scope.live() && failures.length)
                setNotice(
                  `Some sandboxes could not be re-linked: ${failures.join("; ")}`,
                );
            },
            (cause) => {
              if (opened.scope.live())
                setNotice(
                  `Sandboxes could not be re-linked: ${cause instanceof Error ? cause.message : cause}`,
                );
            },
          )
          .finally(() => {
            if (opened.scope.live()) setLinking(false);
          });
      }
    } catch (cause) {
      if (!current.signal.aborted)
        setError(
          cause instanceof Error
            ? cause.message
            : "Could not open the monitor.",
        );
      current.abort();
    } finally {
      if (attempt === current) setBusy(false);
    }
  };

  // Restoring a removed sandbox identity is an explicit owner choice.
  const shell = (opened: OpenedMonitor) => (name: string) => {
    const rows = props.session.inventory().value ?? [];
    const opener = shellOpener(opened, rows, name);
    if (!opener) return undefined;
    return (async (size, handlers, signal) => {
      try {
        return await opener(size, handlers, signal);
      } catch (cause) {
        if (
          !(cause instanceof RestoreRequired) ||
          !confirm(
            `${cause.message}\n\nRestore ${name}'s access to this Monitor?`,
          )
        )
          throw cause;
        return shellOpener(opened, rows, name, true)!(size, handlers, signal);
      }
    }) satisfies NonNullable<ReturnType<typeof shellOpener>>;
  };

  return (
    <div class="hosted-monitor">
      <Show
        when={session()}
        keyed
        fallback={
          <div class="start-page monitor-welcome">
            <Header session={props.session} />
            <main class="start-welcome">
              <span class="start-mark">
                <Icon name="rules" />
              </span>
              <div class="monitor-intro">
                <p class="start-eyebrow">Tinfoil Monitor</p>
                <h1>{title()}</h1>
              </div>
              <Show when={error()}>
                <p class="start-notice" role="alert">
                  {error()}
                </p>
              </Show>
              <Show
                when={UUID.test(id) && props.session.user()}
                fallback={
                  <div class="monitor-actions">
                    <Show
                      when={UUID.test(id)}
                      fallback={
                        <a class="button primary" href="/" link>
                          Choose a Monitor
                        </a>
                      }
                    >
                      <button
                        class="primary"
                        onClick={() => void props.session.signIn()}
                      >
                        Sign in
                      </button>
                    </Show>
                  </div>
                }
              >
                <section class="start-monitors" aria-label="Monitor connection">
                  <KeyGate session={props.session} manager={manager}>
                    <Switch>
                      <Match when={inventory().loading && !inventory().value}>
                        <Loading label="Loading your Monitor…" />
                      </Match>
                      <Match when={inventory().error}>
                        <p class="start-notice" role="alert">
                          Could not load your Monitor: {inventory().error}
                        </p>
                        <button
                          class="link"
                          onClick={() => void props.session.refresh()}
                        >
                          Try again
                        </button>
                      </Match>
                      <Match
                        when={
                          inventory().value && !inventory().loading && !row()
                        }
                      >
                        <p class="start-notice" role="alert">
                          This Monitor is not in the selected account. Switch
                          accounts or choose another Monitor.
                        </p>
                      </Match>
                      <Match when={booting()}>
                        <Loading label="Your Monitor will open automatically when it is ready." />
                      </Match>
                      <Match when={row() && row()!.status !== "running"}>
                        <p class="start-help">
                          Open the dashboard to start this Monitor or check its
                          status.
                        </p>
                        <a class="button primary" href={keys.TARGETS.dashboard}>
                          Open dashboard
                        </a>
                      </Match>
                      <Match
                        when={
                          busy() ||
                          (!error() &&
                            !cancelled() &&
                            row()?.status === "running")
                        }
                      >
                        <Loading label="Verifying and connecting to your Monitor…" />
                        <Show when={busy()}>
                          <button
                            class="link"
                            onClick={() => {
                              cancel();
                              setCancelled(true);
                            }}
                          >
                            Cancel
                          </button>
                        </Show>
                      </Match>
                      <Match
                        when={
                          (error() || cancelled()) &&
                          row()?.status === "running"
                        }
                      >
                        <div class="monitor-actions">
                          <button class="primary" onClick={() => void open()}>
                            {error() ? "Try again" : "Open Monitor"}
                          </button>
                        </div>
                      </Match>
                    </Switch>
                  </KeyGate>
                  <Show when={props.session.keyState().error}>
                    <button
                      class="link"
                      onClick={() => void props.session.refresh()}
                    >
                      Try again
                    </button>
                  </Show>
                  <a class="link" href="/" link>
                    Back to your Monitors
                  </a>
                </section>
              </Show>
            </main>
          </div>
        }
      >
        {(opened) => (
          <>
            <Show when={notice()}>
              <p class="start-notice" role="alert">
                {notice()}
              </p>
            </Show>
            <App
              monitorInfo={{
                name: opened.row.name,
                release: opened.row.current_tag,
                cpus: opened.row.cpus,
                memoryMb: opened.row.memory_mb,
                createdAt: opened.row.created_at,
              }}
              terminalHome="/"
              client={opened.client}
              snapshot={opened.snapshot}
              shell={shell(opened)}
              sandboxesLoading={() =>
                linking() || (!!inventory().loading && !inventory().value)
              }
              candidates={() =>
                sandboxCandidates(opened, props.session.inventory().value ?? [])
              }
              accept={(name) =>
                acceptSandbox(
                  opened,
                  props.session.inventory().value ?? [],
                  name,
                )
              }
            />
          </>
        )}
      </Show>
    </div>
  );
}
