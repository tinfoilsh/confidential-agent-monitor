import type { PasskeyKeyManager } from "@tinfoilsh/passkey-kit";
import { useParams } from "@solidjs/router";
import { Show, createEffect, createSignal, on, onCleanup } from "solid-js";
import App from "../App";
import { Icon } from "../components";
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
}) {
  const manager = props.manager ?? keys.passkeys();
  const id = decodeURIComponent(useParams().id ?? "");
  const [error, setError] = createSignal("");
  const [notice, setNotice] = createSignal("");
  const [busy, setBusy] = createSignal(false);
  const [session, setSession] = createSignal<OpenedMonitor>();
  let attempt: AbortController | undefined;
  const cancel = () => {
    attempt?.abort();
    attempt = undefined;
    setBusy(false);
  };
  onCleanup(cancel);
  // Keys opened for one user and account never outlive a switch.
  createEffect(
    on([() => props.session.user()?.id, props.session.account], () => {
      if (session() && !session()!.scope.live()) setSession(undefined);
    }),
  );
  const row = () =>
    props.session
      .inventory()
      .value?.find((r) => r.id === id && r.repo === MONITOR_REPO);
  // Unlocking opens the Monitor; after a failure, opening is the owner's retry.
  let opening = true;
  createEffect(
    on([props.session.unlocked, row], ([unlocked, found]) => {
      if (opening && unlocked && found && !session()) {
        opening = false;
        void open();
      }
    }),
  );

  const open = async () => {
    if (busy()) return;
    cancel();
    const current = (attempt = new AbortController());
    setBusy(true);
    setError("");
    try {
      const opened = await openMonitor({
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
        void relinkSandboxes(opened).then(
          (failures) =>
            failures.length &&
            setNotice(
              `Some sandboxes could not be re-linked: ${failures.join("; ")}`,
            ),
          (cause) =>
            setNotice(
              `Sandboxes could not be re-linked: ${cause instanceof Error ? cause.message : cause}`,
            ),
        );
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
                <h1>
                  {row() ? `Welcome to ${row()!.name}` : "Open your Monitor"}
                </h1>
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
                <section class="start-monitors" aria-label="Your keys">
                  <KeyGate session={props.session} manager={manager}>
                    <Show when={props.session.inventory().value && !row()}>
                      <p class="start-notice" role="alert">
                        This Monitor is not in the selected account. Switch
                        accounts or choose another Monitor.
                      </p>
                    </Show>
                    <div class="monitor-actions">
                      <button
                        class="primary"
                        disabled={busy() || !row()}
                        aria-busy={busy()}
                        onClick={() => void open()}
                      >
                        {busy() ? "Verifying and opening…" : "Open Monitor"}
                      </button>
                      <Show when={busy()}>
                        <button class="link" onClick={cancel}>
                          Cancel
                        </button>
                      </Show>
                    </div>
                  </KeyGate>
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
              client={opened.client}
              snapshot={opened.snapshot}
              shell={shell(opened)}
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
