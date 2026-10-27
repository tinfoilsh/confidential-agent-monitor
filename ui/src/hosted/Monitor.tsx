import { Show, createSignal, onCleanup } from "solid-js";
import type { PasskeyKeyManager } from "@tinfoilsh/passkey-kit";
import App from "../App";
import { Icon } from "../components";
import * as keys from "./keys";
import { readMonitorLink, hasMonitorHandoff, type MonitorLink } from "./links";
import {
  MissingState,
  monitorConfig,
  openMonitor,
  type AttestMonitor,
} from "./monitors";
import "./console.css";

export default function Monitor(props: {
  manager?: PasskeyKeyManager;
  attest?: AttestMonitor;
}) {
  const manager = props.manager ?? keys.passkeys();
  const [error, setError] = createSignal("");
  const [busy, setBusy] = createSignal(false);
  const [missing, setMissing] = createSignal(false);
  const [session, setSession] =
    createSignal<Awaited<ReturnType<typeof openMonitor>>>();
  let target: MonitorLink | undefined;
  let local = false;
  let attempt: AbortController | undefined;
  let recovery: File | undefined;
  try {
    target = readMonitorLink(new URL(location.href), sessionStorage);
    monitorConfig(target.config);
    local = keys.keyBundle(target.bundle).type === "local";
    if (hasMonitorHandoff(location.hash))
      history.replaceState(null, "", location.pathname + "#agents");
    document.title = `${target.name} · Monitor`;
  } catch (cause) {
    target = undefined;
    setError(
      cause instanceof Error
        ? cause.message
        : "Could not read the monitor link.",
    );
  }
  const lock = () => {
    attempt?.abort();
    attempt = undefined;
    manager.cancelActiveCeremony();
    manager.clearLocalState();
    setSession(undefined);
    setBusy(false);
  };
  onCleanup(lock);

  const open = async (initialize = false) => {
    if (!target || busy()) return;
    lock();
    const current = new AbortController();
    attempt = current;
    setBusy(true);
    setError("");
    setMissing(false);
    let key: Uint8Array | undefined;
    try {
      const file = recovery;
      if (file && file.size > 16_000)
        throw new Error("This file is too large to be a key bundle.");
      key = await keys.recoverMonitorKey(
        target.bundle,
        manager,
        current.signal,
        await file?.text(),
      );
      const connected = await openMonitor({
        target,
        key,
        signal: current.signal,
        initialize,
        attest: props.attest,
      });
      if (!current.signal.aborted) setSession(connected);
    } catch (cause) {
      if (!current.signal.aborted) {
        setMissing(cause instanceof MissingState);
        setError(
          cause instanceof Error
            ? cause.message
            : "Could not open the monitor.",
        );
      }
      current.abort();
    } finally {
      key?.fill(0);
      if (attempt === current) setBusy(false);
    }
  };

  return (
    <div class="hosted-monitor">
      <header class="start-header">
        <a href={keys.DASHBOARD}>
          <Icon name="arrow" /> Dashboard
        </a>
        <strong>{target?.name ?? "Monitor"}</strong>
        <Show when={session()}>
          <button onClick={lock}>Lock monitor</button>
        </Show>
      </header>
      <Show
        when={session()}
        keyed
        fallback={
          <main class="start-welcome">
            <span class="start-mark">
              <Icon name="rules" />
            </span>
            <h1>{target ? `Open ${target.name}` : "Could not open Monitor"}</h1>
            <Show when={target}>
              <p>
                {local
                  ? "Use the key saved in this browser, or choose your downloaded key bundle."
                  : "Unlock with the passkey you used to create this monitor."}
              </p>
            </Show>
            <Show when={error()}>
              <p class="start-notice" role="alert">
                {error()}
              </p>
            </Show>
            <Show when={target}>
              <Show when={local}>
                <label class="start-help">
                  Saved key bundle
                  <input
                    type="file"
                    accept="application/json,.json"
                    disabled={busy()}
                    onChange={(event) => {
                      recovery = event.currentTarget.files?.[0];
                    }}
                  />
                </label>
              </Show>
              <button
                class="primary"
                disabled={busy()}
                aria-busy={busy()}
                onClick={() => void open(missing())}
              >
                {busy()
                  ? "Opening monitor…"
                  : missing()
                    ? "Initialize monitor"
                    : local
                      ? "Open monitor"
                      : "Unlock with passkey"}
              </button>
              <Show when={busy()}>
                <button onClick={lock}>Cancel</button>
              </Show>
              <p class="start-help">
                Your connection is verified before your monitor is unlocked.
              </p>
            </Show>
            <Show when={!target}>
              <a class="button primary" href={keys.DASHBOARD}>
                Return to dashboard
              </a>
            </Show>
          </main>
        }
      >
        {(connected) => (
          <App
            client={connected.client}
            snapshot={connected.snapshot}
            onLock={lock}
          />
        )}
      </Show>
    </div>
  );
}
