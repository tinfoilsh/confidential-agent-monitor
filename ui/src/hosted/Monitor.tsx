import { Show, createSignal, onCleanup } from "solid-js";
import type { PasskeyKeyManager } from "@tinfoilsh/passkey-kit";
import App from "../App";
import { Icon } from "../components";
import * as keys from "./keys";
import { readMonitorLink, hasMonitorHandoff, type MonitorLink } from "./links";
import { monitorConfig, openMonitor, type AttestMonitor } from "./monitors";
import "./console.css";

export default function Monitor(props: {
  manager?: PasskeyKeyManager;
  attest?: AttestMonitor;
}) {
  const manager = props.manager ?? keys.passkeys();
  const [error, setError] = createSignal("");
  const [busy, setBusy] = createSignal(false);
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
  const cancel = () => {
    attempt?.abort();
    attempt = undefined;
    manager.cancelActiveCeremony();
    manager.clearLocalState();
    setBusy(false);
  };
  onCleanup(cancel);

  const open = async () => {
    if (!target || busy()) return;
    cancel();
    const current = new AbortController();
    attempt = current;
    setBusy(true);
    setError("");
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
        attest: props.attest,
      });
      if (!current.signal.aborted) setSession(connected);
    } catch (cause) {
      if (!current.signal.aborted) {
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
      <Show
        when={session()}
        keyed
        fallback={
          <div class="start-page monitor-welcome">
            <main class="start-welcome">
              <span class="start-mark">
                <Icon name="rules" />
              </span>
              <div class="monitor-intro">
                <p class="start-eyebrow">Tinfoil Monitor</p>
                <h1>
                  {target
                    ? `Welcome to ${target.name}`
                    : "Could not open Monitor"}
                </h1>
                <Show when={target}>
                  <p class="monitor-description">
                    {local
                      ? "Use the key saved in this browser, or choose your downloaded key bundle."
                      : "Sign in with the passkey you used to create this monitor."}
                  </p>
                </Show>
              </div>
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
              </Show>
              <div class="monitor-actions">
                <Show
                  when={target}
                  fallback={
                    <a class="button primary" href={keys.DASHBOARD}>
                      Return to dashboard
                    </a>
                  }
                >
                  <button
                    class="primary"
                    disabled={busy()}
                    aria-busy={busy()}
                    onClick={() => void open()}
                  >
                    {busy()
                      ? "Opening monitor…"
                      : local
                        ? "Open monitor"
                        : "Continue with passkey"}
                  </button>
                  <Show when={busy()}>
                    <button class="link" onClick={cancel}>
                      Cancel
                    </button>
                  </Show>
                </Show>
              </div>
            </main>
          </div>
        }
      >
        {(connected) => (
          <App client={connected.client} snapshot={connected.snapshot} />
        )}
      </Show>
    </div>
  );
}
