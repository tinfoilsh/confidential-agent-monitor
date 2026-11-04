import { For, Show, createMemo, createSignal, onCleanup } from "solid-js";
import App from "../monitor/App";
import { Icon } from "../monitor/components";
import { ShellSplit, type ShellTarget } from "./ShellSplit";
import type { ShellOpener } from "../monitor/owner";
import type { OpenedMonitor } from "./connection";
import {
  RestoreRequired,
  acceptSandbox,
  sandboxCandidates,
  shellOpener,
} from "./sandboxes";
import type { Session } from "./session";
import "./workspace.css";

// Trusted Terminal chrome. Account and sandbox capabilities stay here; the
// shared Monitor app receives only its owner API connection and initial state.
export default function MonitorWorkspace(props: {
  monitor: OpenedMonitor;
  session: Session;
  linking: boolean;
  notice: string;
}) {
  const lifetime = new AbortController();
  const signal = AbortSignal.any([lifetime.signal, props.monitor.scope.signal]);
  const live = () => !signal.aborted && props.monitor.scope.live();
  const [selected, setSelected] = createSignal("");
  const [shell, setShell] = createSignal<ShellTarget>();
  const [busy, setBusy] = createSignal(false);
  const [error, setError] = createSignal("");
  const [message, setMessage] = createSignal("");
  const [apiKey, setApiKey] = createSignal("");
  const [creatingKey, setCreatingKey] = createSignal(false);
  const [copied, setCopied] = createSignal(false);
  const clearSecrets = () => {
    setApiKey("");
    setCopied(false);
    setShell(undefined);
  };
  signal.addEventListener("abort", clearSecrets, { once: true });
  onCleanup(() => {
    lifetime.abort();
    signal.removeEventListener("abort", clearSecrets);
    clearSecrets();
  });
  const inventory = () => props.session.inventory();
  const rows = () => inventory().value ?? [];
  const problem = () =>
    error() ||
    props.notice ||
    (inventory().error ? `Could not load sandboxes: ${inventory().error}` : "");
  const candidates = createMemo(() => sandboxCandidates(props.monitor, rows()));
  // Selection is always resolved against Terminal's own inventory and saved
  // keys, never names or capabilities supplied by the Monitor response.
  const name = () =>
    candidates().some((row) => row.name === selected())
      ? selected()
      : (candidates()[0]?.name ?? "");
  const unavailable = () =>
    busy() || props.linking || !name() || !!inventory().error;
  const report = (cause: unknown) => {
    if (live())
      setError(cause instanceof Error ? cause.message : String(cause));
  };
  const restore = (cause: unknown, sandbox: string) =>
    live() &&
    cause instanceof RestoreRequired &&
    confirm(`${cause.message}\n\nRestore ${sandbox}'s access to this Monitor?`);

  const enroll = async () => {
    if (!live() || unavailable()) return;
    const sandbox = name();
    setBusy(true);
    setError("");
    setMessage("");
    try {
      try {
        await acceptSandbox(props.monitor, rows(), sandbox, false, signal);
      } catch (cause) {
        if (!restore(cause, sandbox)) throw cause;
        await acceptSandbox(props.monitor, rows(), sandbox, true, signal);
      }
      if (live())
        setMessage(
          `${sandbox} is connected. Monitor will refresh automatically.`,
        );
    } catch (cause) {
      report(cause);
    } finally {
      if (live()) setBusy(false);
    }
  };
  const openShell = () => {
    if (!live() || unavailable()) return;
    const sandbox = name();
    if (shell()?.name === sandbox) return;
    const opener = shellOpener(props.monitor, rows(), sandbox);
    if (!opener) return;
    const open: ShellOpener = async (size, handlers, at) => {
      const sessionSignal = AbortSignal.any([signal, at]);
      try {
        return await opener(size, handlers, sessionSignal);
      } catch (cause) {
        if (!restore(cause, sandbox)) throw cause;
        const retry = shellOpener(props.monitor, rows(), sandbox, true);
        if (!retry) throw new Error("This sandbox is no longer available.");
        return retry(size, handlers, sessionSignal);
      }
    };
    setShell({ name: sandbox, open });
  };
  const createKey = async () => {
    if (!live() || creatingKey() || apiKey()) return;
    setCreatingKey(true);
    setError("");
    try {
      const { key } = (await props.monitor.scope.api("/api/keys/", {
        method: "POST",
        body: { name: props.monitor.row.name },
        signal,
      })) as { key: string };
      if (live()) setApiKey(key);
    } catch (cause) {
      report(cause);
    } finally {
      if (live()) setCreatingKey(false);
    }
  };
  const copyKey = async () => {
    if (!live() || !apiKey()) return;
    try {
      await navigator.clipboard.writeText(apiKey());
      if (live()) setCopied(true);
    } catch (cause) {
      report(cause);
    }
  };

  return (
    <div class="monitor-host">
      <header class="monitor-bezel" aria-label="Terminal controls">
        <a href="/" link title="Back to your Monitors">
          <Icon name="arrow" />
          <span>Terminal</span>
        </a>
        <strong class="monitor-host-name" title={props.monitor.row.name}>
          {props.monitor.row.name}
        </strong>
        <span class="monitor-host-status" role="status">
          {props.linking ? "Reconnecting sandboxes…" : "Connected"}
        </span>
        <div class="monitor-host-actions">
          <Show
            when={candidates().length}
            fallback={
              <Show
                when={!inventory().loading && !inventory().error}
                fallback={
                  <span role="status">
                    {inventory().loading
                      ? "Loading sandboxes…"
                      : "Sandboxes unavailable"}
                  </span>
                }
              >
                <a
                  class="button"
                  href="https://dash.tinfoil.sh/?tab=sandboxes"
                  target="_blank"
                  rel="noopener noreferrer"
                >
                  Create sandbox
                </a>
              </Show>
            }
          >
            <select
              aria-label="Sandbox"
              value={name()}
              onChange={(event) => setSelected(event.currentTarget.value)}
            >
              <For each={candidates()}>
                {(row) => <option value={row.name}>{row.name}</option>}
              </For>
            </select>
            <button
              disabled={unavailable()}
              onClick={() => void enroll()}
              title="Enroll this sandbox if needed and unlock its workspace"
            >
              {busy() ? "Connecting…" : "Connect sandbox"}
            </button>
            <button
              disabled={unavailable()}
              onClick={openShell}
              title="Connect this sandbox and open its shell"
            >
              <Icon name="integrations" />
              Open shell
            </button>
          </Show>
          <details class="monitor-host-keys">
            <summary>API key</summary>
            <div class="monitor-host-key-panel">
              <p>
                Create an API key for this account. It is not sent to Monitor
                automatically.
              </p>
              <Show
                when={apiKey()}
                fallback={
                  <button
                    disabled={creatingKey()}
                    onClick={() => void createKey()}
                  >
                    {creatingKey() ? "Creating…" : "Create API key"}
                  </button>
                }
              >
                <label>
                  New API key
                  <input
                    aria-label="New API key"
                    type="password"
                    readonly
                    value={apiKey()}
                    onFocus={(event) => event.currentTarget.select()}
                  />
                </label>
                <button onClick={() => void copyKey()}>
                  {copied() ? "Copied" : "Copy key"}
                </button>
                <p>
                  Paste it into Monitor setup only if you want to give this
                  Monitor access.
                </p>
              </Show>
            </div>
          </details>
        </div>
      </header>
      <Show when={problem()}>
        <p class="monitor-host-notice" role="alert">
          {problem()}
          <Show when={inventory().error}>
            <button onClick={() => void props.session.refresh()}>Retry</button>
          </Show>
        </p>
      </Show>
      <Show when={message()}>
        <p class="monitor-host-notice" role="status">
          {message()}
        </p>
      </Show>
      <div class="monitor-host-workspace">
        <ShellSplit shell={shell()} onClose={() => setShell(undefined)}>
          <div class="monitor-host-app">
            <App
              connection={{
                client: props.monitor.client,
                snapshot: props.monitor.snapshot,
              }}
            />
          </div>
        </ShellSplit>
      </div>
    </div>
  );
}
