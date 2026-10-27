import type {
  PasskeyCapability,
  PasskeyKeyManager,
} from "@tinfoilsh/passkey-kit";
import {
  Match,
  Show,
  Switch,
  createSignal,
  onCleanup,
  onMount,
} from "solid-js";
import { download, Icon, Modal } from "../components";
import * as keys from "./keys";
import "./console.css";

const starting = () => location.pathname.replace(/\/+$/, "") === "/start";

export default function Console(props: {
  manager?: PasskeyKeyManager;
  navigate?: (url: string) => void;
}) {
  const manager = props.manager ?? keys.passkeys();
  const navigate = props.navigate ?? ((url: string) => location.assign(url));
  const [open, setOpen] = createSignal(starting());
  const [capability, setCapability] =
    createSignal<PasskeyCapability>("unknown");
  const [busy, setBusy] = createSignal(false);
  const [error, setError] = createSignal("");
  const [fallback, setFallback] = createSignal(false);
  const [setup, setSetup] = createSignal<keys.Setup>();
  const [downloaded, setDownloaded] = createSignal(false);
  // The dashboard's one-time state, echoed back so it accepts the result.
  const state = keys.setupState(new URL(location.href));
  const finish = (result: keys.Setup) =>
    navigate(keys.dashboardURL(result, state));
  let ceremony: AbortController | undefined;

  const cancel = () => {
    ceremony?.abort();
    ceremony = undefined;
    manager.cancelActiveCeremony();
    setBusy(false);
  };
  const route = (next: boolean) => {
    if (!next) cancel();
    history.pushState(null, "", next ? "/start" : "/");
    setOpen(next);
  };
  onMount(() => {
    let mounted = true;
    void manager.capability({ operation: "enroll" }).then(
      (value) => mounted && setCapability(value),
      () => {},
    );
    const pop = () => {
      if (!starting()) cancel();
      setOpen(starting());
    };
    window.addEventListener("popstate", pop);
    onCleanup(() => {
      mounted = false;
      window.removeEventListener("popstate", pop);
    });
  });
  onCleanup(cancel);

  const local = async (unavailable = false) => {
    if (busy()) return;
    setError("");
    setFallback(unavailable);
    setDownloaded(false);
    try {
      setSetup(await keys.setupLocal());
    } catch {
      setError("We couldn't create your key. Please reload and try again.");
    }
  };
  const enroll = async () => {
    if (busy()) return;
    if (capability() === "unsupported") return local(true);
    const attempt = new AbortController();
    ceremony = attempt;
    setBusy(true);
    setError("");
    try {
      const result = await keys.setupPasskey(manager, attempt.signal);
      if (!attempt.signal.aborted) {
        setSetup(result);
        finish(result);
      }
    } catch (cause) {
      if (attempt.signal.aborted) return;
      setBusy(false);
      if (keys.unavailablePasskey(cause)) void local(true);
      else setError(keys.passkeyMessage(cause));
    } finally {
      if (ceremony === attempt) {
        ceremony = undefined;
        setBusy(false);
      }
    }
  };

  return (
    <div class="start-page">
      <header class="start-header">
        <a href="/" class="start-brand" aria-label="Tinfoil home">
          <img src="/icons/tinfoil.svg" alt="" />
          <span>Tinfoil</span>
        </a>
        <a href={keys.DASHBOARD}>
          Open dashboard <Icon name="external" />
        </a>
      </header>
      <main class="start-welcome">
        <span class="start-mark">
          <Icon name="sandboxes" />
        </span>
        <h1>Set up a sandbox</h1>
        <p>
          Give your agents a sandbox of their own, with you in control of what
          they can access.
        </p>
        <button class="primary" onClick={() => route(true)}>
          Get started <Icon name="arrow" />
        </button>
      </main>
      <footer class="start-footer">
        <Icon name="rules" /> Privacy by design.
      </footer>

      <Modal
        class="start-dialog"
        open={open()}
        onClose={() => route(false)}
        aria-labelledby="start-title"
        aria-describedby="start-description"
      >
        <button
          class="icon-button start-close"
          aria-label="Close setup"
          onClick={() => route(false)}
        >
          <Icon name="close" />
        </button>
        <div class="start-dialog-body">
          <span class="start-mark">
            <Icon name={setup()?.recovery ? "devices" : "rules"} />
          </span>
          <p class="start-eyebrow">Let's get you started</p>
          <h1 id="start-title">
            {setup()?.recovery
              ? "Keep your key close."
              : setup()
                ? "You're all set."
                : "Welcome to Tinfoil."}
          </h1>
          <Switch
            fallback={
              <>
                <p id="start-description">
                  First, let's set up your key. Then we'll take you to the
                  dashboard to create your sandbox.
                </p>
                <ol class="start-steps" aria-label="Getting started">
                  <li aria-current="step">
                    <span>1</span> Set up your key
                  </li>
                  <li>
                    <span>2</span> Create your sandbox
                  </li>
                </ol>
                <div class="start-key-choice">
                  <Icon
                    name={capability() === "unsupported" ? "devices" : "rules"}
                  />
                  <div>
                    <h2>
                      {capability() === "unsupported"
                        ? "A data key works here"
                        : "A passkey makes it easy"}
                    </h2>
                    <p>
                      {capability() === "unsupported"
                        ? "Passkeys aren't available in this browser. We'll create a data key for you to save instead."
                        : "Use your fingerprint, face, screen lock, or a security key to protect your access."}
                    </p>
                  </div>
                </div>
                <Show when={error()}>
                  <p class="start-notice" role="alert">
                    {error()}
                  </p>
                </Show>
                <button
                  class="primary start-continue"
                  disabled={busy()}
                  aria-busy={busy()}
                  onClick={() => void enroll()}
                >
                  {busy()
                    ? "Follow your device's prompt…"
                    : capability() === "unsupported"
                      ? "Create a data key"
                      : "Create a passkey"}
                  <Show when={!busy()}>
                    <Icon name="arrow" />
                  </Show>
                </button>
                <Show when={capability() !== "unsupported"}>
                  <button
                    class="link start-alternative"
                    disabled={busy()}
                    onClick={() => void local()}
                  >
                    Use a data key instead
                  </button>
                </Show>
                <Show when={busy()}>
                  <p class="start-help" role="status">
                    Your browser may ask you to confirm twice. You can close
                    this dialog to cancel.
                  </p>
                </Show>
              </>
            }
          >
            <Match when={setup()?.recovery}>
              {(recovery) => (
                <>
                  <p id="start-description">
                    {fallback()
                      ? "No passkey? No problem. A data key file gets you started."
                      : "Your data key is ready. Save it before you head to your sandboxes."}
                  </p>
                  <div class="start-key-choice">
                    <Icon name="devices" />
                    <div>
                      <h2>Save your data key somewhere safe</h2>
                      <p>
                        This file is the only way to open your sandboxes: it is
                        not kept anywhere else. Keep it private, anyone with it
                        can access your monitor
                      </p>
                    </div>
                  </div>
                  <button
                    class="start-download"
                    classList={{ primary: !downloaded() }}
                    onClick={() => {
                      download(
                        recovery().text,
                        recovery().filename,
                        "application/x-pem-file",
                      );
                      setDownloaded(true);
                    }}
                  >
                    <Icon name="download" />{" "}
                    {downloaded() ? "Download data key again" : "Save data key"}
                  </button>
                  <Show when={downloaded()}>
                    <p class="start-help" role="status">
                      Keep the downloaded file somewhere you can find it later.
                    </p>
                  </Show>
                  <button
                    class="primary start-continue"
                    disabled={!downloaded()}
                    onClick={() => finish(setup()!)}
                  >
                    Continue to sandboxes <Icon name="arrow" />
                  </button>
                  <p class="start-help">Next stop: your Tinfoil dashboard.</p>
                </>
              )}
            </Match>
            <Match when={setup()}>
              {(ready) => (
                <>
                  <p id="start-description">
                    Your passkey is ready. Let's find a home for your next idea.
                  </p>
                  <p class="start-help" role="status">
                    Opening your Tinfoil dashboard…
                  </p>
                  <a
                    class="button primary start-continue"
                    href={keys.dashboardURL(ready(), state)}
                  >
                    Continue to sandboxes <Icon name="arrow" />
                  </a>
                </>
              )}
            </Match>
          </Switch>
        </div>
      </Modal>
    </div>
  );
}
