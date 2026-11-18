import { useParams } from "@solidjs/router";
import {
  Match,
  Show,
  Switch,
  createEffect,
  createSignal,
  lazy,
  on,
  onCleanup,
} from "solid-js";
import { AuthCard, AuthScreen, Icon, Loading } from "../components";
import type { ShellOpener } from "../owner";
import { openShell } from "./channel";
import { Header } from "./Header";
import * as keys from "./keys";
import { KeyGate } from "./KeyPanel";
import { PRODUCT } from "./product";
import { openBunker, type SandboxClient } from "./sandboxes";
import { SANDBOX_REPO, STARTING, type Session } from "./session";
import "./console.css";

const SandboxTerminal = lazy(() => import("../SandboxTerminal"));

export default function Bunker(props: { session: Session }) {
  document.title = PRODUCT.title;
  const manager = keys.passkeys();
  const id = decodeURIComponent(useParams().id ?? "");
  const [error, setError] = createSignal("");
  const [ready, setReady] = createSignal(false);
  // The first shell uses the page's verification; a reconnect verifies again.
  let verified: SandboxClient | undefined;
  let attempt: AbortController | undefined;
  const cancel = () => attempt?.abort();
  onCleanup(cancel);
  // An open bunker never outlives a switch of user or account.
  let opening = true;
  createEffect(
    on([() => props.session.user()?.id, props.session.account], () => {
      cancel();
      opening = true;
      verified = undefined;
      setError("");
      setReady(false);
    }),
  );
  const inventory = () => props.session.inventory();
  const row = () =>
    inventory().value?.find((r) => r.id === id && r.repo === SANDBOX_REPO);
  const name = () => row()?.name ?? "your bunker";
  const booting = () => STARTING.includes(row()?.status ?? "");
  const title = () => {
    if (!props.session.user()) return "Sign in to open your bunker";
    if (inventory().error) return "Could not load your bunker";
    if (error()) return `Could not open ${name()}`;
    if (booting()) return `Waiting for ${name()} to start…`;
    if (row() && row()!.status !== "running")
      return `${name()} is ${row()!.status}`;
    if (inventory().value && !inventory().loading && !row())
      return "Bunker not found";
    return `Connecting to ${name()}…`;
  };
  createEffect(
    on(
      [props.session.unlocked, () => row()?.status, () => inventory().error],
      ([unlocked, status, readError]) => {
        if (opening && unlocked && status === "running" && !readError) {
          opening = false;
          void open();
        }
      },
    ),
  );

  const open = async () => {
    if (row()?.status !== "running" || inventory().error) return;
    cancel();
    const current = (attempt = new AbortController());
    setError("");
    try {
      const scope = props.session.bind();
      const sandbox = await openBunker(scope, id, current.signal);
      if (!current.signal.aborted && scope.live()) {
        verified = sandbox;
        setReady(true);
      }
    } catch (cause) {
      if (!current.signal.aborted)
        setError(
          cause instanceof Error ? cause.message : "Could not open the bunker.",
        );
      current.abort();
    }
  };
  const shell: ShellOpener = async (size, handlers, signal) => {
    const sandbox =
      verified ?? (await openBunker(props.session.bind(), id, signal));
    verified = undefined;
    return openShell(await sandbox.shell(size, signal), handlers, signal);
  };

  return (
    <Show
      when={ready()}
      fallback={
        <div class="start-page">
          <Header session={props.session} />
          <Show
            when={props.session.user()}
            fallback={
              <AuthScreen title={title()}>
                <AuthCard icon={<Icon name="terminal" />}>
                  <p>Use the account that owns this bunker.</p>
                  <button
                    class="primary"
                    onClick={() => void props.session.signIn()}
                  >
                    Sign in
                  </button>
                </AuthCard>
              </AuthScreen>
            }
          >
            <KeyGate session={props.session} manager={manager}>
              <AuthScreen title={title()}>
                <AuthCard>
                  <Switch
                    fallback={
                      <Loading
                        stacked
                        label="Verifying and unlocking your bunker…"
                      />
                    }
                  >
                    <Match when={inventory().loading && !inventory().value}>
                      <Loading stacked label="Loading your bunker…" />
                    </Match>
                    <Match when={inventory().error}>
                      <p role="alert">
                        Could not load your bunker: {inventory().error}
                      </p>
                      <button
                        class="primary"
                        onClick={() => void props.session.refresh()}
                      >
                        Try again
                      </button>
                    </Match>
                    <Match
                      when={inventory().value && !inventory().loading && !row()}
                    >
                      <p role="alert">
                        This bunker is not in the selected account. Switch
                        accounts or choose another bunker.
                      </p>
                    </Match>
                    <Match when={booting()}>
                      <Loading
                        stacked
                        label="Your bunker will open automatically when it is ready."
                      />
                    </Match>
                    <Match when={row() && row()!.status !== "running"}>
                      <p>
                        Open the dashboard to start this bunker or check its
                        status.
                      </p>
                      <a class="button primary" href={keys.TARGETS.dashboard}>
                        Open dashboard
                      </a>
                    </Match>
                    <Match when={error()}>
                      <p role="alert">{error()}</p>
                      <button class="primary" onClick={() => void open()}>
                        Try again
                      </button>
                    </Match>
                  </Switch>
                </AuthCard>
                <a class="auth-link" href="/" link>
                  Back to home
                </a>
              </AuthScreen>
            </KeyGate>
          </Show>
        </div>
      }
    >
      <div class="app-frame">
        <SandboxTerminal open={shell} name={name()} active />
      </div>
    </Show>
  );
}
