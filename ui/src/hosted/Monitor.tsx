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
import { AuthCard, AuthScreen, Icon, Loading, askConfirm } from "../components";
import type { TinfoilApiKey } from "../monitor";
import { UUID } from "./contract";
import { Header, openedFromHome } from "./Header";
import * as keys from "./keys";
import { KeyGate } from "./KeyPanel";
import { openMonitor, type OpenedMonitor } from "./monitors";
import { PRODUCT } from "./product";
import {
  RestoreRequired,
  acceptSandbox,
  relinkSandboxes,
  sandboxCandidates,
  shellOpener,
} from "./sandboxes";
import { MONITOR_REPO, STARTING, type Session } from "./session";
import "./console.css";

// A Monitor link names only its resource; inventory and saved keys supply the rest.
// The signed-in user's own inference keys that still work. In an organization,
// other members' keys are listed masked and are left out.
function usableApiKeys(value: unknown): TinfoilApiKey[] {
  if (!Array.isArray(value))
    throw new Error("Your API keys could not be read.");
  return value.flatMap((row) =>
    typeof row?.key === "string" &&
    !row.chat &&
    !row.disabled &&
    !row.is_admin &&
    row.is_owner !== false &&
    !(
      typeof row.expires_at === "string" &&
      Date.parse(row.expires_at) <= Date.now()
    )
      ? [{ key: row.key, name: typeof row.name === "string" ? row.name : "" }]
      : [],
  );
}

export default function Monitor(props: { session: Session }) {
  document.title = PRODUCT.title;
  const manager = keys.passkeys();
  const id = decodeURIComponent(useParams().id ?? "");
  // An OAuth sign-in returns without the marker, then restores it in the URL.
  const [fromHome, setFromHome] = createSignal(openedFromHome());
  const restored = () => setFromHome(openedFromHome());
  addEventListener("hashchange", restored);
  onCleanup(() => removeEventListener("hashchange", restored));
  const back = () => (fromHome() ? "/" : keys.TARGETS.dashboard);
  const bunker = /^#agents\/([^/]+)/.exec(location.hash)?.[1];
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
  const booting = () => STARTING.includes(row()?.status ?? "");
  const title = () => {
    if (!UUID.test(id)) return "Choose a Perimeter";
    if (!props.session.user()) return "Sign in to open your Perimeter";
    const name = row()?.name ?? "your Perimeter";
    if (props.session.keyState().error) return "Could not load your keys";
    if (inventory().error) return "Could not load your Perimeter";
    if (error()) return `Could not open ${name}`;
    if (cancelled()) return `Open ${name}`;
    if (booting()) return `Waiting for ${name} to start…`;
    if (row() && row()!.status !== "running")
      return `${name} is ${row()!.status}`;
    if (inventory().value && !inventory().loading && !row())
      return "Perimeter not found";
    return "Connecting to bunker…";
  };
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
      const opened = await openMonitor({
        scope: props.session.bind(),
        id,
        signal: current.signal,
        onCheckpoint: (problem) => setNotice(problem ?? ""),
      });
      if (!current.signal.aborted && opened.scope.live()) {
        setSession(opened);
        setLinking(true);
        void relinkSandboxes(opened)
          .then(
            (failures) => {
              if (opened.scope.live() && failures.length)
                setNotice(
                  `Some bunkers could not be re-linked: ${failures.join("; ")}`,
                );
            },
            (cause) => {
              if (opened.scope.live())
                setNotice(
                  `Bunkers could not be re-linked: ${cause instanceof Error ? cause.message : cause}`,
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
            : "Could not open the Perimeter.",
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
          !(await askConfirm({
            title: `Restore ${name}'s access to this Perimeter?`,
            description: cause.message,
            confirmLabel: "Restore access",
          }))
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
          <div class="start-page">
            <Header session={props.session} />
            <Show
              when={UUID.test(id) && props.session.user()}
              fallback={
                <AuthScreen title={title()}>
                  <AuthCard icon={<Icon name="rules" />}>
                    <Show
                      when={UUID.test(id)}
                      fallback={
                        <a class="button primary" href="/" link>
                          Choose a Perimeter
                        </a>
                      }
                    >
                      <p>Use the account that owns this Perimeter.</p>
                      <button
                        class="primary"
                        onClick={() => void props.session.signIn()}
                      >
                        Sign in
                      </button>
                    </Show>
                  </AuthCard>
                </AuthScreen>
              }
            >
              <KeyGate
                session={props.session}
                manager={manager}
                purpose={`connect to ${bunker ?? "your bunkers"}`}
              >
                <AuthScreen title={title()}>
                  <AuthCard icon={<Icon name="rules" />}>
                    <Show when={error()}>
                      <p role="alert">{error()}</p>
                    </Show>
                    <Switch>
                      <Match when={inventory().loading && !inventory().value}>
                        <Loading label="Loading your Perimeter…" />
                      </Match>
                      <Match when={inventory().error}>
                        <p role="alert">
                          Could not load your Perimeter: {inventory().error}
                        </p>
                        <button
                          class="primary"
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
                        <p role="alert">
                          This Perimeter is not in the selected account. Switch
                          accounts or choose another Perimeter.
                        </p>
                      </Match>
                      <Match when={booting()}>
                        <Loading label="Your Perimeter will open automatically when it is ready." />
                      </Match>
                      <Match when={row() && row()!.status !== "running"}>
                        <p>
                          Open the dashboard to start this Perimeter or check
                          its status.
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
                        <Loading label="Verifying and connecting to your bunker…" />
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
                        <button class="primary" onClick={() => void open()}>
                          {error() ? "Try again" : "Open Perimeter"}
                        </button>
                      </Match>
                    </Switch>
                  </AuthCard>
                  <Show when={props.session.keyState().error}>
                    <button
                      class="link auth-link"
                      onClick={() => void props.session.refresh()}
                    >
                      Try again
                    </button>
                  </Show>
                  <a class="auth-link" href={back()} link>
                    {fromHome()
                      ? "Back to your Perimeters"
                      : "Back to dashboard"}
                  </a>
                </AuthScreen>
              </KeyGate>
            </Show>
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
              product={PRODUCT}
              backTo={back()}
              header={<Header session={props.session} />}
              client={opened.client}
              snapshot={opened.snapshot}
              shell={shell(opened)}
              sandboxesLoading={() =>
                linking() || (!!inventory().loading && !inventory().value)
              }
              candidates={() =>
                sandboxCandidates(opened, props.session.inventory().value ?? [])
              }
              accept={(name, restore) =>
                acceptSandbox(
                  opened,
                  props.session.inventory().value ?? [],
                  name,
                  restore,
                )
              }
              tinfoilApiKeys={async () =>
                usableApiKeys(await opened.scope.api("/api/keys/"))
              }
            />
          </>
        )}
      </Show>
    </div>
  );
}
