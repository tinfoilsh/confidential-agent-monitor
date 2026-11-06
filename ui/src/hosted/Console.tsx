import type { PasskeyKeyManager } from "@tinfoilsh/passkey-kit";
import {
  For,
  Match,
  Show,
  Switch,
  createEffect,
  createSignal,
  on,
} from "solid-js";
import {
  AuthCard,
  AuthScreen,
  Icon,
  Loading,
  SkeletonRows,
} from "../components";
import {
  SSH_ED25519,
  fromBase64,
  parseStartRequest,
  startErrorURL,
  startReturnURL,
  toBase64,
  type MKResource,
  type StartRequest,
  type StartRole,
} from "./contract";
import { Header, monitorURL } from "./Header";
import * as keys from "./keys";
import {
  AddPasskey,
  KeyGate,
  RecoveryDownload,
  RecoveryMethods,
  SetupKeys,
  UnlockKeys,
} from "./KeyPanel";
import {
  MONITOR_REPO,
  SANDBOX_REPO,
  STARTING,
  monitorOf,
  type Container,
  type Scope,
  type Session,
} from "./session";
import "./console.css";

const START = "tinfoil.start";
// Mirrors the dashboard's container state labels.
const STATUS_LABELS: Record<string, string> = {
  created: "Provisioning",
  pending: "Queued",
  deploying: "Deploying",
  started: "Booting",
  running: "Running",
  stopping: "Stopping",
  stopped: "Stopped",
  failed: "Failed",
};
const BUSY_STATUSES = [...STARTING, "stopping"];

// The /start fragment is read once, kept for this tab across sign-in and removed from the URL.
export function capture() {
  if (location.pathname.replace(/\/+$/, "") !== "/start" || !location.hash)
    return;
  let request = "invalid";
  try {
    request = JSON.stringify(parseStartRequest(location.hash));
  } catch {}
  sessionStorage.setItem(START, request);
  history.replaceState(null, "", "/start");
}

function startRequest(): StartRequest | "invalid" | undefined {
  const saved = sessionStorage.getItem(START);
  if (!saved || location.pathname.replace(/\/+$/, "") !== "/start") return;
  return saved === "invalid" ? "invalid" : JSON.parse(saved);
}

// An OpenSSH Ed25519 public key in the measured owner key form.
function ownerKeyFromSSH(line: string): string {
  const [type, blob] = line.trim().split(/\s+/);
  try {
    const wire = fromBase64(blob);
    if (
      type === "ssh-ed25519" &&
      wire.length === SSH_ED25519.length + 32 &&
      SSH_ED25519.every((byte, i) => wire[i] === byte)
    )
      return "ed25519:" + toBase64(wire.subarray(SSH_ED25519.length));
  } catch {}
  throw new Error("Paste an ssh-ed25519 public key.");
}

function roleKeys(
  resources: { kind: StartRole; public_key: string; key_id: string }[],
) {
  const out = {} as Record<StartRole, { public_key: string; key_id: string }>;
  for (const r of resources) out[r.kind] = r;
  return out;
}

// Key-only handoff: persists the requested keys, then returns only public keys.
function Start(props: {
  session: Session;
  manager: PasskeyKeyManager;
  request: StartRequest;
}) {
  const r = props.request;
  const dashboard = keys.TARGETS.dashboard!;
  const [file, setFile] = createSignal<keys.RecoveryFile>();
  const [error, setError] = createSignal("");
  const [busy, setBusy] = createSignal(false);
  const [entries, setEntries] = createSignal<Record<string, string>>({});
  let created: MKResource[] | undefined;
  let finished = false;
  // Fresh keys per attempt; a retry after an uncertain write resends the same ones.
  const generate = () => {
    const attempt = keys.newAttempt();
    return (created = r.roles.map((role) =>
      keys.newResourceKey(role, attempt),
    ));
  };
  const finish = (
    resources: { kind: StartRole; public_key: string; key_id: string }[],
  ) => {
    finished = true;
    sessionStorage.removeItem(START);
    location.assign(startReturnURL(dashboard, r, roleKeys(resources)));
  };
  const finishTMK = (resources: MKResource[]) =>
    finish(
      resources.map((x) => ({
        kind: x.kind,
        public_key: x.owner_public_key,
        key_id: x.key_id,
      })),
    );
  const leave = (reason: "cancelled" | "account_mismatch" | "unsupported") => {
    sessionStorage.removeItem(START);
    location.assign(startErrorURL(dashboard, r.state, reason));
  };
  // Bound to the user and account it started in; a switch discards the result.
  const act = async (task: (scope: Scope) => Promise<void>) => {
    if (busy()) return;
    const scope = props.session.bind();
    setBusy(true);
    setError("");
    try {
      await task(scope);
    } catch (cause) {
      if (scope.live())
        setError(cause instanceof Error ? cause.message : String(cause));
    } finally {
      setBusy(false);
    }
  };
  const addTMK = () =>
    act(async (scope) => {
      await props.session.refresh();
      const resources = created ?? generate();
      await scope.update(keys.addResources(resources));
      if (scope.live()) finishTMK(resources);
    });
  const finishUMK = () =>
    act(async () =>
      finish(
        r.roles.map((kind) => ({
          kind,
          public_key: ownerKeyFromSSH(entries()[kind] ?? ""),
          key_id: keys.id16(),
        })),
      ),
    );
  const state = () => props.session.keyState().value;
  const hasPasskey = () =>
    !!state()?.recovery.some((r) => r.type === "passkey");
  // Opening keys that a passkey protects is the go-ahead; the button remains for retries.
  createEffect(
    on(
      () =>
        r.mode === "tmk" &&
        !file() &&
        props.session.user()?.id === r.user &&
        !!props.session.unlocked() &&
        hasPasskey(),
      (ready) => {
        if (ready && !finished) void addTMK();
      },
    ),
  );
  return (
    <AuthScreen
      title={
        r.mode === "umk"
          ? "Add your CLI keys"
          : file()
            ? "Save your recovery key"
            : "Welcome to Terminal"
      }
      description={
        r.mode === "umk"
          ? "Paste the public keys made by the Tinfoil CLI. Their private keys stay on your computer, so this sandbox is reached with the CLI only."
          : file()
            ? "Save your recovery key before you head to your sandboxes."
            : `First, we'll create keys for your ${r.roles.join(" and ")}. They're encrypted with your account, and your dashboard only sees their public keys.`
      }
      account={props.session.user()?.label}
    >
      <Show when={r.mode === "tmk" && !file()}>
        <ol class="start-steps" aria-label="Getting started">
          <li aria-current="step">
            <span>1</span> Set up your keys
          </li>
          <li>
            <span>2</span> Create your sandbox
          </li>
        </ol>
      </Show>
      <Show when={error()}>
        <p class="start-notice" role="alert">
          {error()}
        </p>
      </Show>
      <Switch>
        <Match when={props.session.user()?.id !== r.user}>
          <AuthCard icon={<Icon name="warning" />} title="Different account">
            <p>
              You are signed in as a different user than the one who started
              this setup.
            </p>
            <button class="primary" onClick={() => leave("account_mismatch")}>
              Return to dashboard
            </button>
          </AuthCard>
        </Match>
        <Match when={r.mode === "umk"}>
          <AuthCard icon={<Icon name="terminal" />}>
            <For each={r.roles}>
              {(role) => (
                <label class="start-field">
                  {role === "monitor" ? "Monitor" : "Sandbox"} owner public key
                  <textarea
                    rows={2}
                    disabled={busy()}
                    placeholder="ssh-ed25519 AAAA…"
                    onInput={(event) =>
                      setEntries({
                        ...entries(),
                        [role]: event.currentTarget.value,
                      })
                    }
                  />
                </label>
              )}
            </For>
            <button
              class="primary"
              disabled={busy() || !state()}
              onClick={() => void finishUMK()}
            >
              Continue to dashboard
            </button>
          </AuthCard>
        </Match>
        <Match when={file()}>
          {(recovery) => (
            <RecoveryDownload
              file={recovery()}
              onContinue={() => finishTMK(created!)}
              onBack={() => setFile()}
            />
          )}
        </Match>
        <Match when={!state()}>
          <AuthCard>
            <Show
              when={props.session.keyState().error}
              fallback={<Loading label="Loading your keys…" />}
            >
              <p role="alert">
                Your keys could not be loaded: {props.session.keyState().error}
              </p>
            </Show>
          </AuthCard>
        </Match>
        <Match when={state() && !state()!.dek_id}>
          <SetupKeys
            session={props.session}
            manager={props.manager}
            resources={generate}
            onDone={(saved) => (saved ? setFile(saved) : finishTMK(created!))}
          />
        </Match>
        <Match when={state() && !props.session.unlocked()}>
          <UnlockKeys session={props.session} manager={props.manager} />
        </Match>
        <Match when={props.session.unlocked()}>
          <Show
            when={hasPasskey()}
            fallback={
              <AddPasskey
                session={props.session}
                manager={props.manager}
                onContinue={() => void addTMK()}
              />
            }
          >
            <AuthCard icon={<Icon name="key" />} title="Sandbox keys">
              <p>
                Your keys are unlocked. Create keys for your{" "}
                {r.roles.join(" and ")} to continue.
              </p>
              <button
                class="primary"
                disabled={busy()}
                aria-busy={busy()}
                onClick={() => void addTMK()}
              >
                {busy() ? "Saving keys…" : "Create keys and continue"}
              </button>
            </AuthCard>
          </Show>
        </Match>
      </Switch>
      <button
        class="link auth-link"
        disabled={busy()}
        onClick={() => leave("cancelled")}
      >
        Cancel and return to dashboard
      </button>
    </AuthScreen>
  );
}

function Inventory(props: { session: Session }) {
  const read = () => props.session.inventory();
  const mine = (row: Container) =>
    row.clerk_user_id === props.session.user()?.id;
  const monitors = () =>
    (read().value ?? []).filter((r) => r.repo === MONITOR_REPO && mine(r));
  const sandboxes = (monitor: Container) =>
    (read().value ?? []).filter(
      (r) => r.repo === SANDBOX_REPO && monitorOf(r) === monitor.id,
    );
  return (
    <nav class="start-monitors" aria-label="Your monitors">
      <p class="start-eyebrow">Your monitors</p>
      <Show when={read().loading && !read().value}>
        <SkeletonRows cards label="Loading your Monitors and sandboxes…" />
      </Show>
      <Show when={read().error}>
        <p class="start-notice" role="alert">
          {read().value
            ? "Could not refresh your resources. This list may be out of date."
            : `Your resources could not be loaded: ${read().error}`}
        </p>
      </Show>
      <Show
        when={
          read().value && !read().loading && !read().error && !monitors().length
        }
      >
        <p class="start-help">
          No Monitors in this account yet. Create one from your dashboard.
        </p>
      </Show>
      <For each={monitors()}>
        {(monitor) => (
          <a
            class="start-key-choice"
            link
            href={
              monitor.owner_key_mode === "tmk"
                ? monitorURL(monitor.id)
                : undefined
            }
          >
            <div>
              <h2>
                {monitor.name}
                <span
                  class={`badge status-${BUSY_STATUSES.includes(monitor.status) ? "busy" : monitor.status}`}
                >
                  <Show when={BUSY_STATUSES.includes(monitor.status)}>
                    <span class="loading-spinner" aria-hidden="true" />
                  </Show>
                  {STATUS_LABELS[monitor.status] ?? "Status unavailable"}
                </span>
              </h2>
              <p>
                {sandboxes(monitor)
                  .map((s) => s.name)
                  .join(", ")}
              </p>
              <Show when={monitor.owner_key_mode !== "tmk"}>
                <p>
                  Open with the CLI:{" "}
                  <code>tinfoil monitor open {monitor.name}</code>
                </p>
              </Show>
            </div>
            <Show when={monitor.owner_key_mode === "tmk"}>
              <Icon name="arrow" />
            </Show>
          </a>
        )}
      </For>
    </nav>
  );
}

// Removes saved keys only for resources confirmed deleted in their own account.
function Cleanup(props: { session: Session }) {
  const [error, setError] = createSignal("");
  const candidates = () => {
    const rows = props.session.inventory();
    if (!rows.value || rows.error) return [];
    return (props.session.unlocked()?.payload.resources ?? []).filter(
      (r) =>
        r.binding?.account === props.session.account() &&
        !rows.value!.some((row) => row.id === r.binding!.container_id),
    );
  };
  // Absence must be confirmed per resource in its own account, not inferred.
  const clean = async () => {
    setError("");
    const scope = props.session.bind();
    try {
      const gone: string[] = [];
      for (const r of candidates())
        try {
          await scope.api(`/api/containers/${r.binding!.container_id}`);
        } catch (cause) {
          if (cause instanceof keys.ApiError && cause.status === 404)
            gone.push(r.key_id);
          else throw cause;
        }
      if (gone.length) await scope.update(keys.removeResources(gone));
    } catch (cause) {
      setError(cause instanceof Error ? cause.message : String(cause));
    }
  };
  return (
    <Show when={candidates().length}>
      <p class="start-help">
        Some saved keys belong to resources that are no longer listed.{" "}
        <button class="link" onClick={() => void clean()}>
          Check and remove deleted ones
        </button>
      </p>
      <Show when={error()}>
        <p class="start-notice" role="alert">
          {error()}
        </p>
      </Show>
    </Show>
  );
}

export default function Console(props: { session: Session }) {
  document.title = "Get started · Terminal";
  const manager = keys.passkeys();
  const start = startRequest();
  return (
    <div class="start-page">
      <Header session={props.session} />
      <Switch
        fallback={
          <KeyGate session={props.session} manager={manager}>
            <main class="start-welcome start-home">
              <h1>Welcome back</h1>
              <Inventory session={props.session} />
              <Show when={props.session.keyState().error}>
                {(error) => (
                  <p class="start-notice" role="alert">
                    Your saved keys could not be refreshed: {error()}
                  </p>
                )}
              </Show>
              <section class="start-monitors" aria-label="Your keys">
                <p class="start-eyebrow">Your keys</p>
                <Cleanup session={props.session} />
                <RecoveryMethods session={props.session} manager={manager} />
              </section>
            </main>
          </KeyGate>
        }
      >
        <Match when={start === "invalid"}>
          <AuthScreen title="This setup link is not valid">
            <AuthCard icon={<Icon name="warning" />}>
              <p>Start again from your dashboard.</p>
              <a class="button primary" href={keys.TARGETS.dashboard}>
                Open dashboard
              </a>
            </AuthCard>
          </AuthScreen>
        </Match>
        <Match when={!props.session.user()}>
          <AuthScreen title="Welcome to Terminal">
            <AuthCard icon={<Icon name="terminal" />}>
              <p>
                {start
                  ? "Sign in with the account that started this setup."
                  : "Sign in to open your Monitors and set up sandbox keys."}
              </p>
              <button
                class="primary"
                onClick={() => void props.session.signIn()}
              >
                Sign in
              </button>
            </AuthCard>
          </AuthScreen>
        </Match>
        <Match when={start as StartRequest}>
          {(request) => (
            <Start
              session={props.session}
              manager={manager}
              request={request()}
            />
          )}
        </Match>
      </Switch>
    </div>
  );
}
