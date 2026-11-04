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
import { Icon, Loading, Modal, SkeletonRows } from "../components";
import {
  parseStartRequest,
  startErrorURL,
  startReturnURL,
  type MKResource,
  type StartRequest,
  type StartRole,
} from "./contract";
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
  monitorOf,
  type Container,
  type Scope,
  type Session,
} from "./session";
import "./console.css";

const START = "tinfoil.start";
const SSH_ED25519_PREFIX = "AAAAC3NzaC1lZDI1NTE5AAAAI";
// Mirrors the dashboard's container state labels.
const STATUS_LABELS: Record<string, string> = {
  created: "Provisioning",
  pending: "Queued",
  started: "Booting",
};
const BUSY_STATUSES = [
  "created",
  "pending",
  "deploying",
  "started",
  "stopping",
];

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
    const wire = Uint8Array.from(atob(blob), (c) => c.charCodeAt(0));
    if (
      type === "ssh-ed25519" &&
      blob.startsWith(SSH_ED25519_PREFIX) &&
      wire.length === 51
    )
      return "ed25519:" + btoa(String.fromCharCode(...wire.subarray(19)));
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
  navigate: (url: string) => void;
}) {
  const r = props.request;
  const dashboard = keys.TARGETS.dashboard!;
  const [file, setFile] = createSignal<keys.RecoveryFile>();
  const [error, setError] = createSignal("");
  const [busy, setBusy] = createSignal(false);
  const [entries, setEntries] = createSignal<Record<string, string>>({});
  let created: MKResource[] | undefined;
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
    sessionStorage.removeItem(START);
    props.navigate(startReturnURL(dashboard, r, roleKeys(resources)));
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
    props.navigate(startErrorURL(dashboard, r.state, reason));
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
  return (
    <>
      <span class="start-mark">
        <Icon name={file() ? "devices" : "terminal"} />
      </span>
      <h1 id="start-title">
        {r.mode === "umk"
          ? "Add your CLI keys"
          : file()
            ? "Keep your key close."
            : "Welcome to Tinfoil."}
      </h1>
      <p id="start-description">
        {r.mode === "umk"
          ? "Paste the public keys made by the Tinfoil CLI. Their private keys stay on your computer, so this sandbox is reached with the CLI only."
          : file()
            ? "Save your recovery key before you head to your sandboxes."
            : `First, we'll create keys for your ${r.roles.join(" and ")}. They're encrypted with your account, and your dashboard only sees their public keys.`}
      </p>
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
          <p class="start-notice" role="alert">
            You are signed in as a different user than the one who started this
            setup.
          </p>
          <button
            class="primary start-continue"
            onClick={() => leave("account_mismatch")}
          >
            Return to dashboard
          </button>
        </Match>
        <Match when={r.mode === "umk"}>
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
            class="primary start-continue"
            disabled={busy() || !state()}
            onClick={() => void finishUMK()}
          >
            Continue to dashboard
          </button>
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
          <Show
            when={props.session.keyState().error}
            fallback={<Loading label="Loading your keys…" />}
          >
            <p class="start-notice" role="alert">
              Your keys could not be loaded: {props.session.keyState().error}
            </p>
          </Show>
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
            when={state()?.recovery.some((r) => r.type === "passkey")}
            fallback={
              <AddPasskey
                session={props.session}
                manager={props.manager}
                onContinue={() => void addTMK()}
              />
            }
          >
            <button
              class="primary start-continue"
              disabled={busy()}
              aria-busy={busy()}
              onClick={() => void addTMK()}
            >
              {busy() ? "Saving keys…" : "Create keys and continue"}
            </button>
          </Show>
        </Match>
      </Switch>
      <button
        class="link start-alternative"
        disabled={busy()}
        onClick={() => leave("cancelled")}
      >
        Cancel and return to dashboard
      </button>
    </>
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
                ? `/monitor/${monitor.id}`
                : undefined
            }
          >
            <div>
              <h2>
                {monitor.name}
                <span
                  class="start-status"
                  classList={{ busy: BUSY_STATUSES.includes(monitor.status) }}
                  data-status={monitor.status}
                >
                  {STATUS_LABELS[monitor.status] ?? monitor.status}
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

export function Header(props: { session: Session }) {
  // Recovery keys settled at sign-out, offered once before they are deleted.
  const [leaving, setLeaving] =
    createSignal<Awaited<ReturnType<Session["prepareLogout"]>>>();
  const [busy, setBusy] = createSignal(false);
  createEffect(
    on(
      [() => props.session.user()?.id, props.session.account],
      () => setLeaving(undefined),
      { defer: true },
    ),
  );
  const stay = () => {
    setLeaving(undefined);
    props.session.cancelLogout();
  };
  const [failed, setFailed] = createSignal("");
  const signOut = async () => {
    if (busy()) return;
    setBusy(true);
    setFailed("");
    try {
      // An account change at any point offers and deletes nothing; records
      // changed by another tab are settled and offered again.
      for (;;) {
        const settled = await props.session.prepareLogout();
        if (!settled.live()) return;
        if (settled.files.length || settled.unresolved)
          return setLeaving(settled);
        if ((await props.session.logout(settled)) || !settled.live()) return;
      }
    } catch (cause) {
      setFailed(cause instanceof Error ? cause.message : String(cause));
    } finally {
      setBusy(false);
    }
  };
  const confirm = async () => {
    const offer = leaving();
    try {
      if (await props.session.logout(offer)) return;
    } catch (cause) {
      return setFailed(cause instanceof Error ? cause.message : String(cause));
    }
    setLeaving(undefined);
    if (offer?.live()) await signOut();
  };
  return (
    <header class="start-header">
      <a href="/" class="start-brand" aria-label="Tinfoil Terminal home" link>
        <img src="/icons/tinfoil.svg" alt="" />
        <span>Terminal</span>
      </a>
      <Show
        when={props.session.user()}
        fallback={
          <a href={keys.TARGETS.dashboard}>
            Open dashboard <Icon name="external" />
          </a>
        }
      >
        {(user) => (
          <span>
            {user().label}{" "}
            <button
              class="link"
              disabled={busy()}
              onClick={() => void signOut()}
            >
              Sign out
            </button>
            <Show when={failed()}>
              <span class="start-notice" role="alert">
                {failed()}
              </span>
            </Show>
          </span>
        )}
      </Show>
      <Modal
        class="start-dialog"
        open={!!leaving()}
        onClose={stay}
        aria-labelledby="leave-title"
      >
        <button
          class="dialog-close icon-button start-close"
          aria-label="Stay signed in"
          onClick={stay}
        >
          <Icon name="close" />
        </button>
        <div class="start-dialog-body">
          <h1 id="leave-title">Save your recovery key first</h1>
          <Show when={failed()}>
            <p class="start-notice" role="alert">
              {failed()}
            </p>
          </Show>
          <Show when={leaving()?.unresolved}>
            <p class="start-notice" role="alert">
              A recovery key in this browser could not be confirmed. If your
              setup finished, it may be the only way to open your keys, and
              signing out deletes it. Stay signed in to try again later.
            </p>
          </Show>
          <For each={leaving()?.files ?? []}>
            {(file) => <RecoveryDownload file={file} />}
          </For>
          <p class="start-help">
            Signing out removes the recovery keys saved in this browser.
          </p>
          <button class="primary start-continue" onClick={() => void confirm()}>
            {leaving()?.unresolved ? "Sign out anyway" : "Sign out"}
          </button>
        </div>
      </Modal>
    </header>
  );
}

export default function Console(props: {
  session: Session;
  manager?: PasskeyKeyManager;
  navigate?: (url: string) => void;
}) {
  const manager = props.manager ?? keys.passkeys();
  const navigate = props.navigate ?? ((url: string) => location.assign(url));
  const [start, setStart] = createSignal(startRequest());
  const close = () => {
    sessionStorage.removeItem(START);
    history.pushState(null, "", "/");
    setStart(undefined);
  };
  return (
    <div class="start-page">
      <Header session={props.session} />
      <main class="start-welcome start-home">
        <h1>{props.session.user() ? "Welcome back" : "Welcome to Tinfoil"}</h1>
        <Show
          when={props.session.user()}
          fallback={
            <>
              <p>Sign in to open your Monitors and set up sandbox keys.</p>
              <button
                class="primary"
                onClick={() => void props.session.signIn()}
              >
                Sign in <Icon name="arrow" />
              </button>
            </>
          }
        >
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
            <KeyGate session={props.session} manager={manager}>
              <Cleanup session={props.session} />
              <RecoveryMethods session={props.session} manager={manager} />
            </KeyGate>
          </section>
        </Show>
      </main>
      <footer class="start-footer">
        <Icon name="rules" /> Privacy by design.
      </footer>
      <Modal
        class="start-dialog"
        open={!!start()}
        onClose={close}
        aria-labelledby="start-title"
        aria-describedby="start-description"
      >
        <button
          class="dialog-close icon-button start-close"
          aria-label="Close setup"
          onClick={close}
        >
          <Icon name="close" />
        </button>
        <div class="start-dialog-body start-setup">
          <Switch>
            <Match when={start() === "invalid"}>
              <h1 id="start-title">This setup link is not valid</h1>
              <p id="start-description">Start again from your dashboard.</p>
            </Match>
            <Match when={!props.session.user()}>
              <h1 id="start-title">Sign in to continue</h1>
              <p id="start-description">
                Sign in with the account that started this setup.
              </p>
              <button
                class="primary start-continue"
                onClick={() => void props.session.signIn()}
              >
                Sign in
              </button>
            </Match>
            <Match when={start() as StartRequest}>
              {(request) => (
                <Start
                  session={props.session}
                  manager={manager}
                  request={request()}
                  navigate={navigate}
                />
              )}
            </Match>
          </Switch>
        </div>
      </Modal>
    </div>
  );
}
