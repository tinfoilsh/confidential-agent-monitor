import { sha256 } from "@noble/hashes/sha2.js";
import { For, Match, Show, Switch, createSignal, onMount } from "solid-js";
import { AuthCard, AuthScreen, Icon, Loading } from "../components";
import {
  b64u,
  canonicalKeySyncRequest,
  CONFIRMATION_CODE_LENGTH,
  confirmationCode,
  confirmationCodeMatches,
  keySyncCallbackURL,
  parseKeySyncCompletion,
  parseKeySyncLaunch,
  sealKeySyncEnvelope,
  type KeySyncRequest,
} from "./contract";
import { Header } from "./Header";
import * as keys from "./keys";
import { KeyGate } from "./KeyPanel";
import { PRODUCT } from "./product";
import type { Session } from "./session";
import "./console.css";

const LAUNCH = "tinfoil.cli.key-sync";
const PENDING = "tinfoil.cli.key-sync.pending";
const now = () => Math.floor(Date.now() / 1000);
const route = () => location.pathname.replace(/\/+$/, "");
const digestOf = (r: KeySyncRequest, profile: KeySyncProfile) =>
  b64u(sha256(canonicalKeySyncRequest(r, profile)));
type KeySyncProfile = ReturnType<typeof keys.keySyncProfile>;

let launchError = "";
let completion: ReturnType<typeof parseKeySyncCompletion> | undefined;

// Only public key-sync fragments enter this page. OAuth returns directly to CLI.
export function capture() {
  const at = route();
  try {
    if (at === "/cli" && location.hash) {
      parseKeySyncLaunch(location.hash, now());
      sessionStorage.setItem(LAUNCH, location.hash);
    } else if (at === "/cli/complete" && location.hash) {
      completion = parseKeySyncCompletion(location.hash);
    } else if (at !== "/cli") {
      throw new Error(
        "This key-sync link is not valid. Run tinfoil login --sync again.",
      );
    }
  } catch (cause) {
    sessionStorage.removeItem(LAUNCH);
    launchError = cause instanceof Error ? cause.message : String(cause);
  }
  if (location.hash || location.search) history.replaceState(null, "", at);
}

function stored(): KeySyncRequest | undefined {
  try {
    return parseKeySyncLaunch(sessionStorage.getItem(LAUNCH) ?? "", now());
  } catch {
    return undefined;
  }
}

export default function Cli(props: { session: Session }) {
  document.title = `CLI key sync · ${PRODUCT.title}`;
  const manager = keys.passkeys();
  const [error, setError] = createSignal(launchError);
  const [typed, setTyped] = createSignal("");
  const [confirmed, setConfirmed] = createSignal("");
  const [done, setDone] = createSignal(false);
  const [busy, setBusy] = createSignal(false);
  let profile: KeySyncProfile | undefined;
  try {
    profile = keys.keySyncProfile();
  } catch (cause) {
    setError(
      launchError || (cause instanceof Error ? cause.message : String(cause)),
    );
  }
  const launch = stored();
  const live = () => !!launch && launch.expires > now();
  const sameUser = () => !!launch && launch.user === props.session.user()?.id;
  const ready = () =>
    profile &&
    launch &&
    live() &&
    sameUser() &&
    props.session.account() === launch.account &&
    confirmed() === digestOf(launch, profile);

  // Confirm the request before selecting its account or offering any private keys.
  const confirm = async () => {
    if (!profile || !launch || !live() || !sameUser() || busy())
      return setError(
        "Sign in as the same user as your CLI, then run tinfoil login --sync again if the request expired.",
      );
    if (
      !confirmationCodeMatches(
        typed(),
        confirmationCode(canonicalKeySyncRequest(launch, profile)),
      )
    )
      return setError("That code does not match the one in your terminal.");
    setBusy(true);
    setError("");
    try {
      await props.session.activate(launch.account);
      if (!live() || !sameUser() || props.session.account() !== launch.account)
        throw new Error(
          "Your account changed. Run tinfoil login --sync again.",
        );
      setConfirmed(digestOf(launch, profile));
    } catch (cause) {
      setError(cause instanceof Error ? cause.message : String(cause));
    } finally {
      setBusy(false);
    }
  };

  const finish = async () => {
    const scope = props.session.bind();
    if (busy()) return;
    if (!ready() || !launch || !profile || !scope.live())
      return setError(
        "Your account changed or the request expired. Run tinfoil login --sync again.",
      );
    setBusy(true);
    setError("");
    try {
      const unlocked = scope.unlocked();
      if (!unlocked)
        throw new Error("Unlock your keys to sync them to the CLI.");
      const payload = await sealKeySyncEnvelope(launch, profile, {
        user_id: scope.user,
        dek: { dek_id: unlocked.context.dek_id, dek: unlocked.dek },
      });
      if (!scope.live() || !ready())
        throw new Error(
          "Your account changed or the request expired. Run tinfoil login --sync again.",
        );
      sessionStorage.setItem(
        PENDING,
        JSON.stringify({
          request: launch.request,
          user: launch.user,
          account: launch.account,
        }),
      );
      sessionStorage.removeItem(LAUNCH);
      location.assign(keySyncCallbackURL(profile, payload));
    } catch (cause) {
      setError(cause instanceof Error ? cause.message : String(cause));
      setBusy(false);
    }
  };

  const complete = async () => {
    if (busy()) return;
    setBusy(true);
    try {
      const pending = JSON.parse(sessionStorage.getItem(PENDING) ?? "null");
      if (
        !completion ||
        pending?.request !== completion.request ||
        pending.user !== completion.user ||
        pending.account !== completion.account ||
        props.session.user()?.id !== completion.user
      )
        throw new Error(
          "This completion does not match a key sync started in this tab.",
        );
      setError("");
      await props.session.activate(completion.account);
      if (
        props.session.user()?.id !== completion.user ||
        props.session.account() !== completion.account
      )
        throw new Error("Your account changed before this page finished.");
      sessionStorage.removeItem(PENDING);
      setDone(true);
    } catch (cause) {
      setError(cause instanceof Error ? cause.message : String(cause));
    } finally {
      setBusy(false);
    }
  };
  if (route() === "/cli/complete" && completion) void complete();
  const Send = () => {
    onMount(() => void finish());
    return null;
  };

  const page = () => (
    <AuthScreen title={done() ? "Sync successful" : "Sync your CLI"}>
      <AuthCard icon={<Icon name={done() ? "check" : "devices"} />}>
        <Show when={error()}>
          <p role="alert">{error()}</p>
        </Show>
        <Switch>
          <Match when={!props.session.user()}>
            <p>Sign in with the same account as your CLI.</p>
            <button class="primary" onClick={() => void props.session.signIn()}>
              Sign in
            </button>
          </Match>
          <Match when={route() === "/cli/complete"}>
            <p role="status">
              {done()
                ? "Your keys are synced. You can close this tab."
                : error()
                  ? "Return to your terminal to check whether key sync finished."
                  : "Finishing key sync…"}
            </p>
            <Show when={!done() && error() && completion}>
              <button
                class="primary"
                disabled={busy()}
                onClick={() => void complete()}
              >
                Try again
              </button>
            </Show>
            <a class="button" href={keys.TARGETS.dashboard}>
              Open your bunkers
            </a>
          </Match>
          <Match when={profile && live() && !sameUser()}>
            <p role="alert">
              This key-sync request belongs to a different user. Sign out here
              and sign in as the user you chose in the CLI.
            </p>
          </Match>
          <Match when={ready()}>
            <Show when={!error()}>
              <Loading label="Sending your keys to the CLI…" />
            </Show>
            <Send />
          </Match>
          <Match when={profile && live()}>
            <p>Type the code shown in your terminal.</p>
            <form
              class="start-code"
              onSubmit={(event) => {
                event.preventDefault();
                void confirm();
              }}
            >
              <label class="start-code-boxes">
                <input
                  aria-label="Confirmation code"
                  autocomplete="one-time-code"
                  autocapitalize="characters"
                  spellcheck={false}
                  value={typed()}
                  onInput={(event) => {
                    const input = event.currentTarget;
                    input.value = input.value
                      .toUpperCase()
                      .replace(/[^A-Z]/g, "")
                      .slice(0, CONFIRMATION_CODE_LENGTH);
                    setTyped(input.value);
                  }}
                />
                <For each={Array.from({ length: CONFIRMATION_CODE_LENGTH })}>
                  {(_, i) => (
                    <span
                      aria-hidden="true"
                      classList={{
                        active:
                          i() ===
                          Math.min(
                            typed().length,
                            CONFIRMATION_CODE_LENGTH - 1,
                          ),
                      }}
                    >
                      {typed()[i()]}
                    </span>
                  )}
                </For>
              </label>
              <button class="primary" disabled={busy()}>
                Continue
              </button>
            </form>
          </Match>
          <Match when={!error()}>
            <p role="alert">
              This key-sync request has expired or is missing. Run tinfoil login
              --sync again.
            </p>
          </Match>
        </Switch>
      </AuthCard>
    </AuthScreen>
  );

  return (
    <div class="start-page">
      <Header session={props.session} />
      <Show when={ready()} fallback={page()}>
        <KeyGate
          session={props.session}
          manager={manager}
          purpose="let the CLI open your bunkers"
        >
          {page()}
        </KeyGate>
      </Show>
    </div>
  );
}
