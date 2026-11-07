import type { PasskeyKeyManager } from "@tinfoilsh/passkey-kit";
import {
  For,
  Match,
  Show,
  Switch,
  createResource,
  createSignal,
  onCleanup,
  type JSX,
} from "solid-js";
import {
  AuthCard,
  AuthCardSkeleton,
  AuthScreen,
  download,
  Icon,
} from "../components";
import type { MKResource } from "./contract";
import * as keys from "./keys";
import type { Scope, Session } from "./session";

const MAX_RECOVERY_FILE_BYTES = 16_000;
const message = (cause: unknown) => keys.passkeyMessage(cause);

// One key action at a time, bound to the user and account it started in;
// closing the page or switching accounts cancels it and its passkey prompt.
function useAction(session: Session, manager: PasskeyKeyManager) {
  const [busy, setBusy] = createSignal(false);
  const [error, setError] = createSignal("");
  let current: AbortController | undefined;
  onCleanup(() => {
    current?.abort();
    manager.cancelActiveCeremony();
  });
  const run = async (
    task: (scope: Scope, signal: AbortSignal) => Promise<void>,
  ) => {
    if (busy()) return;
    const scope = session.bind();
    const attempt = (current = new AbortController());
    const signal = AbortSignal.any([attempt.signal, scope.signal]);
    signal.addEventListener("abort", () => manager.cancelActiveCeremony(), {
      once: true,
    });
    setBusy(true);
    setError("");
    try {
      await task(scope, signal);
    } catch (cause) {
      if (!signal.aborted) setError(message(cause));
    } finally {
      if (current === attempt) setBusy(false);
    }
  };
  return { busy, error, run };
}

// With no passkey yet, the file is the only way back in, so Continue waits for it.
export function RecoveryDownload(props: {
  file: keys.RecoveryFile;
  onContinue?: () => void;
  onBack?: () => void;
}) {
  const [saved, setSaved] = createSignal(false);
  return (
    <AuthCard icon={<Icon name="key" />} title="Recovery key">
      <p>
        It opens your bunkers after you sign out or switch browsers. This
        browser keeps a copy only until you sign out.
      </p>
      <button
        classList={{ primary: !saved() }}
        onClick={() => {
          download(props.file.text, props.file.filename, "text/plain");
          setSaved(true);
        }}
      >
        <Icon name="download" />{" "}
        {saved() ? "Download recovery key again" : "Download recovery key"}
      </button>
      <Show when={props.onContinue}>
        {(next) => (
          <button class="primary" disabled={!saved()} onClick={() => next()()}>
            Continue
          </button>
        )}
      </Show>
      <Show when={props.onBack}>
        {(back) => (
          <button class="link" onClick={() => back()()}>
            Use a passkey instead
          </button>
        )}
      </Show>
    </AuthCard>
  );
}

// First setup commits MK and its first recovery together, with any new
// resource keys; a manual recovery key is saved in this browser first.
export function SetupKeys(props: {
  session: Session;
  manager: PasskeyKeyManager;
  resources?: () => MKResource[];
  onDone: (file?: keys.RecoveryFile) => void;
}) {
  const action = useAction(props.session, props.manager);
  const setup = (method: keys.RecoveryMethod) =>
    action.run(async (scope, signal) => {
      const state = scope.keyState();
      if (!state || !scope.user)
        throw new Error("Your account is still loading.");
      const { unlocked, file } = await keys.setupMK({
        api: scope.api,
        manager: props.manager,
        user_id: scope.user,
        state,
        method,
        resources: props.resources?.() ?? [],
        signal,
        fence: await scope.fence,
      });
      // The next step is chosen before the keys open, so nothing that waits
      // on open keys shows in between.
      props.onDone(file);
      await scope.setUnlocked(unlocked);
      void props.session.refresh();
    });
  return (
    <PasskeyChoice
      action={action}
      onPasskey={() => void setup("passkey")}
      onSkip={() => void setup("manual")}
    />
  );
}

function PasskeyChoice(props: {
  action: ReturnType<typeof useAction>;
  onPasskey: () => void;
  onSkip: () => void;
}) {
  return (
    <AuthCard icon={<Icon name="key" />} title="Passkey">
      <p>
        Use your fingerprint, face, screen lock, or a security key to open your
        bunker keys on any device.
      </p>
      <Show when={props.action.error()}>
        <p role="alert">{props.action.error()}</p>
      </Show>
      <button
        class="primary"
        disabled={props.action.busy()}
        aria-busy={props.action.busy()}
        onClick={() => props.onPasskey()}
      >
        <Icon name="fingerprint" />
        {props.action.busy()
          ? "Follow your device's prompt…"
          : "Set up a passkey"}
      </button>
      <Show when={props.action.busy()}>
        <p class="auth-help" role="status">
          Your browser may ask you to confirm twice. A security key needs a
          second touch.
        </p>
      </Show>
      <button
        class="link"
        disabled={props.action.busy()}
        onClick={() => props.onSkip()}
      >
        Save a recovery key file instead
      </button>
    </AuthCard>
  );
}

const addPasskey = (
  session: Session,
  manager: PasskeyKeyManager,
  action: ReturnType<typeof useAction>,
  onAdded?: () => void,
) =>
  action.run(async (scope, signal) => {
    const { unlocked } = await keys.addRecovery({
      api: scope.api,
      manager,
      unlocked: scope.unlocked()!,
      method: "passkey",
      signal,
      fence: await scope.fence,
    });
    await scope.setUnlocked(unlocked);
    await session.refresh();
    onAdded?.();
  });

export function AddPasskey(props: {
  session: Session;
  manager: PasskeyKeyManager;
  onContinue: () => void;
}) {
  const action = useAction(props.session, props.manager);
  const [recovery, setRecovery] = createSignal<keys.RecoveryFile>();
  // Without a passkey, this browser's recovery key is saved before going on;
  // keys opened from a file need nothing more.
  const skip = () =>
    action.run(async (scope) => {
      const state = scope.keyState();
      const file = state && (await keys.savedRecoveryFile(state, scope.user));
      if (file) setRecovery(file);
      else props.onContinue();
    });
  return (
    <Show
      when={recovery()}
      fallback={
        <PasskeyChoice
          action={action}
          onPasskey={() =>
            void addPasskey(
              props.session,
              props.manager,
              action,
              props.onContinue,
            )
          }
          onSkip={() => void skip()}
        />
      }
    >
      {(file) => (
        <RecoveryDownload
          file={file()}
          onContinue={props.onContinue}
          onBack={() => setRecovery()}
        />
      )}
    </Show>
  );
}

export function UnlockKeys(props: {
  session: Session;
  manager: PasskeyKeyManager;
}) {
  const action = useAction(props.session, props.manager);
  const state = () => props.session.keyState().value!;
  const hasPasskey = () => state().recovery.some((r) => r.type === "passkey");
  const [noPasskey, setNoPasskey] = createSignal(false);
  const [confirming, setConfirming] = createSignal(false);
  let picker!: HTMLInputElement;
  const unlock = (
    task: (
      state: keys.KeyState,
      user: string,
      signal: AbortSignal,
    ) => Promise<keys.Unlocked | undefined>,
  ) =>
    action.run(async (scope, signal) => {
      const current = scope.keyState();
      if (!current) throw new Error("Your account is still loading.");
      const unlocked = await task(current, scope.user, signal);
      if (!unlocked)
        throw new Error("No recovery key is saved in this browser.");
      await scope.setUnlocked(unlocked);
    });
  const startOver = () =>
    action.run(async (scope, signal) => {
      const current = scope.keyState();
      if (!current) throw new Error("Your account is still loading.");
      await keys.resetKeyState(scope.api, current, signal);
      await props.session.refresh();
    });
  // A recovery key saved in this browser opens without a prompt, so the
  // choices wait until it has been tried.
  const [checking, setChecking] = createSignal(true);
  void action
    .run(async (scope) => {
      const current = scope.keyState();
      const unlocked = current && (await keys.unlockSaved(current, scope.user));
      if (unlocked) await scope.setUnlocked(unlocked);
    })
    .finally(() => setChecking(false));
  const error = () => (
    <Show when={action.error()}>
      <p role="alert">{action.error()}</p>
    </Show>
  );
  return (
    <Show
      when={!checking()}
      fallback={<AuthCardSkeleton label="Opening your keys…" />}
    >
      <Show
        when={!confirming()}
        fallback={
          <AuthCard icon={<Icon name="warning" />} title="Start over?">
            <p>
              <strong>You will lose your bunkers.</strong> Starting over makes
              new keys. Bunkers and Perimeters that use your current keys can't
              be opened again, and their data can't be recovered. CLI keys you
              added stay.
            </p>
            {error()}
            <button
              class="danger"
              disabled={action.busy()}
              aria-busy={action.busy()}
              onClick={() => void startOver()}
            >
              Yes, start over
            </button>
            <button
              disabled={action.busy()}
              onClick={() => setConfirming(false)}
            >
              Go back
            </button>
          </AuthCard>
        }
      >
        <Show
          when={hasPasskey() && !noPasskey()}
          fallback={
            <>
              <AuthCard icon={<Icon name="document" />} title="Recovery key">
                <p>
                  Choose the recovery key file you saved when you set up your
                  keys.
                </p>
                {error()}
                <input
                  ref={picker}
                  class="start-file"
                  type="file"
                  accept=".txt,text/plain"
                  onChange={(event) => {
                    const file = event.currentTarget.files?.[0];
                    event.currentTarget.value = "";
                    if (file)
                      void unlock(async (current, user) => {
                        if (file.size > MAX_RECOVERY_FILE_BYTES)
                          throw new Error(
                            "This file is too large to be a recovery key.",
                          );
                        return keys.unlockFile(
                          await file.text(),
                          current,
                          user,
                        );
                      });
                  }}
                />
                <button
                  class="primary"
                  disabled={action.busy()}
                  aria-busy={action.busy()}
                  onClick={() => picker.click()}
                >
                  {action.busy() ? "Unlocking…" : "Choose recovery key file"}
                </button>
                <Show when={hasPasskey()}>
                  <button
                    class="link"
                    disabled={action.busy()}
                    onClick={() => setNoPasskey(false)}
                  >
                    Use a passkey instead
                  </button>
                </Show>
                <button
                  class="link"
                  disabled={action.busy()}
                  onClick={() => setConfirming(true)}
                >
                  I lost my recovery key
                </button>
              </AuthCard>
            </>
          }
        >
          <AuthCard icon={<Icon name="lock" />} title="Passkey">
            <p>
              When you're ready, unlock with your fingerprint, face, screen
              lock, or security key.
            </p>
            {error()}
            <button
              class="primary"
              disabled={action.busy()}
              aria-busy={action.busy()}
              onClick={() =>
                void unlock((current, user, signal) =>
                  keys.unlockPasskey(props.manager, current, user, signal),
                )
              }
            >
              <Icon name="fingerprint" />
              {action.busy() ? "Unlocking…" : "Unlock with passkey"}
            </button>
            <button
              class="link"
              disabled={action.busy()}
              onClick={() => setNoPasskey(true)}
            >
              Use your recovery key file
            </button>
          </AuthCard>
        </Show>
      </Show>
    </Show>
  );
}

// After a first passkey, offers a recovery key file once: it is the only
// other way in if the passkey is lost. Nothing is made unless it is downloaded.
export function OfferRecovery(props: {
  session: Session;
  manager: PasskeyKeyManager;
  onDone: () => void;
}) {
  const action = useAction(props.session, props.manager);
  const [file, setFile] = createSignal<keys.RecoveryFile>();
  const save = () =>
    action.run(async (scope, signal) => {
      let saved = file();
      if (!saved) {
        const result = await keys.addRecovery({
          api: scope.api,
          manager: props.manager,
          unlocked: scope.unlocked()!,
          method: "manual",
          signal,
          fence: await scope.fence,
        });
        await scope.setUnlocked(result.unlocked);
        saved = result.file!;
        setFile(saved);
        void props.session.refresh();
      }
      download(saved.text, saved.filename, "text/plain");
    });
  return (
    <AuthCard icon={<Icon name="key" />} title="Recovery key">
      <p>
        If you lose your passkey, this file is the only other way to open your
        bunkers.
      </p>
      <Show when={action.error()}>
        <p role="alert">{action.error()}</p>
      </Show>
      <button
        classList={{ primary: !file() }}
        disabled={action.busy()}
        aria-busy={action.busy()}
        onClick={() => void save()}
      >
        <Icon name="download" />
        {file() ? "Download recovery key again" : "Download recovery key"}
      </button>
      <Show
        when={file()}
        fallback={
          <button
            class="link"
            disabled={action.busy()}
            onClick={() => props.onDone()}
          >
            Skip for now
          </button>
        }
      >
        <button class="primary" onClick={() => props.onDone()}>
          Continue
        </button>
      </Show>
    </AuthCard>
  );
}

export function RecoveryMethods(props: {
  session: Session;
  manager: PasskeyKeyManager;
}) {
  const action = useAction(props.session, props.manager);
  const state = () => props.session.keyState().value;
  const user = () => props.session.user()!.id;
  const [saved] = createResource(state, (s) =>
    keys.savedRecoveryFile(s, user()),
  );
  const replaces = () =>
    !saved() && !!state()?.recovery.some((r) => r.type === "manual");
  // Saves this browser's recovery key, or makes one that replaces any other.
  const save = () =>
    action.run(async (scope, signal) => {
      let file = saved.error ? undefined : saved();
      if (!file) {
        const result = await keys.addRecovery({
          api: scope.api,
          manager: props.manager,
          unlocked: scope.unlocked()!,
          method: "manual",
          signal,
          fence: await scope.fence,
        });
        await scope.setUnlocked(result.unlocked);
        file = result.file!;
        await props.session.refresh();
      }
      download(file.text, file.filename, "text/plain");
    });
  return (
    <>
      <For each={state()?.recovery ?? []}>
        {(r) => (
          <div class="start-key-choice">
            <Icon name={r.type === "passkey" ? "fingerprint" : "key"} />
            <div>
              <h2>{r.type === "passkey" ? "Passkey" : "Recovery key"}</h2>
              <p>Added {new Date(r.created_at).toLocaleDateString()}</p>
            </div>
            <Show when={(state()?.recovery.length ?? 0) > 1}>
              <button
                class="link"
                disabled={action.busy()}
                onClick={() =>
                  void action.run(async (scope, signal) => {
                    await scope.setUnlocked(
                      await keys.removeRecovery(
                        scope.api,
                        scope.unlocked()!,
                        r.recovery_id,
                        signal,
                      ),
                    );
                    await props.session.refresh();
                  })
                }
              >
                Remove
              </button>
            </Show>
          </div>
        )}
      </For>
      <Show when={action.error() || saved.error}>
        <p class="start-notice" role="alert">
          {action.error() || message(saved.error)}
        </p>
      </Show>
      <div class="monitor-actions">
        <button
          disabled={action.busy()}
          onClick={() => void addPasskey(props.session, props.manager, action)}
        >
          Add a passkey
        </button>
        <button disabled={action.busy()} onClick={() => void save()}>
          <Icon name="download" /> Save recovery key
        </button>
      </div>
      <Show when={replaces()}>
        <p class="start-help">
          This browser doesn't have your recovery key, so saving makes a new one
          and the old file stops working.
        </p>
      </Show>
    </>
  );
}

// Stands in for its page, showing setup to new users and unlock to returning
// ones, until the user's keys are open in memory.
export function KeyGate(props: {
  session: Session;
  manager: PasskeyKeyManager;
  purpose?: string;
  children: JSX.Element;
}) {
  const [file, setFile] = createSignal<keys.RecoveryFile>();
  const [offer, setOffer] = createSignal(false);
  const read = () => props.session.keyState();
  const purpose = () => props.purpose ?? "open your bunkers";
  return (
    <Show
      when={props.session.unlocked() && !file() && !offer()}
      fallback={
        <Show
          when={read().value}
          fallback={
            <Show
              when={read().error}
              fallback={
                <AuthScreen>
                  <AuthCardSkeleton label="Loading your keys…" />
                </AuthScreen>
              }
            >
              <AuthScreen title="Could not load your keys">
                <AuthCard icon={<Icon name="warning" />}>
                  <p role="alert">{read().error}</p>
                  <button
                    class="primary"
                    onClick={() => void props.session.refresh()}
                  >
                    Try again
                  </button>
                </AuthCard>
              </AuthScreen>
            </Show>
          }
        >
          {(state) => (
            <Switch>
              <Match when={offer()}>
                <AuthScreen title="Save a recovery key">
                  <OfferRecovery
                    session={props.session}
                    manager={props.manager}
                    onDone={() => setOffer(false)}
                  />
                </AuthScreen>
              </Match>
              <Match when={file()}>
                {(recovery) => (
                  <AuthScreen title="Save your recovery key">
                    <RecoveryDownload
                      file={recovery()}
                      onContinue={() => setFile()}
                    />
                  </AuthScreen>
                )}
              </Match>
              <Match when={!state().dek_id}>
                <AuthScreen
                  title="Set up your keys"
                  description={`Your keys ${purpose()}. They're encrypted with your account, so only you can open them.`}
                >
                  <SetupKeys
                    session={props.session}
                    manager={props.manager}
                    onDone={(saved) =>
                      saved ? setFile(saved) : setOffer(true)
                    }
                  />
                </AuthScreen>
              </Match>
              <Match when={state().dek_id}>
                <AuthScreen
                  title="Unlock your keys"
                  description={`You need them to ${purpose()}.`}
                >
                  <UnlockKeys session={props.session} manager={props.manager} />
                </AuthScreen>
              </Match>
            </Switch>
          )}
        </Show>
      }
    >
      {props.children}
    </Show>
  );
}
