import type { PasskeyKeyManager } from "@tinfoilsh/passkey-kit";
import {
  For,
  Show,
  createResource,
  createSignal,
  onCleanup,
  type JSX,
} from "solid-js";
import { download, Icon } from "../components";
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
}) {
  const [saved, setSaved] = createSignal(false);
  return (
    <>
      <div class="start-key-choice">
        <Icon name="devices" />
        <div>
          <h2>Save your recovery key</h2>
          <p>
            It opens your sandboxes after you sign out or switch browsers. This
            browser keeps a copy only until you sign out.
          </p>
          <button
            class="start-download"
            classList={{ primary: !saved() }}
            onClick={() => {
              download(props.file.text, props.file.filename, "text/plain");
              setSaved(true);
            }}
          >
            <Icon name="download" />{" "}
            {saved() ? "Download recovery key again" : "Download recovery key"}
          </button>
        </div>
      </div>
      <Show when={props.onContinue}>
        {(next) => (
          <button
            class="primary start-continue"
            disabled={!saved()}
            onClick={() => next()()}
          >
            Continue <Icon name="arrow" />
          </button>
        )}
      </Show>
    </>
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
      await scope.setUnlocked(unlocked);
      void props.session.refresh();
      props.onDone(file);
    });
  return (
    <PasskeyChoice
      action={action}
      onPasskey={() => void setup("passkey")}
      onSkip={() => void setup("manual")}
    />
  );
}

// Leads with a passkey; the alternative goes on without one.
function PasskeyChoice(props: {
  action: ReturnType<typeof useAction>;
  onPasskey: () => void;
  onSkip: () => void;
}) {
  return (
    <>
      <div class="start-key-choice">
        <Icon name="rules" />
        <div>
          <h2>A passkey makes it easy</h2>
          <p>
            Use your fingerprint, face, screen lock, or a security key to open
            your sandbox keys on any device.
          </p>
        </div>
      </div>
      <Show when={props.action.error()}>
        <p class="start-notice" role="alert">
          {props.action.error()}
        </p>
      </Show>
      <button
        class="primary start-continue"
        disabled={props.action.busy()}
        aria-busy={props.action.busy()}
        onClick={() => props.onPasskey()}
      >
        {props.action.busy() ? (
          "Follow your device's prompt…"
        ) : (
          <>
            Create a passkey <Icon name="arrow" />
          </>
        )}
      </button>
      <button
        class="link start-alternative"
        disabled={props.action.busy()}
        onClick={() => props.onSkip()}
      >
        I don't have a passkey
      </button>
      <Show when={props.action.busy()}>
        <p class="start-help" role="status">
          Your browser may ask you to confirm twice. A security key needs a
          second touch.
        </p>
      </Show>
    </>
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

// Offers a passkey to keys that open only with a recovery key, then continues either way.
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
        <RecoveryDownload file={file()} onContinue={props.onContinue} />
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
  const usePasskey = () => hasPasskey() && !noPasskey();
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
  // A recovery key saved in this browser opens without a prompt.
  void action.run(async (scope) => {
    const current = scope.keyState();
    const unlocked = current && (await keys.unlockSaved(current, scope.user));
    if (unlocked) await scope.setUnlocked(unlocked);
  });
  return (
    <>
      <Show when={action.error()}>
        <p class="start-notice" role="alert">
          {action.error()}
        </p>
      </Show>
      <Show
        when={!confirming()}
        fallback={
          <>
            <p class="start-notice" role="alert">
              <strong>You will lose your sandboxes.</strong> Starting over makes
              new keys. Sandboxes and Monitors that use your current keys can't
              be opened again, and their data can't be recovered. CLI keys you
              added stay.
            </p>
            <button
              class="danger start-continue"
              disabled={action.busy()}
              aria-busy={action.busy()}
              onClick={() => void startOver()}
            >
              Yes, start over
            </button>
            <button
              class="link start-alternative"
              disabled={action.busy()}
              onClick={() => setConfirming(false)}
            >
              Go back
            </button>
          </>
        }
      >
        <div class="start-key-choice">
          <Icon name="rules" />
          <div>
            <h2>Unlock your keys</h2>
            <p>
              {usePasskey()
                ? "Use your passkey to open your sandbox keys in this browser."
                : "Choose the recovery key file you saved when you set up your keys."}
            </p>
          </div>
        </div>
        <Show
          when={usePasskey()}
          fallback={
            <>
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
                      return keys.unlockFile(await file.text(), current, user);
                    });
                }}
              />
              <button
                class="primary start-continue"
                disabled={action.busy()}
                aria-busy={action.busy()}
                onClick={() => picker.click()}
              >
                {action.busy() ? "Unlocking…" : "Choose recovery key file"}
              </button>
              <p class="start-help">
                Lost your recovery key?{" "}
                <button
                  class="link"
                  disabled={action.busy()}
                  onClick={() => setConfirming(true)}
                >
                  Start over
                </button>
              </p>
            </>
          }
        >
          <button
            class="primary start-continue"
            disabled={action.busy()}
            aria-busy={action.busy()}
            onClick={() =>
              void unlock((current, user, signal) =>
                keys.unlockPasskey(props.manager, current, user, signal),
              )
            }
          >
            {action.busy() ? "Unlocking…" : "Unlock with passkey"}
          </button>
          <button
            class="link start-alternative"
            disabled={action.busy()}
            onClick={() => setNoPasskey(true)}
          >
            I don't have a passkey
          </button>
        </Show>
      </Show>
    </>
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
    <section class="start-monitors" aria-label="Recovery methods">
      <p class="start-eyebrow">Recovery methods</p>
      <For each={state()?.recovery ?? []}>
        {(r) => (
          <div class="start-key-choice">
            <Icon name={r.type === "passkey" ? "rules" : "devices"} />
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
    </section>
  );
}

// Shows setup or unlock until the user's keys are open in memory.
export function KeyGate(props: {
  session: Session;
  manager: PasskeyKeyManager;
  children: JSX.Element;
}) {
  const [file, setFile] = createSignal<keys.RecoveryFile>();
  const read = () => props.session.keyState();
  return (
    <Show
      when={props.session.unlocked() && !file()}
      fallback={
        <Show
          when={read().value}
          fallback={
            <p
              class={read().error ? "start-notice" : "start-help"}
              role="status"
            >
              {read().error
                ? `Your keys could not be read: ${read().error}`
                : "Checking your keys…"}
            </p>
          }
        >
          {(state) => (
            <Show
              when={file()}
              fallback={
                <Show
                  when={state().dek_id}
                  fallback={
                    <SetupKeys
                      session={props.session}
                      manager={props.manager}
                      onDone={setFile}
                    />
                  }
                >
                  <UnlockKeys session={props.session} manager={props.manager} />
                </Show>
              }
            >
              {(recovery) => (
                <RecoveryDownload
                  file={recovery()}
                  onContinue={() => setFile()}
                />
              )}
            </Show>
          )}
        </Show>
      }
    >
      {props.children}
    </Show>
  );
}
