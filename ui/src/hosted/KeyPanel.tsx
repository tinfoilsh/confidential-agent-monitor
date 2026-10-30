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

export function RecoveryDownload(props: { file: keys.RecoveryFile }) {
  const [saved, setSaved] = createSignal(false);
  return (
    <div class="start-key-choice">
      <Icon name="devices" />
      <div>
        <h2>Save your recovery key</h2>
        <p>
          It opens your sandboxes if you lose your passkey or switch browsers.
          This browser keeps a copy until you sign out.
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
    <>
      <div class="start-key-choice">
        <Icon name="rules" />
        <div>
          <h2>Protect your sandbox keys</h2>
          <p>
            Your keys are encrypted in this browser. Use a passkey or a recovery
            key file to open them anywhere.
          </p>
        </div>
      </div>
      <Show when={action.error()}>
        <p class="start-notice" role="alert">
          {action.error()}
        </p>
      </Show>
      <button
        class="primary start-continue"
        disabled={action.busy()}
        aria-busy={action.busy()}
        onClick={() => void setup("passkey")}
      >
        {action.busy() ? "Follow your device's prompt…" : "Use a passkey"}
      </button>
      <button
        class="link start-alternative"
        disabled={action.busy()}
        onClick={() => void setup("manual")}
      >
        Use a recovery key file instead
      </button>
    </>
  );
}

export function UnlockKeys(props: {
  session: Session;
  manager: PasskeyKeyManager;
}) {
  const action = useAction(props.session, props.manager);
  const state = () => props.session.keyState().value!;
  const hasPasskey = () => state().recovery.some((r) => r.type === "passkey");
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
      <Show when={hasPasskey()}>
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
      </Show>
      <label class="start-help">
        Recovery key file
        <input
          type="file"
          accept=".txt,text/plain"
          disabled={action.busy()}
          onChange={(event) => {
            const file = event.currentTarget.files?.[0];
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
      </label>
    </>
  );
}

export function RecoveryMethods(props: {
  session: Session;
  manager: PasskeyKeyManager;
}) {
  const action = useAction(props.session, props.manager);
  const [file, setFile] = createSignal<keys.RecoveryFile>();
  const state = () => props.session.keyState().value;
  const user = () => props.session.user()!.id;
  const [saved] = createResource(state, (s) =>
    keys.savedRecoveryFile(s, user()),
  );
  const add = (method: keys.RecoveryMethod) =>
    action.run(async (scope, signal) => {
      const result = await keys.addRecovery({
        api: scope.api,
        manager: props.manager,
        unlocked: scope.unlocked()!,
        method,
        signal,
        fence: await scope.fence,
      });
      await scope.setUnlocked(result.unlocked);
      setFile(result.file);
      await props.session.refresh();
    });
  return (
    <section class="start-monitors" aria-label="Recovery methods">
      <p class="start-eyebrow">Recovery methods</p>
      <For each={state()?.recovery ?? []}>
        {(r) => (
          <div class="start-key-choice">
            <Icon name={r.type === "passkey" ? "rules" : "devices"} />
            <div>
              <h2>{r.type === "passkey" ? "Passkey" : "Recovery key file"}</h2>
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
      <Show when={file() ?? (saved.error ? undefined : saved())}>
        {(recovery) => <RecoveryDownload file={recovery()} />}
      </Show>
      <div class="monitor-actions">
        <button disabled={action.busy()} onClick={() => void add("passkey")}>
          Add a passkey
        </button>
        <button disabled={action.busy()} onClick={() => void add("manual")}>
          Add a recovery key file
        </button>
      </div>
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
                <>
                  <RecoveryDownload file={recovery()} />
                  <button
                    class="primary start-continue"
                    onClick={() => setFile()}
                  >
                    Continue
                  </button>
                </>
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
