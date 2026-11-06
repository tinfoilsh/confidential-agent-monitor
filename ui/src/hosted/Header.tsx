import {
  For,
  Show,
  createEffect,
  createSignal,
  createUniqueId,
  on,
} from "solid-js";
import { Icon, Modal } from "../components";
import * as keys from "./keys";
import { RecoveryDownload } from "./KeyPanel";
import type { Session } from "./session";

const OPENED_FROM = "from";
const HOME = "home";
const ACCOUNT_MENU_GAP = 8;

// A Monitor opened from the home page goes back there; one opened elsewhere, such
// as from the dashboard, goes back to the dashboard.
export const monitorURL = (id: string) =>
  `/monitor/${id}?${new URLSearchParams({ [OPENED_FROM]: HOME })}`;
export const openedFromHome = () =>
  new URLSearchParams(location.search).get(OPENED_FROM) === HOME;

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
  const menuId = createUniqueId();
  let trigger!: HTMLButtonElement;
  let menu!: HTMLDivElement;
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
            <button
              ref={trigger}
              class="account-trigger"
              popovertarget={menuId}
            >
              {user().label}
              <Icon name="arrow" />
            </button>
            <div
              ref={menu}
              id={menuId}
              class="account-menu"
              popover
              onBeforeToggle={(event) => {
                if (event.newState !== "open") return;
                const anchor = trigger.getBoundingClientRect();
                menu.style.top = `${anchor.bottom + ACCOUNT_MENU_GAP}px`;
                menu.style.right = `${innerWidth - anchor.right}px`;
              }}
            >
              <button
                disabled={busy()}
                onClick={() => {
                  menu.hidePopover();
                  void signOut();
                }}
              >
                Sign out
              </button>
            </div>
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
