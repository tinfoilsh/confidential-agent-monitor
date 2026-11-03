import type { Clerk } from "@clerk/clerk-js/no-rhc";
import { createSignal } from "solid-js";
import { createStore, reconcile } from "solid-js/store";
import * as keys from "./keys";

export const MONITOR_REPO = "tinfoilsh/confidential-agent-monitor";
export const SANDBOX_REPO = "tinfoilsh/confidential-agent-sandbox";
const REFRESH_MS = 30_000;
const SIGN_OUT_CHANNEL = "tinfoil.manual-kek";
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;

export type Container = {
  id: string;
  name: string;
  repo: string;
  status: string;
  domain: string;
  debug?: boolean;
  clerk_user_id?: string | null;
  owner_key_mode: "tmk" | "umk" | null;
  owner_public_key: string | null;
  config?: string;
  current_tag?: string;
  cpus?: number;
  memory_mb?: number | null;
  created_at?: string;
  volumes?: Record<string, string>;
  network_policy?: { egress?: { container_id: string }[] } | null;
};

// A malformed Monitor or sandbox row makes the list unavailable, never shorter.
function containers(value: unknown): Container[] {
  const unreadable = new Error("The resource list could not be read.");
  if (!Array.isArray(value)) throw unreadable;
  const rows = value.filter(
    (row) => row?.repo === MONITOR_REPO || row?.repo === SANDBOX_REPO,
  ) as Container[];
  for (const row of rows)
    if (
      !UUID.test(row.id) ||
      typeof row.name !== "string" ||
      typeof row.status !== "string" ||
      typeof row.domain !== "string" ||
      !["tmk", "umk", null].includes(row.owner_key_mode ?? null) ||
      !["string", "undefined"].includes(
        typeof (row.owner_public_key ?? undefined),
      )
    )
      throw unreadable;
  return rows.filter((row) => !row.debug);
}

export const monitorOf = (sandbox: Container) =>
  sandbox.network_policy?.egress?.[0]?.container_id;

type Read<T> = { value?: T; error?: string; loading?: boolean };
const message = (cause: unknown) =>
  cause instanceof Error ? cause.message : String(cause);

// Key state is scoped by API and user, inventory also by the selected account.
// Changing either cancels and discards earlier reads and forgets unlocked keys.
export function createSession(clerk: Clerk) {
  const [user, setUser] = createSignal<{ id: string; label: string }>();
  const [account, setAccount] = createSignal("");
  const [keyState, setKeyState] = createSignal<Read<keys.KeyState>>({});
  // Reads change rows in place, so unchanged rows keep their identity.
  const [rows, setRows] = createStore<Read<Container[]>>({});
  const inventory = () => rows;
  const [unlocked, setUnlocked] = createSignal<keys.Unlocked>();
  let scope = new AbortController();
  let writes: Promise<unknown> = Promise.resolve();
  // Set while a sign-out is settled and confirmed; no new key action starts then.
  let signingOut: AbortController | undefined;
  // This sign-in's record-write fence: refused once a sign-out in any tab ends it.
  let sid = "";
  let fence = Promise.resolve<keys.KekFence>({ epoch: "", session: "" });
  // Set once storage shows that a sign-out ended this sign-in.
  let ended = false;
  const ENDED = "You signed out in another tab. Sign in again to continue.";
  const fenced = new AbortController();
  fenced.abort();
  let inflight: { scope: AbortController; done: Promise<void> } | undefined;

  async function request(
    path: string,
    who: { user?: string; account: string },
    init: Parameters<keys.Api>[1] = {},
  ): Promise<unknown> {
    const token = await clerk.session?.getToken();
    init.signal?.throwIfAborted();
    // The token must still belong to the user and account the request was made for.
    if (
      !token ||
      clerk.user?.id !== who.user ||
      (clerk.organization?.id ?? "personal") !== who.account
    )
      throw new keys.ApiError(401, {
        error: "Your account changed. Try again.",
      });
    const response = await fetch(keys.TARGETS.api_origin + path, {
      method: init.method ?? "GET",
      signal: init.signal,
      cache: "no-store",
      credentials: "omit",
      redirect: "error",
      headers: {
        Authorization: `Bearer ${token}`,
        ...(init.body !== undefined && { "Content-Type": "application/json" }),
      },
      body: init.body === undefined ? undefined : JSON.stringify(init.body),
    });
    const text = await response.text();
    let value: unknown = null;
    try {
      value = text ? JSON.parse(text) : null;
    } catch {
      if (response.ok)
        throw new Error("The service returned an unreadable response.");
    }
    if (!response.ok)
      throw new keys.ApiError(response.status, value as keys.ApiError["body"]);
    return value;
  }
  const scoped = (current: AbortController): keys.Api => {
    const who = { user: user()?.id, account: account() };
    return (path, init = {}) =>
      request(path, who, {
        ...init,
        signal: init.signal
          ? AbortSignal.any([current.signal, init.signal])
          : current.signal,
      });
  };

  // A new Clerk session is a new sign-in even for the same user and account.
  function sync() {
    const id = clerk.user?.id;
    const next = clerk.organization?.id ?? "personal";
    const session = clerk.session?.id ?? "";
    if (id === user()?.id && next === account() && session === sid) return;
    scope.abort();
    scope = new AbortController();
    signingOut = undefined;
    // An account switch stays in the same sign-in and keeps its fence.
    if (id !== user()?.id || session !== sid) {
      sid = session;
      ended = false;
      fence = id
        ? keys.kekFence(keys.TARGETS.api_origin!, id, session)
        : Promise.resolve({ epoch: "", session: "" });
      fence.catch(() => {});
    }
    if (id !== user()?.id) setKeyState({});
    setUser(
      id
        ? {
            id,
            label:
              clerk.user?.primaryEmailAddress?.emailAddress ??
              clerk.user?.username ??
              id,
          }
        : undefined,
    );
    setAccount(next);
    setRows(reconcile({}));
    setUnlocked(undefined);
    if (id) void refresh();
  }

  async function read(current: AbortController) {
    const id = user()?.id;
    if (!id) return;
    const api = scoped(current);
    const live = () => current === scope && !current.signal.aborted;
    const sign_in = fence;
    setKeyState((state) => ({ ...state, error: undefined, loading: true }));
    setRows("error", undefined);
    setRows("loading", true);
    // A sign-in ended elsewhere (even across a reload) neither reads nor reconciles keys.
    await Promise.all([
      checkEnded()
        .then(async (over) => {
          if (over) throw new Error(ENDED);
          const state = await keys.readKeyState(api);
          return keys.reconcilePending(
            api,
            id,
            state,
            await sign_in,
            current.signal,
          );
        })
        .then(async (state) => {
          const next = await keys.refreshUnlocked(unlocked(), state);
          if (!live()) return;
          setKeyState({ value: state, loading: false });
          setUnlocked(next);
        })
        .catch((cause) => {
          if (live())
            setKeyState((s) => ({
              ...s,
              error: ended ? ENDED : message(cause),
              loading: false,
            }));
        }),
      api("/api/containers")
        .then(containers)
        .then(
          (value) => live() && setRows(reconcile({ value, loading: false })),
        )
        .catch((cause) => {
          if (live()) setRows({ error: message(cause), loading: false });
        }),
    ]);
  }

  // Joins a read already running for the same account.
  function refresh() {
    if (inflight?.scope !== scope) {
      const current = scope;
      const done = read(current).finally(() => {
        if (inflight?.scope === current) inflight = undefined;
      });
      inflight = { scope: current, done };
    }
    return inflight.done;
  }

  // The one MK write path, serialized; an uncertain write stays pending on the unlocked keys.
  function write(current: AbortController, delta: keys.Delta) {
    const next = writes.then(async () => {
      const u = unlocked();
      if (!u || current !== scope) throw new Error("Unlock your keys first.");
      const updated = await keys.updateMK(scoped(current), u, delta);
      if (current === scope) setUnlocked(updated);
      return updated;
    });
    writes = next.catch(() => {});
    return next;
  }

  // One operation fixed to the user and account it started in: a switch or
  // sign-out cancels its requests and discards its results.
  // A tab whose sign-in is known to have ended, or one preparing its own
  // sign-out, starts no key action; storage refuses the writes of any other.
  function bind() {
    const current = signingOut || ended ? fenced : scope;
    const live = () => current === scope && !current.signal.aborted;
    const gone = () => new Error("Your account changed. Start again.");
    return {
      user: user()?.id ?? "",
      fence,
      account: account(),
      api: scoped(current),
      signal: current.signal,
      live,
      unlocked: () => (live() ? unlocked() : undefined),
      keyState: () => (live() ? keyState().value : undefined),
      // A late result is accepted only while storage still shows this sign-in.
      async setUnlocked(u: keys.Unlocked | undefined) {
        if (!live() || (await checkEnded()) || !live()) throw gone();
        setUnlocked(u);
      },
      update: (delta: keys.Delta) => write(current, delta),
      // A successful read of this account's resources; a failed one is never reused.
      async fresh() {
        if (!live()) throw gone();
        await refresh();
        if (!live()) throw gone();
        const read = inventory();
        if (read.error || !read.value)
          throw new Error("Your resources could not be refreshed. Try again.");
        return read.value;
      },
    };
  }

  // Once a sign-out in any tab has ended this sign-in, drops unlocked keys and
  // cancels running key actions; the fence already refuses their writes.
  async function checkEnded() {
    const id = user()?.id;
    const current = fence;
    if (!id || ended) return ended;
    const over = await keys.fenceEnded(
      keys.TARGETS.api_origin!,
      id,
      await current,
    );
    if (!over || current !== fence || ended) return ended;
    ended = true;
    scope.abort();
    scope = new AbortController();
    setUnlocked(undefined);
    setKeyState({ error: ENDED });
    void refresh();
    return true;
  }
  // Only a hint to check sooner; storage alone decides.
  const channel = new BroadcastChannel(SIGN_OUT_CHANNEL);
  channel.onmessage = () => void checkEnded().catch(() => {});
  // Staying signed in resumes normal operation with a fresh scope.
  function cancelLogout() {
    if (!signingOut) return;
    signingOut = undefined;
    scope.abort();
    scope = new AbortController();
    void refresh();
  }
  const stop = clerk.addListener(sync);
  const onFocus = () => void refresh();
  const onVisible = () => document.visibilityState === "visible" && refresh();
  addEventListener("focus", onFocus);
  addEventListener("online", onFocus);
  document.addEventListener("visibilitychange", onVisible);
  const timer = setInterval(onVisible, REFRESH_MS);
  sync();

  return {
    user,
    account,
    keyState,
    inventory,
    unlocked,
    setUnlocked,
    refresh,
    bind,
    signIn: () =>
      clerk.redirectToSignIn({ signInForceRedirectUrl: location.href }),
    // The CLI's validated grant selects this account explicitly.
    activate: (next: string) =>
      clerk.setActive({ organization: next === "personal" ? null : next }),
    // Cancels running key actions and admits none, then settles this user's
    // pending recovery commits and gathers the recovery files to offer. The
    // result stays valid only for this sign-out; logout() then deletes every
    // cached KEK. A sign-out abandoned by an account change returns not live.
    async prepareLogout() {
      scope.abort();
      const current = (scope = signingOut = new AbortController());
      const live = () => current === scope && signingOut === current;
      const id = user()?.id;
      const none = { files: [], unresolved: false, covered: new Map() };
      const settled = await (
        id
          ? fence.then((f) =>
              keys.settlePending(scoped(current), id, f, current.signal),
            )
          : Promise.resolve(none)
      ).catch((cause) => {
        if (!live()) return none;
        cancelLogout();
        throw cause;
      });
      return { ...(live() ? settled : none), live };
    },
    cancelLogout,
    // Completes only the sign-out prepared in this scope, and only while the
    // records are those it offered; false means prepare and offer again.
    async logout(
      prepared:
        { live(): boolean; covered: ReadonlyMap<string, string> } | undefined,
    ) {
      const id = user()?.id;
      if (
        !prepared?.live() ||
        (id &&
          !(await keys.forgetManualKEKs(
            keys.TARGETS.api_origin!,
            id,
            await fence,
            prepared.covered,
            prepared.live,
          )))
      )
        return false;
      // The wipe stands, but a user or account that replaced this one while it
      // committed is not this sign-out's to end.
      if (!prepared.live()) return false;
      try {
        channel.postMessage(null);
      } catch {}
      signingOut = undefined;
      scope.abort();
      setUnlocked(undefined);
      await clerk.signOut({ redirectUrl: "/" });
      return true;
    },
    dispose() {
      stop();
      scope.abort();
      clearInterval(timer);
      channel.close();
      removeEventListener("focus", onFocus);
      removeEventListener("online", onFocus);
      document.removeEventListener("visibilitychange", onVisible);
    },
  };
}

export type Session = ReturnType<typeof createSession>;
export type Scope = ReturnType<Session["bind"]>;
