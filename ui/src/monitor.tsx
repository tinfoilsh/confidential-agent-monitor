/* @refresh reload */
// Replace the owner session and its shared context together during development.
import {
  batch,
  createContext,
  createEffect,
  createMemo,
  createSignal,
  on,
  onCleanup,
  onMount,
  useContext,
  type JSX,
  type ParentProps,
} from "solid-js";
import { createStore, reconcile } from "solid-js/store";
import * as owner from "./owner.js";
import { createRequestLog } from "./requests";

const KEY = "monitor-owner-key",
  SESSION = "monitor-local-session",
  GENERATION = "monitor-generation",
  RETURN = "monitor-sign-in-return",
  DEVICE_POLL_MS = 2000,
  // A page served apart from its Monitor reaches the bearer owner API there.
  ENDPOINT: string | undefined =
    import.meta.env.VITE_MONITOR_ENDPOINT || undefined;

export type MonitorOptions = {
  monitorInfo?: { name: string };
  terminalHome?: string;
  // Hosted builds show their site header above the setup screens.
  header?: JSX.Element;
  client?: owner.OwnerApi;
  snapshot?: owner.Snapshot;
  // Hosted builds own sandbox signers; other builds have no browser shell.
  shell?: (name: string) => owner.ShellOpener | undefined;
  // Sandboxes routed here whose keys a hosted build holds, by the agent key
  // each would enroll; accepting one adds it to this Monitor.
  candidates?: () => { name: string; key: string }[];
  sandboxesLoading?: () => boolean;
  accept?: (name: string, restore: boolean) => Promise<void>;
  // Hosted builds mint a Tinfoil API key for the signed-in account.
  tinfoilApiKey?: () => Promise<string>;
};

function createMonitor(options: MonitorOptions) {
  const lifetime = new AbortController();
  const fragment = new URLSearchParams(location.hash.slice(1));
  if (fragment.has("session")) {
    sessionStorage.setItem(SESSION, fragment.get("session")!);
    history.replaceState(null, "", location.pathname + location.search);
  }
  // Set before mount: writes inside onMount would let refresh join a read the api effect then discards.
  const [mode, setMode] = createSignal<"bearer" | "ssh" | undefined>(
    ENDPOINT && !options.client ? "bearer" : undefined,
  );
  const [credential, setCredential] = createSignal(
    mode() ? (sessionStorage.getItem(KEY) ?? "") : "",
  );
  // Reads change the snapshot in place, so unchanged requests and settings keep their identity.
  const [store, setStore] = createStore<{ snapshot?: owner.Snapshot }>({
    snapshot: options.snapshot,
  });
  const snapshot = () => store.snapshot;
  const setSnapshot = (next?: owner.Snapshot) =>
    setStore("snapshot", reconcile(next));
  const [locked, setLocked] = createSignal(false);
  type PendingEdit = {
    source: owner.OwnerApi;
    task: (client: owner.OwnerApi) => Promise<owner.View | null | void>;
    update?: (state: owner.Snapshot) => void;
    text: string;
    from: string;
    to?: string;
    resolve: (saved: boolean) => void;
  };
  const [pending, setPending] = createSignal<PendingEdit[]>([]);
  const busy = () => pending().length > 0;
  const [loading, setLoading] = createSignal(false);
  const [error, setError] = createSignal("");
  const [notice, setNotice] = createSignal<{ text: string; path: string }>();
  const message = (path?: string) =>
    path === undefined || notice()?.path === path ? (notice()?.text ?? "") : "";
  const [now, setNow] = createSignal(Date.now());
  const [icons, setIcons] = createSignal<owner.IconManifest>({});
  // The sandbox whose shell is open beside the page.
  const [shell, setShell] = createSignal<string>();
  const [accepting, setAccepting] = createSignal<string>();
  // Sandboxes whose automatic accept failed; they wait for an explicit one.
  const [stalled, setStalled] = createSignal<string[]>([]);
  const [deviceSignIn, setDeviceSignIn] = createSignal<
    owner.DeviceSignIn & {
      title: string;
      preset: string;
      source: owner.OwnerApi;
    }
  >();
  // Keep request pagination when opening a request or switching Activity tabs.
  const [activity, setActivity] = createStore({
    scope: "",
    page: 0,
    anchor: 0,
  });
  const [searches, setSearches] = createStore<Record<string, string>>({});
  const search = (section: string) =>
    [
      () => searches[section] ?? "",
      (value: string) => setSearches(section, value),
    ] as const;
  const [dismissed, setDismissed] = createSignal<string[]>(
    (() => {
      try {
        const value = JSON.parse(
          localStorage.getItem("monitor-dismissed") ?? "[]",
        );
        return Array.isArray(value)
          ? value.filter((id) => typeof id === "string")
          : [];
      } catch {
        return [];
      }
    })(),
  );
  const dismiss = (id: string) => {
    setDismissed((ids) => [...new Set([...ids, id])]);
    localStorage.setItem("monitor-dismissed", JSON.stringify(dismissed()));
  };
  let toastTimer: ReturnType<typeof setTimeout>;
  let refreshing: Promise<void> | undefined,
    version = 0;

  const notify = (text: string, path = location.hash) => {
    if (lifetime.signal.aborted) return;
    setNotice({ text, path });
    clearTimeout(toastTimer);
    toastTimer = setTimeout(() => setNotice(undefined), 5000);
  };
  const report = (cause: unknown, path = location.hash) => {
    if (lifetime.signal.aborted) return;
    if ((cause as owner.OwnerError)?.status === 423) setLocked(true);
    const text = cause instanceof Error ? cause.message : String(cause);
    setError(text);
    notify(text, path);
  };
  const observe: typeof fetch = async (input, options) => {
    const signal = options?.signal
      ? AbortSignal.any([options.signal, lifetime.signal])
      : lifetime.signal;
    const response = await fetch(input, { ...options, signal });
    if (response.status === 401) {
      sessionStorage.removeItem(KEY);
      sessionStorage.removeItem(SESSION);
      setCredential("");
    }
    if (response.status === 423) setLocked(true);
    return response;
  };
  const api = createMemo(
    () =>
      options.client ??
      (!mode() || !credential()
        ? undefined
        : mode() === "ssh"
          ? owner.localOwnerClient({ token: credential(), fetch: observe })
          : owner.ownerClient({
              endpoint: ENDPOINT,
              key: credential(),
              fetch: observe,
            })),
  );
  const copySnapshot = (state: owner.Snapshot): owner.Snapshot => ({
    ...state,
    view: { ...state.view, labels: { ...state.view.labels } },
  });
  // Reapply pending edits over the confirmed snapshot, including after a failure.
  const projected = createMemo(() => {
    const confirmed = snapshot();
    if (!confirmed || !pending().length) return confirmed;
    const next = copySnapshot(confirmed);
    for (const edit of pending()) edit.update?.(next);
    return next;
  });
  const view = createMemo(() => projected()?.view);
  // Archived records continue past the live log, which the monitor caps and clears on restart.
  const [archived, setArchived] = createSignal<owner.RequestRecord[]>([]);
  const [older, setOlder] = createSignal<string | null>("");
  const [loadingOlder, setLoadingOlder] = createSignal(false);
  const loadOlder = async () => {
    setLoadingOlder(true);
    try {
      const page = await api()!.archive(older()!, lifetime.signal);
      batch(() => {
        setArchived([...archived(), ...page.records]);
        setOlder(page.next ?? null);
      });
    } catch (cause) {
      report(cause);
    } finally {
      setLoadingOlder(false);
    }
  };
  const requests = createMemo(() => [
    ...(projected()?.requests ?? []),
    ...archived(),
  ]);
  const {
    records,
    byId: recordsById,
    pendingCount,
  } = createRequestLog(requests, now);
  const proposals = createMemo(() =>
    records().filter(
      (r) => r.state === "pending" && owner.isConnectionProposalRecord(r),
    ),
  );
  const remember = (
    next: owner.View,
    requests = snapshot()?.requests ?? [],
  ) => {
    setLocked(false);
    if (!options.client)
      localStorage.setItem(
        GENERATION,
        String(
          Math.max(
            next.generation,
            Number(localStorage.getItem(GENERATION)) || 0,
          ),
        ),
      );
    setSnapshot({ view: next, requests });
    if (older() === "" && !loadingOlder()) void loadOlder();
  };

  // Polling and manual refresh share one read. An edit invalidates any older read.
  function refresh(): Promise<void> {
    if (busy() || !api()) return Promise.resolve();
    if (!refreshing) {
      setLoading(true);
      refreshing = (async () => {
        while (!busy() && api() && !lifetime.signal.aborted) {
          const source = api()!,
            revision = version;
          const next = await source.read(lifetime.signal);
          if (source !== api()) continue;
          if (revision !== version || lifetime.signal.aborted) return;
          remember(next.view, next.requests);
          setError("");
          return;
        }
      })()
        .catch(report)
        .finally(() => {
          refreshing = undefined;
          setLoading(false);
        });
    }
    return refreshing;
  }
  function perform(
    task: (client: owner.OwnerApi) => Promise<owner.View | null | void>,
    text = "",
    options: { update?: PendingEdit["update"]; to?: string } = {},
  ): Promise<boolean> {
    const source = api();
    if (!source || lifetime.signal.aborted) return Promise.resolve(false);
    return new Promise((resolve) => {
      // Validate the projection before putting it into reactive state.
      try {
        const current = projected();
        if (current) options.update?.(copySnapshot(current));
      } catch (cause) {
        report(cause);
        resolve(false);
        return;
      }
      const sending = busy();
      const item = {
        source,
        task,
        text,
        ...options,
        from: location.hash,
        resolve,
      };
      version++;
      setPending((items) => [...items, item]);
      if (item.to) location.hash = item.to;
      if (!sending) void flush();
    });
  }

  async function flush() {
    let needsRefresh = false,
      failed = false,
      message = "",
      messagePath = "";
    while (pending().length) {
      const item = pending()[0];
      let saved = false;
      try {
        if (item.source !== api() || lifetime.signal.aborted) continue;
        const result = await item.task(item.source);
        if (item.source !== api() || lifetime.signal.aborted) continue;
        batch(() => {
          if (result) remember(result);
          else {
            const confirmed = snapshot();
            if (confirmed && item.update) {
              const next = copySnapshot(confirmed);
              item.update(next);
              setSnapshot(next);
            }
            needsRefresh = true;
          }
          setPending((items) => items.slice(1));
        });
        saved = true;
        message = item.text;
        messagePath = item.to ?? item.from;
      } catch (cause) {
        if (item.source === api()) {
          failed = needsRefresh = true;
          report(cause, item.from);
          if (item.to && location.hash === item.to) location.hash = item.from;
        }
      } finally {
        version++;
        if (!saved) setPending((items) => items.slice(1));
        item.resolve(saved);
      }
    }
    if (!failed && message) notify(message, messagePath);
    // Writes return the authoritative view. Only decisions and uncertain failures
    // need another read; ordinary saves should not trigger a loading cycle.
    if (needsRefresh) {
      // A decision still needs a read after any older, invalidated poll settles.
      await refreshing;
      void refresh();
    }
  }
  const edit = (changes: owner.Change[], to?: string) =>
    perform((client) => client.edit(changes), "", {
      update: (state) => {
        owner.previewChanges(state.view, changes);
      },
      to,
    });
  const label = (
    name: string,
    change: Partial<Pick<owner.Label, "trust" | "audience">>,
  ) => {
    const next = (view: owner.View): owner.Label => ({
      trust: view.labels[name]?.trust ?? "trusted",
      audience: view.labels[name]?.audience ?? "anyone",
      ...change,
    });
    return perform((client) => client.label(name, next(snapshot()!.view)), "", {
      update: (state) => {
        state.view.labels[name] = next(state.view);
      },
    });
  };
  const decide = (record: owner.RequestRecord, decision: owner.Decision) =>
    perform(
      (client) => client.decide(record.id, decision),
      decision === "save"
        ? "Rule saved. Retry the request from your sandbox."
        : "",
      {
        update: (state) => {
          state.requests = state.requests.map((r) =>
            r.id === record.id
              ? {
                  ...r,
                  state:
                    decision === "once"
                      ? "approved"
                      : decision === "deny"
                        ? "denied"
                        : r.state,
                  savingDecision: true,
                }
              : r,
          );
        },
      },
    );
  const signIn = (account: string, field: owner.CredentialField) =>
    perform(async (client) => {
      setDeviceSignIn(undefined);
      const result = await client.signIn(
        account,
        field.path,
        location.origin + location.pathname,
        field.credential,
      );
      if ("user_code" in result) {
        setDeviceSignIn({
          ...result,
          source: client,
          title: owner.presetOf(view()!, account).title,
          preset: view()!.config.accounts![account].preset,
        });
        return;
      }
      sessionStorage.setItem(RETURN, location.hash);
      location.assign(result.url);
    }, "");

  createEffect(
    on(deviceSignIn, (attempt) => {
      if (!attempt) return;
      const controller = new AbortController();
      let completed = false;
      let timer: ReturnType<typeof setTimeout>;
      const poll = async () => {
        try {
          if (Date.now() >= Date.parse(attempt.expires))
            throw new Error(
              "Sign-in code expired. Sign in again to get a new code.",
            );
          const result = await attempt.source.finishSignIn(
            attempt.state,
            {},
            controller.signal,
          );
          if (controller.signal.aborted) return;
          if (result && "pending" in result) {
            timer = setTimeout(poll, DEVICE_POLL_MS);
            return;
          }
          completed = true;
          version++;
          setDeviceSignIn(undefined);
          // Fetch a fresh view; other owner edits may have completed while waiting.
          await refreshing;
          void refresh();
        } catch (cause) {
          if (!controller.signal.aborted) {
            setDeviceSignIn(undefined);
            report(cause);
          }
        }
      };
      timer = setTimeout(poll, DEVICE_POLL_MS);
      onCleanup(() => {
        clearTimeout(timer);
        controller.abort();
        if (!completed)
          void attempt.source
            .finishSignIn(attempt.state, { cancel: true })
            .catch(() => {});
      });
    }),
  );

  createEffect(
    on(
      api,
      () => {
        setDeviceSignIn(undefined);
        version++;
        setSnapshot(undefined);
        void refresh();
      },
      { defer: true },
    ),
  );
  createEffect(() => {
    const count = pendingCount();
    document.title = count ? `(${count}) Monitor` : "Monitor";
  });
  onMount(async () => {
    try {
      if (!options.client && !ENDPOINT) {
        const response = await fetch("/app/auth.json", {
          cache: "no-store",
          credentials: "omit",
          redirect: "error",
          signal: lifetime.signal,
        });
        if (!response.ok)
          throw new Error(
            "Could not load Monitor sign-in options. Reload to retry.",
          );
        const { mode } = await response.json();
        if (mode !== "bearer" && mode !== "ssh")
          throw new Error("Unknown Monitor sign-in method.");
        sessionStorage.removeItem(mode === "ssh" ? KEY : SESSION);
        setMode(mode);
        setCredential(
          sessionStorage.getItem(mode === "ssh" ? SESSION : KEY) ?? "",
        );
      }
      await refresh();
      const back = new URLSearchParams(location.search);
      if (back.has("state") || back.has("code") || back.has("error")) {
        history.replaceState(
          null,
          "",
          location.pathname + (sessionStorage.getItem(RETURN) ?? ""),
        );
        sessionStorage.removeItem(RETURN);
        window.dispatchEvent(new HashChangeEvent("hashchange"));
        if (
          !back.get("state") ||
          ["state", "code", "client_id", "error"].some(
            (key) => back.getAll(key).length > 1,
          )
        )
          throw new Error("Invalid sign-in callback. Start sign-in again.");
        await perform(async (client) => {
          const result = await client.finishSignIn(
            back.get("state")!,
            Object.fromEntries(
              ["code", "client_id", "error"]
                .filter((key) => back.has(key))
                .map((key) => [key, back.get(key)!]),
            ),
          );
          if (!result || "pending" in result)
            throw new Error("Sign-in was not completed. Start again.");
          return result;
        });
      }
    } catch (cause) {
      report(cause);
    }
  });
  onMount(() => {
    void fetch(import.meta.env.BASE_URL + "icons/manifest.json", {
      signal: lifetime.signal,
    })
      .then((r) => r.json())
      .then(setIcons)
      .catch(() => {});
    const visible = () => {
      if (!document.hidden) {
        setNow(Date.now());
        if (!locked()) void refresh();
      }
    };
    document.addEventListener("visibilitychange", visible);
    const poll = setInterval(visible, 5000);
    const clock = setInterval(() => {
      if (!document.hidden) setNow(Date.now());
    }, 1000);
    onCleanup(() => {
      document.removeEventListener("visibilitychange", visible);
      clearInterval(poll);
      clearInterval(clock);
    });
  });
  onCleanup(() => {
    lifetime.abort();
    clearTimeout(toastTimer);
  });
  const waiting = () => {
    const keys = Object.values(view()?.config.identities ?? {}).map(
      (identity) => identity.key,
    );
    return (options.candidates?.() ?? [])
      .filter((candidate) => !keys.includes(candidate.key))
      .map((candidate) => candidate.name);
  };
  const accept = async (name: string, restore = true) => {
    if (accepting()) return;
    setAccepting(name);
    try {
      await options.accept!(name, restore);
      await refresh();
    } catch (cause) {
      if (restore) report(cause);
      else setStalled((names) => [...names, name]);
    } finally {
      setAccepting();
    }
  };
  createEffect(() => {
    const next = view() && waiting().find((name) => !stalled().includes(name));
    if (next && !accepting()) void accept(next, false);
  });

  return {
    options,
    mode,
    credential,
    view,
    records,
    recordsById,
    pendingCount,
    proposals,
    older,
    loadingOlder,
    loadOlder,
    locked,
    busy,
    loading,
    error,
    message,
    now,
    icons,
    activity,
    setActivity,
    search,
    dismissed,
    dismiss,
    api,
    notify,
    report,
    refresh,
    perform,
    edit,
    label,
    decide,
    signIn,
    deviceSignIn,
    shell,
    setShell,
    shellFor: (name: string) => options.shell?.(name),
    sandboxesLoading: () => options.sandboxesLoading?.() ?? false,
    waiting,
    accepting,
    stalled,
    accept,
    cancelSignIn: () => setDeviceSignIn(undefined),
    unlock: () =>
      perform((client) =>
        // Rollback floor: never unlock a state older than the newest
        // generation this browser has seen. Local dev wipes its store,
        // which looks identical to a rollback, so the floor is off there.
        client.unlock(
          options.client
            ? undefined
            : import.meta.env.DEV
              ? 0
              : Number(localStorage.getItem(GENERATION)) || 0,
        ),
      ),
    login: (value: string) => {
      try {
        const key = owner.encodeOwnerKey(value);
        sessionStorage.setItem(KEY, key);
        setCredential(key);
      } catch (cause) {
        report(cause);
      }
    },
  };
}

const MonitorContext = createContext<ReturnType<typeof createMonitor>>();
export function MonitorProvider(props: ParentProps<MonitorOptions>) {
  return (
    <MonitorContext.Provider value={createMonitor(props)}>
      {props.children}
    </MonitorContext.Provider>
  );
}
export function useMonitor() {
  const monitor = useContext(MonitorContext);
  if (!monitor) throw new Error("MonitorProvider is required");
  return monitor;
}
