import { Route, Router } from "@solidjs/router";
import { render } from "solid-js/web";
import { onCleanup, onMount } from "solid-js";
import App from "../src/monitor/App";
import Console from "../src/terminal/Console";
import MonitorPage from "../src/terminal/MonitorPage";
import * as keys from "../src/terminal/keys";
import type { openMonitor } from "../src/terminal/connection";
import { createSession } from "../src/terminal/session";
import { isDevice, ownerClient, type Snapshot } from "../src/monitor/owner";
import { devClerk, devPasskeys } from "./account";
import { MONITOR_ID, ORIGIN, resource, STORAGE_KEY } from "./fixtures";
import { hold, previewSession, scenarioOf } from "./scenarios";
import { createFullFlow, delay } from "./flow";

const root = document.getElementById("root")!;
const loading = render(
  () => (
    <main id="gate">
      <h1>Starting local development console…</h1>
    </main>
  ),
  root,
);

async function start() {
  if (
    !import.meta.env.DEV ||
    import.meta.env.MODE !== "dev-console" ||
    location.origin !== ORIGIN
  )
    throw new Error(
      "The fake console only runs on its loopback development origin.",
    );
  const session = createSession(devClerk());
  const manager = devPasskeys();
  await session.refresh();
  const state = session.keyState().value;
  if (!state || session.keyState().error)
    throw new Error(session.keyState().error ?? "Could not read local keys.");
  const scope = session.bind();
  const unlocked = state.dek_id
    ? await keys.unlockPasskey(manager, state, scope.user)
    : (
        await keys.setupMK({
          api: scope.api,
          manager,
          user_id: scope.user,
          state,
          method: "passkey",
          resources: [resource],
          fence: await scope.fence,
          signal: scope.signal,
        })
      ).unlocked;
  await scope.setUnlocked(unlocked);
  await session.refresh();

  const scenario = scenarioOf(
    new URLSearchParams(location.search).get("preview"),
  );
  const flow = scenario === "full-flow" ? createFullFlow() : undefined;
  const preview = previewSession(session, scenario, flow);
  const previewManager: typeof manager = flow
    ? {
        ...manager,
        recoverKey: async (options) => {
          await delay(900, options.signal);
          return manager.recoverKey(options);
        },
      }
    : manager;
  let attempts = 0;

  // No production attestation bypass. This dev-only adapter talks to this
  // worktree's real local bearer API; account/passkey fixtures stay on loopback.
  const openLocal: typeof openMonitor = async ({ scope, id, signal }) => {
    if (scenario === "monitor-opening") return hold(signal);
    if (flow) await delay(1800, signal);
    if (scenario === "monitor-error" && attempts++ === 0)
      throw new Error("Could not reach your Monitor. Please try again.");
    if (id !== MONITOR_ID) throw new Error("There is no such local Monitor.");
    const row = (await scope.fresh()).find((row) => row.id === id)!;
    const client = Object.assign(
      ownerClient({ endpoint: `${ORIGIN}/__dev/monitor`, key: STORAGE_KEY }),
      {
        call: async () => {
          throw new Error(
            "Sandbox VMs and shells are not running in this local preview.",
          );
        },
      },
    );
    if (scenario === "onboarding") {
      let pending = true;
      const read = client.read,
        onboard = client.onboard;
      client.read = async (at) => {
        const snapshot = await read(at);
        return pending
          ? {
              ...snapshot,
              view: {
                ...snapshot.view,
                config: {
                  ...snapshot.view.config,
                  data: {
                    ...snapshot.view.config.data,
                    onboarding: { completed: false },
                  },
                },
              },
            }
          : snapshot;
      };
      client.onboard = async (...args) => {
        const view = await onboard(...args);
        pending = false;
        return view;
      };
    }
    await client.unlock(undefined, signal);
    let snapshot = await client.read(signal);
    if (scenario === "sandboxes-loading" || flow) {
      snapshot = {
        ...snapshot,
        view: {
          ...snapshot.view,
          config: {
            ...snapshot.view.config,
            identities: Object.fromEntries(
              Object.entries(snapshot.view.config.identities ?? {}).filter(
                ([name]) => isDevice(name),
              ),
            ),
          },
        },
      };
      const current = AbortSignal.any([signal, scope.signal]);
      if (flow) {
        const read = client.read,
          fresh = scope.fresh;
        const ready = delay(2200, current).then(() => read(current));
        ready.catch(() => {});
        let pending: Promise<Snapshot> | undefined = ready;
        client.read = async (at) => {
          if (!pending) return read(at);
          const loaded = await pending;
          pending = undefined;
          return loaded;
        };
        scope = {
          ...scope,
          fresh: async () => {
            await ready;
            return fresh();
          },
        };
      } else {
        client.read = (at) => hold<Snapshot>(at ?? current);
        scope = { ...scope, fresh: () => hold(current) };
      }
    }
    return {
      row,
      resource,
      client,
      snapshot,
      scope,
      hostKey: () => snapshot.view.host_key.trim(),
      relay: async () => {
        throw new Error(
          "Sandbox relays are not running in this local preview.",
        );
      },
      refresh: async () => {},
      registry: "local-development-only",
    };
  };

  if (location.pathname === "/standalone") {
    const lifetime = new AbortController();
    const opened = await openLocal({
      scope,
      id: MONITOR_ID,
      signal: lifetime.signal,
      onCheckpoint: () => {},
    });
    loading();
    render(() => {
      onCleanup(() => lifetime.abort());
      return (
        <App
          connection={{ client: opened.client, snapshot: opened.snapshot }}
        />
      );
    }, root);
    return;
  }
  const MonitorPreview = () => {
    const lifetime = new AbortController();
    onMount(() => {
      void flow?.start(lifetime.signal).catch(() => {});
    });
    onCleanup(() => lifetime.abort());
    return (
      <MonitorPage
        session={preview}
        manager={previewManager}
        open={openLocal}
      />
    );
  };
  loading();
  render(
    () => (
      <Router explicitLinks>
        <Route path="/monitor/:id" component={MonitorPreview} />
        <Route
          path="*"
          component={() => (
            <Console session={preview} manager={previewManager} />
          )}
        />
      </Router>
    ),
    root,
  );
}

void start().catch((cause) => {
  loading();
  render(
    () => (
      <main id="gate">
        <h1>Could not start local development</h1>
        <p role="alert">{String(cause)}</p>
      </main>
    ),
    root,
  );
});
