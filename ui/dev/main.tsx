import { Route, Router } from "@solidjs/router";
import { render } from "solid-js/web";
import { onCleanup, onMount } from "solid-js";
import Console from "../src/hosted/Console";
import Monitor from "../src/hosted/Monitor";
import * as keys from "../src/hosted/keys";
import type { openMonitor } from "../src/hosted/monitors";
import { createSession } from "../src/hosted/session";
import { isDevice, ownerClient, type Snapshot } from "../src/owner";
import { devClerk, devPasskeys } from "./account";
import { MONITOR_ID, ORIGIN, resource, STORAGE_KEY } from "./fixtures";
import { hold, previewSession, scenarioOf } from "./scenarios";
import { createFullFlow, delay } from "./flow";
import { activityDemo } from "./notifications";

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
    new URLSearchParams(location.search).get("state"),
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
  let openAttempts = 0;

  // No attestation bypass is installed in the production opener. This explicitly
  // local adapter uses the real backend's file-bucket/bearer development API.
  const openLocal: typeof openMonitor = async ({ scope, id, signal }) => {
    if (scenario === "monitor-opening") return hold(signal);
    if (flow) await delay(1800, signal);
    if (scenario === "monitor-error" && openAttempts++ === 0)
      throw new Error("Could not reach your Monitor. Please try again.");
    if (id !== MONITOR_ID) throw new Error("There is no such local Monitor.");
    const row = (await scope.fresh()).find((row) => row.id === id)!;
    const client = activityDemo.wrap(
      Object.assign(
        ownerClient({ endpoint: `${ORIGIN}/__dev/monitor`, key: STORAGE_KEY }),
        {
          // The extra hosted call capability is for sandbox enrollment/shells only.
          call: async () => {
            throw new Error(
              "Sandbox VMs and shells are not running in this local preview.",
            );
          },
        },
      ),
    );
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
        client.read = async (readSignal) => {
          if (!pending) return read(readSignal);
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
        client.read = (readSignal) => hold<Snapshot>(readSignal ?? current);
        scope = { ...scope, fresh: () => hold(current) };
      }
    }
    return {
      row,
      resource,
      client,
      snapshot,
      hostKey: () => snapshot.view.host_key.trim(),
      scope,
    };
  };
  const MonitorPage = () => {
    const abort = new AbortController();
    onMount(() => {
      void flow?.start(abort.signal).catch(() => {});
    });
    onCleanup(() => abort.abort());
    return (
      <Monitor session={preview} manager={previewManager} open={openLocal} />
    );
  };
  loading();
  render(
    () => (
      <Router explicitLinks>
        <Route path="/monitor/:id" component={MonitorPage} />
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
