import { Route, Router } from "@solidjs/router";
import { render } from "solid-js/web";
import Console from "../src/hosted/Console";
import Monitor from "../src/hosted/Monitor";
import * as keys from "../src/hosted/keys";
import type { openMonitor } from "../src/hosted/monitors";
import { createSession } from "../src/hosted/session";
import { ownerClient } from "../src/owner";
import { devClerk, devPasskeys } from "./account";
import { MONITOR_ID, ORIGIN, resource, STORAGE_KEY } from "./fixtures";

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

  // No attestation bypass is installed in the production opener. This explicitly
  // local adapter uses the real backend's file-bucket/bearer development API.
  const openLocal: typeof openMonitor = async ({ scope, id, signal }) => {
    if (id !== MONITOR_ID) throw new Error("There is no such local Monitor.");
    const row = (await scope.fresh()).find((row) => row.id === id)!;
    const client = Object.assign(
      ownerClient({ endpoint: `${ORIGIN}/__dev/monitor`, key: STORAGE_KEY }),
      {
        // The extra hosted call capability is for sandbox enrollment/shells only.
        call: async () => {
          throw new Error(
            "Sandbox VMs and shells are not running in this local preview.",
          );
        },
      },
    );
    await client.unlock(undefined, signal);
    const snapshot = await client.read(signal);
    return {
      row,
      resource,
      client,
      snapshot,
      hostKey: () => snapshot.view.host_key.trim(),
      scope,
    };
  };
  loading();
  render(
    () => (
      <Router explicitLinks>
        <Route
          path="/monitor/:id"
          component={() => (
            <Monitor session={session} manager={manager} open={openLocal} />
          )}
        />
        <Route
          path="*"
          component={() => <Console session={session} manager={manager} />}
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
