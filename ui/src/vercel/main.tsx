import { Clerk } from "@clerk/clerk-js/no-rhc";
import { ui } from "@clerk/ui/no-rhc";
import { render } from "solid-js/web";
import Console from "./Console";
import { ownerRpcOnly, type AttestMonitor } from "./monitors";

const root = document.getElementById("root")!;
const key = import.meta.env.VITE_CLERK_PUBLISHABLE_KEY;
// ui/dev/local.ts relays owner RPC in plaintext to local Monitors, which have no enclave shim.
const attest: AttestMonitor | undefined =
  import.meta.env.DEV && import.meta.env.VITE_LOCAL_MONITORS
    ? async ({ url }) => ({ fetch: ownerRpcOnly(url, fetch), verified: false })
    : undefined;

// Bundled clerk-js and UI, as in chat: nothing is loaded from Clerk's CDN.
(async () => {
  if (!key)
    throw new Error(
      "This console was built without VITE_CLERK_PUBLISHABLE_KEY.",
    );
  const clerk = new Clerk(key);
  await clerk.load({ ui, telemetry: false });
  render(() => <Console clerk={clerk} attest={attest} />, root);
})().catch((cause) =>
  render(
    () => (
      <div id="gate">
        <h1>Could not start the console</h1>
        <p role="alert">{String(cause)}</p>
        <button onClick={() => location.reload()}>Reload</button>
      </div>
    ),
    root,
  ),
);
