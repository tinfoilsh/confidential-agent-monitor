import { expect, test } from "bun:test";
import { connectSandbox } from "../src/terminal/sandboxes";
import type { OpenedMonitor } from "../src/terminal/connection";

function fixture(phase: "before" | "container" | "volumes") {
  const cancellation = new AbortController();
  const reason = new Error("Workspace closed during sandbox resolution.");
  const requests: { path: string; signal?: AbortSignal }[] = [];
  let writes = 0;
  const monitor = {
    row: { id: "monitor" },
    scope: {
      user: "user",
      account: "personal",
      signal: new AbortController().signal,
      unlocked: () => ({
        payload: {
          resources: [
            {
              kind: "sandbox",
              owner_public_key: "owner",
              key_id: "key",
              binding: null,
            },
          ],
        },
      }),
      update: async () => {
        writes++;
      },
      api: async (path: string, options?: { signal?: AbortSignal }) => {
        requests.push({ path, signal: options?.signal });
        if (path === "/api/containers/sandbox") {
          if (phase === "container") cancellation.abort(reason);
          return {
            id: "sandbox",
            repo: "tinfoilsh/confidential-agent-sandbox",
            clerk_user_id: "user",
            owner_key_mode: "tmk",
            owner_public_key: "owner",
            network_policy: { egress: [{ container_id: "monitor" }] },
            config:
              "containers:\n  - env:\n      - SANDBOX_INSTANCE_ID: 11111111-1111-4111-8111-111111111111\n",
            volumes: { workspace: "volume" },
          };
        }
        if (path === "/api/volumes") {
          if (phase === "volumes") cancellation.abort(reason);
          return {
            volumes: [
              {
                id: "volume",
                container_id: "sandbox",
                slot: "workspace",
                size_bytes: 1024 ** 3,
              },
            ],
          };
        }
        throw new Error(`Unexpected request: ${path}`);
      },
    },
  } as unknown as OpenedMonitor;
  if (phase === "before") cancellation.abort(reason);
  return { monitor, cancellation, reason, requests, writes: () => writes };
}

for (const phase of ["before", "container", "volumes"] as const) {
  test(`sandbox cancellation ${phase} resolution admits no binding write`, async () => {
    const f = fixture(phase);
    let failure: unknown;
    try {
      await connectSandbox({
        monitor: f.monitor,
        id: "sandbox",
        signal: f.cancellation.signal,
      });
    } catch (cause) {
      failure = cause;
    }
    expect(f.writes()).toBe(0);
    expect(failure).toBe(f.reason);
    expect(f.requests.length).toBe(
      phase === "before" ? 0 : phase === "container" ? 1 : 2,
    );
    for (const request of f.requests)
      expect(request.signal?.aborted).toBe(true);
  });
}
