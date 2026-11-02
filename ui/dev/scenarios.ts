import type { Session } from "../src/hosted/session";

export const SCENARIOS = [
  "keys-loading",
  "inventory-loading",
  "sandboxes-loading",
  "monitor-booting",
  "monitor-opening",
  "monitor-stopped",
  "monitor-error",
] as const;
export type Scenario = (typeof SCENARIOS)[number];
export const scenarioOf = (value: string | null): Scenario | undefined =>
  SCENARIOS.find((scenario) => scenario === value);

// Render-only overrides: no fixture changes reach the API or saved key bundle.
export function previewSession(session: Session, scenario?: Scenario): Session {
  if (!scenario) return session;
  return {
    ...session,
    keyState: () =>
      scenario === "keys-loading" ? { loading: true } : session.keyState(),
    unlocked: () =>
      scenario === "keys-loading" ? undefined : session.unlocked(),
    inventory: () => {
      if (scenario === "inventory-loading") return { loading: true };
      const inventory = session.inventory();
      if (scenario !== "monitor-booting" && scenario !== "monitor-stopped")
        return inventory;
      return {
        ...inventory,
        value: inventory.value?.map((row) =>
          row.repo.endsWith("agent-monitor")
            ? {
                ...row,
                status: scenario === "monitor-booting" ? "pending" : "stopped",
              }
            : row,
        ),
      };
    },
  };
}

// Keep a loading/opening preview pending until its component is cancelled.
export function hold<T>(signal?: AbortSignal): Promise<T> {
  return new Promise((_, reject) => {
    if (signal?.aborted) return reject(signal.reason);
    signal?.addEventListener("abort", () => reject(signal.reason), {
      once: true,
    });
  });
}
