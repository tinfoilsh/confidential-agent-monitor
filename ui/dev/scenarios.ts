import { createSignal } from "solid-js";
import type { Session } from "../src/terminal/session";
import type { FullFlow } from "./flow";

export const SCENARIOS = [
  "onboarding",
  "full-flow",
  "keys-loading",
  "inventory-loading",
  "sandboxes-loading",
  "monitor-booting",
  "monitor-startup",
  "monitor-locked",
  "monitor-opening",
  "monitor-stopped",
  "monitor-error",
] as const;
export type Scenario = (typeof SCENARIOS)[number];
export const scenarioOf = (value: string | null): Scenario | undefined =>
  SCENARIOS.find((scenario) => scenario === value);

// Render-only overrides: no fixture changes reach the API or saved key bundle.
export function previewSession(
  session: Session,
  scenario?: Scenario,
  flow?: FullFlow,
): Session {
  if (!scenario) return session;
  const [locked, setLocked] = createSignal(
    scenario === "monitor-locked" || scenario === "full-flow",
  );
  const [starting, setStarting] = createSignal(scenario === "monitor-startup");
  if (starting()) setTimeout(() => setStarting(false), 5000);
  return {
    ...session,
    keyState: () =>
      scenario === "keys-loading" ? { loading: true } : session.keyState(),
    unlocked: () =>
      scenario === "keys-loading" || locked() ? undefined : session.unlocked(),
    bind:
      scenario === "monitor-locked" || scenario === "full-flow"
        ? () => {
            const scope = session.bind();
            return {
              ...scope,
              setUnlocked: async (unlocked) => {
                await scope.setUnlocked(unlocked);
                setLocked(!unlocked);
              },
            };
          }
        : session.bind,
    inventory: () => {
      if (scenario === "inventory-loading" || flow?.inventoryLoading())
        return { loading: true };
      const inventory = session.inventory();
      const booting =
        scenario === "monitor-booting" || starting() || flow?.booting();
      if (!booting && scenario !== "monitor-stopped") return inventory;
      return {
        ...inventory,
        value: inventory.value?.map((row) =>
          row.repo.endsWith("agent-monitor")
            ? {
                ...row,
                status: booting ? "pending" : "stopped",
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
