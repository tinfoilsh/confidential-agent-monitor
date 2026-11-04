import { createSignal } from "solid-js";

export function delay(ms: number, signal?: AbortSignal): Promise<void> {
  return new Promise((resolve, reject) => {
    if (signal?.aborted) return reject(signal.reason);
    const abort = () => {
      clearTimeout(timer);
      reject(signal?.reason);
    };
    const timer = setTimeout(() => {
      signal?.removeEventListener("abort", abort);
      resolve();
    }, ms);
    signal?.addEventListener("abort", abort, { once: true });
  });
}

// One successful, interactive flow. Boot timing starts on Monitor selection,
// not on arrival at the account home, so it cannot finish before the user clicks.
export function createFullFlow() {
  const [inventoryLoading, setInventoryLoading] = createSignal(true);
  const [booting, setBooting] = createSignal(true);
  let starting = false;
  void delay(1200).then(() => setInventoryLoading(false));
  return {
    inventoryLoading,
    booting,
    async start(signal: AbortSignal) {
      if (starting || !booting()) return;
      starting = true;
      try {
        await delay(3500, signal);
        setBooting(false);
      } finally {
        starting = false;
      }
    },
  };
}
export type FullFlow = ReturnType<typeof createFullFlow>;
