import { expect, test } from "bun:test";
import { monitorCreatedAt, monitorResources } from "../src/monitor-info";

test("Monitor resources use inventory values and omit unavailable values", () => {
  expect(monitorResources({ name: "one", cpus: 2, memoryMb: 2048 })).toBe(
    "2 CPU / 2 GB RAM",
  );
  expect(monitorResources({ name: "one", memoryMb: 512 })).toBe("512 MB RAM");
  expect(monitorResources({ name: "one", cpus: 4 })).toBe("4 CPU");
  expect(monitorResources({ name: "one" })).toBe("");
  expect(monitorResources({ name: "one", cpus: NaN, memoryMb: Infinity })).toBe(
    "",
  );
  expect(monitorResources({ name: "one", cpus: 0, memoryMb: null })).toBe("");
});

test("creation dates are real calendar dates, not guessed from runtime or frontend build", () => {
  expect(
    monitorCreatedAt({
      name: "one",
      createdAt: "2026-11-01T17:00:00Z",
    })?.toISOString(),
  ).toBe("2026-11-01T17:00:00.000Z");
  expect(
    monitorCreatedAt({ name: "one", createdAt: "invalid" }),
  ).toBeUndefined();
  expect(monitorCreatedAt({ name: "one" })).toBeUndefined();
});
