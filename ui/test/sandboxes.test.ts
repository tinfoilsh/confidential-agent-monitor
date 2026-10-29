import { describe, expect, test } from "bun:test";
import {
  RestoreRequired,
  connectPlan,
  type SandboxStatus,
} from "../src/hosted/sandboxes";

const AGENT = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIAgent";
const HOST = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAINewBoot";
const OLD_HOST = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOldBoot";
const status = (s: Partial<SandboxStatus>): SandboxStatus => ({
  protocol: "sandbox-owner-v1",
  instance_id: "1b8a3c52-61f4-4d3e-8d2a-6f1e9c4b7a10",
  volume: "unlocked",
  agent_public_key: AGENT,
  monitor_host_key: HOST,
  ...s,
});
const plan = (s: Partial<SandboxStatus>, known: boolean, restore = false) =>
  connectPlan(status(s), AGENT, HOST, known, restore);

describe("connecting a sandbox", () => {
  test("only a blank workspace without an agent is a first enrollment", () => {
    expect(
      plan(
        {
          agent_public_key: null,
          volume: "locked_blank",
          monitor_host_key: null,
        },
        false,
      ),
    ).toEqual({ monitor: true, sandbox: "enroll" });
  });

  test("a sandbox restart with initialized storage reinstalls its known identity", () => {
    expect(
      plan({ agent_public_key: null, volume: "locked_initialized" }, true),
    ).toEqual({
      monitor: false,
      sandbox: "enroll",
    });
  });

  test("a removed identity is never re-enrolled silently", () => {
    for (const s of [
      { agent_public_key: null, volume: "locked_initialized" as const },
      { agent_public_key: null, volume: "locked_unknown" as const },
      { monitor_host_key: OLD_HOST },
    ])
      expect(() => plan(s, false)).toThrow(RestoreRequired);
    expect(
      plan(
        { agent_public_key: null, volume: "locked_initialized" },
        false,
        true,
      ),
    ).toEqual({
      monitor: true,
      sandbox: "enroll",
    });
  });

  test("a Monitor-only restart re-links a running, authorized sandbox", () => {
    expect(plan({ monitor_host_key: OLD_HOST }, true)).toEqual({
      monitor: false,
      sandbox: "relink",
    });
    expect(plan({}, true)).toEqual({ monitor: false, sandbox: undefined });
  });

  test("another agent identity in the sandbox fails", () => {
    expect(() => plan({ agent_public_key: HOST }, true)).toThrow(
      /different agent/,
    );
  });
});
