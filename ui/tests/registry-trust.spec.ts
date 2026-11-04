import { expect, test } from "bun:test";
import { sha256 } from "@noble/hashes/sha2.js";
import { bytesToHex } from "@noble/hashes/utils.js";
import type { Container } from "../src/terminal/session";
import { registryTarget, verifyImage } from "../src/terminal/trust";
import build from "./fixtures/monitor-build.json";

const registry = "https://registry.tinfoil.sh/scopes/" + "0".repeat(32);
const config = new TextEncoder().encode("name: gpt-oss-120b\n");
const digest = bytesToHex(sha256(config));
const row = {
  domain: "monitor.example",
  connections: {
    production: {
      url: "https://monitor.example",
      config_name: "/acme/monitor/release-1",
      config_digest: digest,
    },
  },
} as Container;

test("pins the selected private registry and exact config revision and digest", () => {
  expect(registryTarget(row, config, registry)).toEqual({
    url: row.connections!.production!.url,
    reference: `acme/monitor@release-1@sha256:${digest}`,
    registry,
  });
});

test("rejects public and noncanonical registry identities", () => {
  for (const id of [
    "https://registry.tinfoil.sh/scopes/public",
    "",
    registry + "\n",
    registry + "?x=1",
    registry + "#x",
    registry.replace(/0$/, "A"),
    registry.replace(/0$/, "%30"),
  ])
    expect(() => registryTarget(row, config, id)).toThrow(
      "private Registry ID",
    );
});

test("rejects mismatched bytes, references, endpoints, and missing live connections", () => {
  expect(() =>
    registryTarget(row, new TextEncoder().encode("different"), registry),
  ).toThrow("config could not be confirmed");
  const connection = row.connections!.production!;
  for (const patch of [
    { url: "https://other.example" },
    { config_name: "/acme/monitor" },
    { config_name: "/acme/monitor/rev@other" },
    { config_digest: "f".repeat(64) },
  ])
    expect(() =>
      registryTarget(
        { ...row, connections: { production: { ...connection, ...patch } } },
        config,
        registry,
      ),
    ).toThrow();
  expect(() =>
    registryTarget({ ...row, connections: undefined }, config, registry),
  ).toThrow("config could not be confirmed");
});

test("requires image provenance for the exact workload and digest", async () => {
  const image =
    "2c7a121c06e78a68110a0caf28c3388a1afbcaabb69f1683c769e1d5a5fb6429";
  const fetchProof: typeof fetch = async () => Response.json(build);
  await verifyImage("monitor", image, { fetch: fetchProof });
  await expect(
    verifyImage("monitor", "f".repeat(64), { fetch: fetchProof }),
  ).rejects.toThrow("approved release");
  await expect(
    verifyImage("sandbox", image, { fetch: fetchProof }),
  ).rejects.toThrow("approved release");
  const corrupt = structuredClone(build);
  corrupt.attestations[0]!.bundle.dsseEnvelope.signatures[0]!.sig = "AA==";
  await expect(
    verifyImage("monitor", image, {
      fetch: async () => Response.json(corrupt),
    }),
  ).rejects.toThrow("approved release");
});
