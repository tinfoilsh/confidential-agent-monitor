import { describe, expect, test } from "bun:test";
import { sha256 } from "@noble/hashes/sha2.js";
import { bytesToHex, utf8ToBytes } from "@noble/hashes/utils.js";
import { parse, stringify } from "yaml";
import attestations from "./public-template-attestations.json";
import {
  bucketOwnedBy,
  monitorDigest,
  checkStatement,
  sandboxDigest,
  verifyImage,
  volumeSize,
} from "../src/hosted/trust";

const MONITOR = await Bun.file(
  new URL("../../tinfoil-config.yml", import.meta.url),
).text();
const SANDBOX = await Bun.file(
  new URL("../src/hosted/sandbox-config.yml", import.meta.url),
).text();
const OWNER = "ed25519:s1UXIOMkYJ15QQlPcXCV4F4njOeJTJ+Qb4oXWPdMfyM=";
const OTHER = "ed25519:pGG2cDT1ezriE3fLwl6XlSxwRAJYWHHlRp5xLuyVqIE=";
const DIGEST = "1".repeat(64);
const INSTANCE = "1b8a3c52-61f4-4d3e-8d2a-6f1e9c4b7a10";
const CREDENTIALS =
  "https://api.tinfoil.sh/api/deployments/storage-credentials";
const BUCKET = `s3://tinfoil-agents?prefix=containers%2F${bytesToHex(sha256(utf8ToBytes("org:org_2abc")))}%2Fobj-1%2F&region=us-east-1`;

type Config = Record<string, any>;
// Renders a template the way provisioning does: only listed values change.
function render(
  template: string,
  env: Record<string, string>,
  change?: (c: Config) => void,
) {
  const config = parse(template) as Config;
  const container = config.containers[0];
  container.image = container.image.replace(
    /@sha256:[0-9a-f]{64}$/,
    `@sha256:${DIGEST}`,
  );
  container.env = container.env.map((entry: Record<string, string>) => {
    const [name] = Object.keys(entry);
    return { [name]: env[name] ?? entry[name] };
  });
  change?.(config);
  return utf8ToBytes(stringify(config));
}
const monitor = (
  change?: (c: Config) => void,
  env: Record<string, string> = {},
) =>
  render(
    MONITOR,
    {
      MONITOR_OWNER_PUBLIC_KEY: OWNER,
      TINFOIL_STORAGE_BUCKET: BUCKET,
      AWS_CONTAINER_CREDENTIALS_FULL_URI: CREDENTIALS,
      ...env,
    },
    change,
  );
const sandbox = (
  change?: (c: Config) => void,
  env: Record<string, string> = {},
) =>
  render(
    SANDBOX,
    { SANDBOX_OWNER_PUBLIC_KEY: OWNER, SANDBOX_INSTANCE_ID: INSTANCE, ...env },
    (c) => {
      c.volumes[0].size = "8GB";
      change?.(c);
    },
  );
const expectMonitor = {
  owner: OWNER,
  bucket: BUCKET,
  credentials: CREDENTIALS,
};
const expectSandbox = { owner: OWNER, instance_id: INSTANCE, size: "8GB" };

describe("trusted templates", () => {
  test("accept only the enumerated substitutions and return the image digest", () => {
    expect(monitorDigest(MONITOR, monitor(), expectMonitor)).toBe(DIGEST);
    expect(sandboxDigest(SANDBOX, sandbox(), expectSandbox)).toBe(DIGEST);
    // Reopening a sandbox with its own non-decimal workspace keeps that exact size.
    const reused = sandbox(
      (c) => (c.volumes[0].size = volumeSize(30_000_000_001)),
    );
    expect(
      sandboxDigest(SANDBOX, reused, {
        ...expectSandbox,
        size: "30000000001B",
      }),
    ).toBe(DIGEST);
    expect(() => sandboxDigest(SANDBOX, reused, expectSandbox)).toThrow(
      /volume size/,
    );
  });

  test("reject modified Monitor configurations before any secret is sent", () => {
    const rejected: [string, Uint8Array][] = [
      ["entrypoint", monitor((c) => c.containers[0].command.push("-debug"))],
      [
        "extra container",
        monitor((c) =>
          c.containers.push({ ...structuredClone(c.containers[0]), name: "x" }),
        ),
      ],
      ["extra env", monitor((c) => c.containers[0].env.push({ EXTRA: "1" }))],
      [
        "extra attested key",
        monitor((c) => c["attested-keys"].push({ id: "x", key: "x25519" })),
      ],
      [
        "shim origin",
        monitor((c) => c.shim.origins.push("https://evil.example")),
      ],
      [
        "image repo",
        monitor(
          (c) =>
            (c.containers[0].image = `ghcr.io/evil/monitor@sha256:${DIGEST}`),
        ),
      ],
      ["owner", monitor(undefined, { MONITOR_OWNER_PUBLIC_KEY: OTHER })],
      [
        "bucket",
        monitor(undefined, {
          TINFOIL_STORAGE_BUCKET: BUCKET.replace("obj-1", "obj-2"),
        }),
      ],
      [
        "credentials",
        monitor(undefined, {
          AWS_CONTAINER_CREDENTIALS_FULL_URI: "https://evil.example/c",
        }),
      ],
    ];
    for (const [, config] of rejected)
      expect(() => monitorDigest(MONITOR, config, expectMonitor)).toThrow(
        /not approved/,
      );
  });

  test("reject modified sandbox configurations", () => {
    const rejected = [
      sandbox((c) => (c.models[0].repo = "nix/other@x")),
      sandbox((c) =>
        c.containers[0].persistent_volumes.push("workspace:/root"),
      ),
      sandbox((c) => (c.containers[0].keys = ["host-ssh"])),
      sandbox((c) => (c.volumes[0].size = "3GB")),
      sandbox(undefined, { NO_MONITOR: "1" }),
      sandbox(undefined, {
        SANDBOX_INSTANCE_ID: "2b8a3c52-61f4-4d3e-8d2a-6f1e9c4b7a10",
      }),
      sandbox(undefined, { SANDBOX_OWNER_PUBLIC_KEY: OTHER }),
    ];
    for (const config of rejected)
      expect(() => sandboxDigest(SANDBOX, config, expectSandbox)).toThrow(
        /not approved/,
      );
  });

  test("reject YAML features that could parse differently elsewhere", () => {
    const text = new TextDecoder().decode(monitor());
    for (const variant of [
      text + "cpus: 2\n",
      text.replace("memory: 2048", "memory: &m 2048\nother: *m"),
      text.replace("cpus: 2", "cpus: !!binary 2"),
    ])
      expect(() =>
        monitorDigest(MONITOR, utf8ToBytes(variant), expectMonitor),
      ).toThrow(/not approved/);
  });

  test("a Monitor bucket belongs only to its account", () => {
    expect(bucketOwnedBy(BUCKET, "org_2abc", "user_x")).toBe(true);
    expect(bucketOwnedBy(BUCKET, "org_2abd", "user_x")).toBe(false);
    expect(bucketOwnedBy(BUCKET, "personal", "user_x")).toBe(false);
  });
});

describe("image provenance", () => {
  const run = {
    commit: "a".repeat(40),
    run: "https://github.com/tinfoilsh/confidential-agent-monitor/actions/runs/7/attempts/1",
  };
  const statement = () => ({
    predicateType: "https://slsa.dev/provenance/v1",
    subject: [
      {
        name: "ghcr.io/tinfoilsh/confidential-agent-monitor",
        digest: { sha256: DIGEST },
      },
    ],
    predicate: {
      buildDefinition: {
        externalParameters: {
          workflow: {
            repository:
              "https://github.com/tinfoilsh/confidential-agent-monitor",
            ref: "refs/heads/main",
            path: ".github/workflows/tinfoil-release.yml",
          },
        },
        internalParameters: {
          github: {
            event_name: "workflow_dispatch",
            runner_environment: "github-hosted",
          },
        },
        resolvedDependencies: [{ digest: { gitCommit: run.commit } }],
      },
      runDetails: {
        builder: {
          id: "https://github.com/tinfoilsh/confidential-agent-monitor/.github/workflows/tinfoil-release.yml@refs/heads/main",
        },
        metadata: { invocationId: run.run },
      },
    },
  });

  test("the signed statement must match the certificate's commit, run and workflow", () => {
    const check = (s: any) =>
      checkStatement("application/vnd.in-toto+json", s, "monitor", DIGEST, run);
    expect(check(statement())).toBe(true);
    const changes: ((s: any) => void)[] = [
      (s) => (s.subject[0].digest.sha256 = "2".repeat(64)),
      (s) =>
        (s.predicate.buildDefinition.resolvedDependencies[0].digest.gitCommit =
          "b".repeat(40)),
      (s) =>
        (s.predicate.runDetails.metadata.invocationId = run.run.replace(
          "/7/",
          "/8/",
        )),
      (s) =>
        (s.predicate.buildDefinition.externalParameters.workflow.ref =
          "refs/heads/dev"),
      (s) =>
        (s.predicate.buildDefinition.internalParameters.github.event_name =
          "push"),
      (s) => (s.predicate.runDetails.builder.id += "x"),
    ];
    for (const change of changes) {
      const s = statement();
      change(s);
      expect(check(s)).toBe(false);
    }
    expect(
      checkStatement("text/plain", statement(), "monitor", DIGEST, run),
    ).toBe(false);
  });

  const serve = (status: number, body: unknown) =>
    (async () =>
      new Response(JSON.stringify(body), {
        status,
      })) as unknown as typeof fetch;

  test("an authentic publish-workflow bundle is not an approved image build", async () => {
    const { payload } = attestations.attestations[0].bundle.dsseEnvelope;
    const digest = JSON.parse(atob(payload)).subject[0].digest.sha256;
    await expect(
      verifyImage("sandbox", digest, { fetch: serve(200, attestations) }),
    ).rejects.toThrow(/not built by an approved release/);
  });

  test("missing or oversized evidence is rejected", async () => {
    await expect(
      verifyImage("monitor", DIGEST, {
        fetch: serve(404, { message: "Not Found" }),
      }),
    ).rejects.toThrow(/No approved build evidence/);
    const huge = { attestations: [{ bundle: { x: "a".repeat(5 << 20) } }] };
    await expect(
      verifyImage("monitor", DIGEST, { fetch: serve(200, huge) }),
    ).rejects.toThrow(/too large/);
  });
});
