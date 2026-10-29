import {
  AllOf,
  Identity,
  OIDCBuildSignerURI,
  OIDCBuildTrigger,
  OIDCRunnerEnvironment,
  OIDCSourceRepositoryRef,
  OIDCSourceRepositoryURI,
  SigstoreVerifier,
  type SigstoreBundle,
  type TrustedRoot,
  type VerificationPolicy,
} from "@freedomofpress/sigstore-browser";
import { sha256 } from "@noble/hashes/sha2.js";
import { bytesToHex, utf8ToBytes } from "@noble/hashes/utils.js";
import { parseDocument } from "yaml";
// Sigstore public-good trusted root, as compiled into tinfoil-js verifier c7f0a57.
import SIGSTORE_ROOT from "./sigstore-root.json";

export type Workload = "monitor" | "sandbox";
const REPOS: Record<Workload, string> = {
  monitor: "confidential-agent-monitor",
  sandbox: "confidential-agent-sandbox",
};
const BYTES_PER_GB = 1_000_000_000;
const OIDC_ISSUER = "https://token.actions.githubusercontent.com";
const BUILD_REF = "refs/heads/main";
const BUNDLE_V03 = "application/vnd.dev.sigstore.bundle.v0.3+json";
const IN_TOTO = "application/vnd.in-toto+json";
const SLSA_V1 = "https://slsa.dev/provenance/v1";
const MAX_PROOF_BYTES = 4 << 20;
const MAX_BUNDLES = 16;
const OWNER_KEY = /^ed25519:[A-Za-z0-9+/]{43}=$/;
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;
const BUCKET =
  /^s3:\/\/[a-z0-9.-]+\?prefix=containers%2F([0-9a-f]{64})%2F[A-Za-z0-9-]+%2F&region=[a-z0-9-]+$/;

const reject = (reason: string): never => {
  throw new Error(`The attested configuration is not approved: ${reason}.`);
};

// Plain YAML only: no aliases, merge keys, duplicate keys or unresolved tags.
export function strictYAML(text: string): unknown {
  const doc = parseDocument(text, {
    schema: "core",
    uniqueKeys: true,
    merge: false,
    strict: true,
    prettyErrors: false,
  });
  try {
    if (!doc.errors.length && !doc.warnings.length)
      return doc.toJS({ maxAliasCount: 0 });
  } catch {}
  return reject("it is not plain YAML");
}

// Measured env strings from an inventory copy of a config, which only locates
// resources; the attested config is checked against the template separately.
export function measuredEnv(config: string | undefined) {
  const env: Record<string, string> = {};
  const doc = strictYAML(config ?? "") as {
    containers?: { env?: Record<string, unknown>[] }[];
  } | null;
  for (const container of doc?.containers ?? [])
    for (const entry of container?.env ?? [])
      for (const [name, value] of Object.entries(entry ?? {}))
        if (typeof value === "string") env[name] = value;
  return env;
}

type Substitution = (path: string[], value: unknown) => boolean;

// The complete config equals the template except where a substitution validates.
function match(t: unknown, a: unknown, path: string[], sub: Substitution) {
  if (sub(path, a)) return;
  const at = path.join(".") || "root";
  if (Array.isArray(t)) {
    if (!Array.isArray(a) || a.length !== t.length) reject(`${at} differs`);
    t.forEach((v, i) => match(v, (a as unknown[])[i], [...path, `${i}`], sub));
  } else if (t && typeof t === "object") {
    if (!a || typeof a !== "object" || Array.isArray(a))
      reject(`${at} differs`);
    const keys = Object.keys(t).sort();
    if (
      keys.join("\0") !==
      Object.keys(a as object)
        .sort()
        .join("\0")
    )
      reject(`${at} has different fields`);
    for (const k of keys)
      match(
        (t as Record<string, unknown>)[k],
        (a as Record<string, unknown>)[k],
        [...path, k],
        sub,
      );
  } else if (t !== a) reject(`${at} differs`);
}

const envAt = (path: string[], name: string) =>
  path.length === 5 &&
  path[0] === "containers" &&
  path[2] === "env" &&
  path[4] === name;

// Returns the image digest, whose build evidence must still be verified.
function check(
  workload: Workload,
  template: string,
  config: Uint8Array,
  env: Record<string, (value: string) => boolean>,
  size?: string,
): string {
  const image = new RegExp(
    `^ghcr\\.io/tinfoilsh/${REPOS[workload]}@sha256:([0-9a-f]{64})$`,
  );
  let digest: string | undefined;
  match(
    strictYAML(template),
    strictYAML(new TextDecoder("utf-8", { fatal: true }).decode(config)),
    [],
    (path, value) => {
      if (
        path.length === 3 &&
        path[0] === "containers" &&
        path[2] === "image"
      ) {
        const found = typeof value === "string" && image.exec(value)?.[1];
        if (!found || (digest && digest !== found)) reject("unexpected image");
        digest = found as string;
        return true;
      }
      if (
        size &&
        path.length === 3 &&
        path[0] === "volumes" &&
        path[2] === "size"
      ) {
        if (value !== size) reject("unexpected volume size");
        return true;
      }
      for (const [name, valid] of Object.entries(env))
        if (envAt(path, name)) {
          if (typeof value !== "string" || !valid(value))
            reject(`${name} differs`);
          return true;
        }
      return false;
    },
  );
  return digest ?? reject("no image");
}

export const monitorDigest = (
  template: string,
  config: Uint8Array,
  expect: { owner: string; bucket: string; credentials: string },
) =>
  check("monitor", template, config, {
    MONITOR_OWNER_PUBLIC_KEY: (v) => OWNER_KEY.test(v) && v === expect.owner,
    TINFOIL_STORAGE_BUCKET: (v) => v === expect.bucket,
    AWS_CONTAINER_CREDENTIALS_FULL_URI: (v) => v === expect.credentials,
  });

export const sandboxDigest = (
  template: string,
  config: Uint8Array,
  expect: { owner: string; instance_id: string; size: string },
) =>
  check(
    "sandbox",
    template,
    config,
    {
      SANDBOX_OWNER_PUBLIC_KEY: (v) => OWNER_KEY.test(v) && v === expect.owner,
      SANDBOX_INSTANCE_ID: (v) => UUID.test(v) && v === expect.instance_id,
      NO_MONITOR: (v) => v === "",
    },
    expect.size,
  );

// The rendered size of the sandbox's own workspace volume, as provisioning
// writes it (services.FormatVolumeSize): whole decimal GB, otherwise bytes.
export const volumeSize = (bytes: number) =>
  bytes % BYTES_PER_GB === 0 ? `${bytes / BYTES_PER_GB}GB` : `${bytes}B`;

// A Monitor bucket names the storage owner it belongs to by hash.
export function bucketOwnedBy(bucket: string, account: string, user: string) {
  const owner = account === "personal" ? `user:${user}` : `org:${account}`;
  return BUCKET.exec(bucket)?.[1] === bytesToHex(sha256(utf8ToBytes(owner)));
}

// Policy for the certificate itself; equal source and signer commits tie the
// build to the main commit it ran from.
type BuildRun = { commit: string; run: string };
const signerOf = (repo: string) =>
  `https://github.com/tinfoilsh/${repo}/.github/workflows/tinfoil-release.yml@${BUILD_REF}`;
const buildPolicy = (
  repo: string,
  seen: (run: BuildRun) => void,
): VerificationPolicy => {
  const signer = signerOf(repo);
  return new AllOf([
    new Identity({ identity: signer, issuer: OIDC_ISSUER }),
    new OIDCBuildSignerURI(signer),
    new OIDCSourceRepositoryURI(`https://github.com/tinfoilsh/${repo}`),
    new OIDCSourceRepositoryRef(BUILD_REF),
    new OIDCBuildTrigger("workflow_dispatch"),
    new OIDCRunnerEnvironment("github-hosted"),
    {
      verify(cert) {
        const commit = cert.extSourceRepositoryDigest?.sourceRepositoryDigest;
        const run = cert.extRunInvocationURI?.runInvocationURI ?? "";
        if (
          !commit ||
          !/^[0-9a-f]{40}$/.test(commit) ||
          commit !== cert.extBuildSignerDigest?.buildSignerDigest ||
          !run.startsWith(`https://github.com/tinfoilsh/${repo}/actions/runs/`)
        )
          throw new Error("The build certificate does not identify its run.");
        seen({ commit, run });
      },
    },
  ]);
};

// The signed SLSA statement must describe the image and the same workflow,
// commit and run as the verified certificate.
export function checkStatement(
  payloadType: string,
  statement: any,
  workload: Workload,
  digest: string,
  build: BuildRun,
) {
  const repo = REPOS[workload];
  const definition = statement?.predicate?.buildDefinition;
  const workflow = definition?.externalParameters?.workflow;
  const github = definition?.internalParameters?.github;
  const details = statement?.predicate?.runDetails;
  return (
    payloadType === IN_TOTO &&
    statement.predicateType === SLSA_V1 &&
    statement.subject?.some(
      (s: { name?: string; digest?: { sha256?: string } }) =>
        s.name === `ghcr.io/tinfoilsh/${repo}` && s.digest?.sha256 === digest,
    ) &&
    workflow?.repository === `https://github.com/tinfoilsh/${repo}` &&
    workflow.ref === BUILD_REF &&
    workflow.path === ".github/workflows/tinfoil-release.yml" &&
    github?.event_name === "workflow_dispatch" &&
    github.runner_environment === "github-hosted" &&
    definition.resolvedDependencies?.[0]?.digest?.gitCommit === build.commit &&
    details?.builder?.id === signerOf(repo) &&
    details.metadata?.invocationId === build.run
  );
}

async function bounded(response: Response) {
  const reader = response.body?.getReader();
  const chunks: Uint8Array[] = [];
  for (let length = 0; reader;) {
    const { done, value } = await reader.read();
    if (done) break;
    length += value.length;
    if (length > MAX_PROOF_BYTES) {
      await reader.cancel();
      throw new Error("The build evidence is too large.");
    }
    chunks.push(value);
  }
  return new TextDecoder().decode(
    await new Blob(chunks as BlobPart[]).arrayBuffer(),
  );
}

// Accepts an image only with Sigstore provenance from the approved release
// workflow, including its transparency-log inclusion proof.
export async function verifyImage(
  workload: Workload,
  digest: string,
  {
    fetch = globalThis.fetch,
    root = SIGSTORE_ROOT as TrustedRoot,
    signal,
  }: {
    fetch?: typeof globalThis.fetch;
    root?: TrustedRoot;
    signal?: AbortSignal;
  } = {},
) {
  const repo = REPOS[workload];
  const response = await fetch(
    `https://api.github.com/repos/tinfoilsh/${repo}/attestations/sha256:${digest}`,
    {
      headers: {
        Accept: "application/vnd.github+json",
        "X-GitHub-Api-Version": "2022-11-28",
      },
      credentials: "omit",
      redirect: "error",
      cache: "no-store",
      signal,
    },
  );
  if (!response.ok)
    throw new Error(
      `No approved build evidence exists for this ${workload} image.`,
    );
  const listed = JSON.parse(await bounded(response))?.attestations;
  const verifier = new SigstoreVerifier({
    tlogThreshold: 1,
    ctlogThreshold: 1,
  });
  await verifier.loadSigstoreRoot(root);
  for (const { bundle } of Array.isArray(listed)
    ? listed.slice(0, MAX_BUNDLES)
    : []) {
    try {
      if (bundle?.mediaType !== BUNDLE_V03) continue;
      let build: BuildRun | undefined;
      const { payloadType, payload } = await verifier.verifyDsse(
        bundle as SigstoreBundle,
        buildPolicy(repo, (run) => (build = run)),
      );
      const statement = JSON.parse(new TextDecoder().decode(payload));
      if (
        build &&
        checkStatement(payloadType, statement, workload, digest, build)
      )
        return;
    } catch {}
  }
  throw new Error(
    `This ${workload} image was not built by an approved release.`,
  );
}
