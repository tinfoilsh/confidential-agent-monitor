import { expect, test } from "bun:test";
import {
  mkdirSync,
  mkdtempSync,
  readFileSync,
  readdirSync,
  rmSync,
  statSync,
} from "node:fs";
import { join } from "node:path";
import { tmpdir } from "node:os";
import {
  decodeWrappedKeyRecord,
  encodeWrappedKeyRecord,
} from "@tinfoilsh/passkey-kit";
import { parseMKPayload } from "../src/terminal/contract";
import { devPasskeys } from "../dev/account";
import { DEVICE_ID, ORIGIN, resource, rows } from "../dev/fixtures";
import { isDevice } from "../src/monitor/owner";
import { localRequestAllowed, persistKeyState } from "../dev/local-console";

test("local key-state replacement leaves one private, complete file", () => {
  const directory = mkdtempSync(join(tmpdir(), "monitor-dev-keys-"));
  try {
    const file = join(directory, "keys.json");
    const initial = {
      revision: 0,
      dek_id: null,
      encrypted_mk: null,
      recovery: [],
    };
    persistKeyState(file, initial);
    const next = {
      ...initial,
      revision: 1,
      dek_id: "fixture",
      encrypted_mk: "fixture",
    };
    persistKeyState(file, next);
    expect(JSON.parse(readFileSync(file, "utf8"))).toEqual(next);
    expect(statSync(file).mode & 0o777).toBe(0o600);
    expect(readdirSync(directory)).toEqual(["keys.json"]);
  } finally {
    rmSync(directory, { recursive: true, force: true });
  }
});

test("failed key-state replacement removes its temporary file", () => {
  const directory = mkdtempSync(join(tmpdir(), "monitor-dev-keys-"));
  try {
    const file = join(directory, "keys.json");
    mkdirSync(file);
    expect(() =>
      persistKeyState(file, {
        revision: 1,
        dek_id: null,
        encrypted_mk: null,
        recovery: [],
      }),
    ).toThrow();
    expect(statSync(file).isDirectory()).toBe(true);
    expect(readdirSync(directory)).toEqual(["keys.json"]);
  } finally {
    rmSync(directory, { recursive: true, force: true });
  }
});

test("local resource uses the current MK schema and sandbox fixtures cannot start hosted enrollment", () => {
  expect(
    parseMKPayload({ version: 1, resources: [resource] }).resources[0],
  ).toEqual(resource);
  expect(isDevice(DEVICE_ID)).toBe(true);
  expect(
    rows
      .filter((row) => row.repo.endsWith("sandbox"))
      .map((row) => row.owner_key_mode),
  ).toEqual(["umk", "umk"]);
});

test("development passkey records round-trip through the real record codec", async () => {
  const manager = devPasskeys();
  const key = crypto.getRandomValues(new Uint8Array(32));
  const created = await manager.createAndWrapKey({
    key,
    user: { id: new Uint8Array(32), name: "dev", displayName: "Dev" },
  });
  const record = decodeWrappedKeyRecord(
    encodeWrappedKeyRecord(created.wrappedKey),
  );
  const recovered = await manager.recoverKey({ wrappedKeys: [record] });
  expect(recovered.key).toEqual(key);
});

test("local API and proxy accept only the exact loopback host and same-origin callers", () => {
  const host = new URL(ORIGIN).host;
  expect(localRequestAllowed({ headers: { host } })).toBe(true);
  expect(
    localRequestAllowed({
      headers: { host, origin: ORIGIN, "sec-fetch-site": "same-origin" },
    }),
  ).toBe(true);
  expect(
    localRequestAllowed({ headers: { host, origin: "https://example.com" } }),
  ).toBe(false);
  expect(
    localRequestAllowed({ headers: { host, "sec-fetch-site": "cross-site" } }),
  ).toBe(false);
  expect(
    localRequestAllowed({
      headers: { host: "example.com:5176", origin: ORIGIN },
    }),
  ).toBe(false);
});
