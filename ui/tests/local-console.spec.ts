import { expect, test } from "bun:test";
import {
  decodeWrappedKeyRecord,
  encodeWrappedKeyRecord,
} from "@tinfoilsh/passkey-kit";
import { parseMKPayload } from "../src/hosted/contract";
import { devPasskeys } from "../dev/account";
import { DEVICE_ID, ORIGIN, resource, rows } from "../dev/fixtures";
import { isDevice } from "../src/owner";
import { localRequestAllowed } from "../dev/local-console";

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
      headers: { host: "example.com:5175", origin: ORIGIN },
    }),
  ).toBe(false);
});
