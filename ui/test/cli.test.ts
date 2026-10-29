import { expect, test } from "bun:test";
import {
  parseKeySyncLaunch,
  canonicalKeySyncRequest,
  confirmationCode,
} from "../src/hosted/contract";
import fixture from "./owner-contract-v1.json";

const sync = fixture.key_sync;
const hash = new URL(sync.launch_url).hash;
const now = sync.request.expires - 1;

test("key sync carries the authenticated user and account without OAuth material", () => {
  const request = parseKeySyncLaunch(hash, now);
  expect(request.user).toBe(sync.request.user);
  expect(request.account).toBe(sync.request.account);
  expect(Object.keys(request).sort()).toEqual([
    "account",
    "expires",
    "hpke_pubkey",
    "request",
    "user",
  ]);
  for (const field of [
    "code",
    "code_challenge",
    "access_token",
    "redirect_uri",
    "callback",
    "sync",
  ])
    expect(() =>
      parseKeySyncLaunch(`${hash}&${field}=unexpected`, now),
    ).toThrow();
  for (const [field, value] of [
    ["user", "not-a-user"],
    ["account", "other"],
    ["request", "short"],
    ["hpke_pubkey", "short"],
  ]) {
    const changed = new URLSearchParams(hash.slice(1));
    changed.set(field, value);
    expect(() => parseKeySyncLaunch(`#${changed}`, now)).toThrow();
  }
});

test("confirmation and encryption context bind key sync to the login's user and account", () => {
  const request = parseKeySyncLaunch(hash, now);
  const original = confirmationCode(
    canonicalKeySyncRequest(request, sync.targets),
  );
  for (const changed of [
    { ...request, user: "user_other" },
    { ...request, account: "personal" },
  ])
    expect(
      confirmationCode(canonicalKeySyncRequest(changed, sync.targets)),
    ).not.toBe(original);
});
