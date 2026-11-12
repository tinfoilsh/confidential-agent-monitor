import { expect, test, type Page } from "@playwright/test";
import type {} from "./passkeys";

const URL = "/app/tests/browser/passkeys.html";
const CACHE_PREFIX = "tinfoil.terminal.passkey.v1|";
const REMEMBER_MS = 30 * 24 * 60 * 60 * 1000;
const button = (page: Page) =>
  page.getByRole("button", { name: "Unlock with passkey" });
const checkbox = (page: Page) =>
  page.getByRole("checkbox", { name: "Remember me for 30 days" });
async function cached(page: Page) {
  return page.evaluate(
    (prefix) =>
      Object.entries(localStorage)
        .filter(([key]) => key.startsWith(prefix))
        .map(([key, value]) => ({ key, value: JSON.parse(value) })),
    CACHE_PREFIX,
  );
}
async function expectUnlocked(page: Page, user = "user_first") {
  await expect(
    page.getByRole("heading", { name: "Keys unlocked" }),
  ).toBeVisible();
  await expect(page.getByLabel("Key owner")).toHaveText(user);
  const payload = await page.evaluate(() =>
    JSON.stringify(window.passkeyFixture.payload),
  );
  await expect(page.getByLabel("Key payload")).toHaveText(payload);
}
async function remember(page: Page) {
  await checkbox(page).check();
  await button(page).click();
  await expectUnlocked(page);
  expect(await cached(page)).toHaveLength(1);
}

test.beforeEach(async ({ page }) => {
  await page.goto(URL);
  await expect(button(page)).toBeVisible();
});

test("unlock is memory-only unless Remember me is checked", async ({
  page,
}) => {
  await expect(checkbox(page)).not.toBeChecked();
  await button(page).click();
  await expectUnlocked(page);
  expect(await cached(page)).toEqual([]);
  await page.reload();
  await expect(button(page)).toBeVisible();
  await expect(page.getByLabel("Passkey prompts")).toHaveText("0");
});

test("remembered PRF opens the latest envelope after reload without another prompt or extending expiry", async ({
  page,
}) => {
  await remember(page);
  const before = await cached(page);
  expect(before[0].value.prf).toBe(
    await page.evaluate(() => window.passkeyFixture.prf),
  );
  await page.reload();
  await expectUnlocked(page);
  await expect(page.getByLabel("Passkey prompts")).toHaveText("0");
  expect(await cached(page)).toEqual(before);
});

test("cache expires at 30 days and is removed", async ({ page }) => {
  await remember(page);
  const [record] = await cached(page);
  await page.clock.setFixedTime(record.value.saved_at + REMEMBER_MS - 1);
  await page.reload();
  await expectUnlocked(page);
  await page.clock.setFixedTime(record.value.saved_at + REMEMBER_MS);
  await page.reload();
  await expect(button(page)).toBeVisible();
  expect(await cached(page)).toEqual([]);
});

test("another user cannot use the cache, even with identical credential and key IDs", async ({
  page,
}) => {
  await remember(page);
  const before = await cached(page);
  await page.evaluate(() => window.passkeyFixture.switchUser("user_second"));
  await expect(button(page)).toBeVisible();
  await button(page).click();
  await expectUnlocked(page, "user_second");
  expect(await cached(page)).toEqual(before);
});

test("sign-out clears remembered material and a late unfenced ceremony cannot put it back", async ({
  page,
}) => {
  await remember(page);
  await page.evaluate(() => window.passkeyFixture.hold());
  const late = page.evaluate(() => window.passkeyFixture.lateUnlock());
  await expect(page.getByLabel("Passkey prompts")).toHaveText("2");
  expect(await page.evaluate(() => window.passkeyFixture.signOut())).toBe(true);
  expect(await cached(page)).toEqual([]);
  await page.evaluate(() => window.passkeyFixture.release());
  expect(await late).toBe("rejected");
  expect(await cached(page)).toEqual([]);
});

test("an account change while the prompt is open prevents persistence", async ({
  page,
}) => {
  await page.evaluate(() => window.passkeyFixture.hold());
  await checkbox(page).check();
  await button(page).click();
  await expect(page.getByLabel("Passkey prompts")).toHaveText("1");
  await page.evaluate(() => window.passkeyFixture.switchUser("user_second"));
  await page.evaluate(() => window.passkeyFixture.release());
  await expect(button(page)).toBeVisible();
  expect(await cached(page)).toEqual([]);
  await expect(
    page.getByRole("heading", { name: "Keys unlocked" }),
  ).not.toBeVisible();
});

test("a late unlock from a signed-out session cannot overwrite a new sign-in's cache", async ({
  page,
}) => {
  await remember(page);
  await page.evaluate(() => window.passkeyFixture.hold());
  const late = page.evaluate(() => window.passkeyFixture.lateUnlock());
  await expect(page.getByLabel("Passkey prompts")).toHaveText("2");
  expect(await page.evaluate(() => window.passkeyFixture.signOut())).toBe(true);
  await page.evaluate(() => window.passkeyFixture.switchUser("user_first"));
  await page.evaluate(() => window.passkeyFixture.resumeNewPrompts());
  await remember(page);
  const fresh = await cached(page);
  await page.evaluate(() => window.passkeyFixture.release());
  expect(await late).toBe("rejected");
  expect(await cached(page)).toEqual(fresh);
});

test("manual recovery still persists, unlocks, and downloads the same key", async ({
  page,
}) => {
  const result = await page.evaluate(() =>
    window.passkeyFixture.manualRecovery(),
  );
  expect(result.restored).toEqual(result.original);
  expect(result.file?.text).toContain("-----BEGIN TINFOIL");
  expect(result.download).toEqual(result.file);
  expect(await cached(page)).toEqual([]);
});

for (const kind of ["recovery", "dek"] as const) {
  test(`a ${kind} replacement removes the cached material`, async ({
    page,
  }) => {
    await remember(page);
    await page.evaluate((kind) => window.passkeyFixture.invalidate(kind), kind);
    expect(await cached(page)).toEqual([]);
  });
}

test("failed decryption never persists PRF material", async ({ page }) => {
  await page.evaluate(() => window.passkeyFixture.wrongPRF());
  await checkbox(page).check();
  await button(page).click();
  await expect(page.getByRole("alert")).toBeVisible();
  expect(await cached(page)).toEqual([]);
});

test("damaged cached PRF falls back to the passkey prompt", async ({
  page,
}) => {
  await remember(page);
  await page.evaluate((prefix) => {
    const key = Object.keys(localStorage).find((key) =>
      key.startsWith(prefix),
    )!;
    const value = JSON.parse(localStorage.getItem(key)!);
    value.prf = "A".repeat(43);
    localStorage.setItem(key, JSON.stringify(value));
  }, CACHE_PREFIX);
  await page.reload();
  await expect(button(page)).toBeVisible();
  expect(await cached(page)).toEqual([]);
  await button(page).click();
  await expectUnlocked(page);
});

test("unavailable storage lets the user retry without remembering", async ({
  page,
}) => {
  await page.evaluate((prefix) => {
    const set = Storage.prototype.setItem;
    Storage.prototype.setItem = function (key, value) {
      if (key.startsWith(prefix))
        throw new DOMException("Full", "QuotaExceededError");
      set.call(this, key, value);
    };
  }, CACHE_PREFIX);
  await checkbox(page).check();
  await button(page).click();
  await expect(page.getByRole("alert")).toContainText(
    "could not remember your passkey",
  );
  expect(await cached(page)).toEqual([]);
  await checkbox(page).uncheck();
  await button(page).click();
  await expectUnlocked(page);
  expect(await cached(page)).toEqual([]);
});
