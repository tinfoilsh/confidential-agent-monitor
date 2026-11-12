import { expect, test, type Page } from "@playwright/test";
import type {} from "./passkeys";

const WIDTHS = [390, 1000, 1440];
const HEIGHT = 1000;
const TOLERANCE_PX = 1;
const FIXTURE = "/app/tests/browser/passkeys.html";

async function layout(page: Page) {
  return page.locator(".start-home").evaluate((home) => {
    const selectors = [
      "h1",
      'nav[aria-label="Your Perimeters"] > .start-eyebrow',
      'nav[aria-label="Your Perimeters"] > .start-key-choice',
      'section[aria-label="Your keys"] > .start-eyebrow',
      'section[aria-label="Your keys"] > .start-key-choice',
      ".monitor-actions",
    ];
    return selectors.flatMap((selector) =>
      [...home.querySelectorAll(selector)].map((el) => {
        const { x, y, width, height } = el.getBoundingClientRect();
        return { x, y, width, height };
      }),
    );
  });
}

for (const theme of ["light", "dark"]) {
  for (const width of WIDTHS) {
    test(`home skeleton matches the loaded page at ${width}px in ${theme} mode`, async ({
      page,
    }) => {
      await page.setViewportSize({ width, height: HEIGHT });
      await page.addInitScript(
        (theme) => localStorage.setItem("monitor-theme", theme),
        theme,
      );
      await page.goto(FIXTURE);
      await page
        .getByRole("checkbox", { name: "Remember me for 30 days" })
        .check();
      await page.getByRole("button", { name: "Unlock with passkey" }).click();
      await expect(
        page.getByRole("heading", { name: "Keys unlocked" }),
      ).toBeVisible();

      await page.goto(`${FIXTURE}?home`);
      await expect(
        page.getByRole("heading", { name: "Welcome back" }),
      ).toBeVisible();
      await expect(page.locator("html")).toHaveAttribute("data-theme", theme);
      await expect(
        page.getByText("Loading your keys…", { exact: true }),
      ).toBeAttached();
      await page.evaluate(() => document.fonts.ready);
      await expect(
        page.getByRole("button", { name: "Add a passkey" }),
      ).toBeDisabled();
      await expect(
        page.getByRole("button", { name: "Save recovery key" }),
      ).toBeDisabled();
      const loading = await layout(page);
      expect(loading).toHaveLength(7);
      await page.evaluate(() => window.passkeyFixture.holdDecryption());
      await page.evaluate(() => window.passkeyFixture.releaseKeys());
      await page.evaluate(() => window.passkeyFixture.waitForDecryption());
      await expect(
        page.getByRole("heading", { name: "Welcome back" }),
      ).toBeVisible();
      await expect(
        page.getByRole("heading", { name: "Unlock your keys" }),
      ).not.toBeVisible();
      expect(await layout(page)).toEqual(loading);
      await page.evaluate(() => window.passkeyFixture.releaseDecryption());
      await expect(
        page.getByRole("button", { name: "Add a passkey" }),
      ).toBeEnabled();
      await expect(
        page.getByText("Loading your Perimeters and bunkers…", { exact: true }),
      ).toBeAttached();
      await page.evaluate(() => window.passkeyFixture.releaseInventory());
      await expect(
        page.getByRole("link", { name: /first-perimeter/ }),
      ).toBeVisible();
      await expect(
        page.getByRole("link", { name: /second-perimeter/ }),
      ).toBeVisible();
      await expect(page.getByLabel("Passkey prompts")).toHaveText("0");
      const loaded = await layout(page);
      expect(loaded).toHaveLength(loading.length);
      for (const [index, rect] of loaded.entries())
        for (const dimension of ["x", "y", "width", "height"] as const)
          expect(
            Math.abs(rect[dimension] - loading[index][dimension]),
          ).toBeLessThanOrEqual(TOLERANCE_PX);
    });
  }
}

test("the home skeleton gives way to interactive unlock when no key is saved", async ({
  page,
}) => {
  await page.goto(`${FIXTURE}?home`);
  await expect(
    page.getByRole("heading", { name: "Welcome back" }),
  ).toBeVisible();
  await page.evaluate(() => window.passkeyFixture.releaseKeys());
  await expect(
    page.getByRole("heading", { name: "Unlock your keys" }),
  ).toBeVisible();
  await expect(
    page.getByRole("button", { name: "Unlock with passkey" }),
  ).toBeVisible();
  await expect(
    page.getByRole("heading", { name: "Welcome back" }),
  ).not.toBeVisible();
});
