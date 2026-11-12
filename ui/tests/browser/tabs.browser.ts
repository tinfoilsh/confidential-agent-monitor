import { expect, test, type Locator } from "@playwright/test";

const WIDTHS = [360, 820, 1440];
const VIEWPORT_HEIGHT = 900;
const LAYOUT_TOLERANCE_PX = 1;
const PETROL = "rgb(5, 37, 46)";
const BONE = "rgb(249, 248, 246)";
const COLORS = {
  light: {
    background: PETROL,
    foreground: BONE,
    hover: "rgb(8, 51, 63)",
    selection: "rgb(255, 255, 255)",
  },
  dark: {
    background: BONE,
    foreground: PETROL,
    hover: "rgb(240, 244, 244)",
    selection: BONE,
  },
};

async function expectAligned(track: Locator) {
  await expect
    .poll(() =>
      track.evaluate((element) => {
        const selected = element
          .querySelector('[aria-pressed="true"]')!
          .getBoundingClientRect();
        const pill = element
          .querySelector(".tab-bar-pill")!
          .getBoundingClientRect();
        return Math.max(
          Math.abs(selected.left - pill.left),
          Math.abs(selected.width - pill.width),
        );
      }),
    )
    .toBeLessThanOrEqual(LAYOUT_TOLERANCE_PX);
}

for (const theme of ["light", "dark"] as const) {
  for (const width of WIDTHS) {
    test(`animated tabs fit ${width}px in ${theme} mode`, async ({ page }) => {
      await page.setViewportSize({ width, height: VIEWPORT_HEIGHT });
      await page.goto("/app/tests/browser/tabs.html");
      await page.evaluate((theme) => {
        document.documentElement.dataset.theme = theme;
      }, theme);
      await page.evaluate(async () => {
        await document.fonts.ready;
      });
      const action = page.getByRole("button", { name: "Expand bunker label" });
      await expect(action).toHaveCSS(
        "background-color",
        COLORS[theme].background,
      );
      await expect(action).toHaveCSS("color", COLORS[theme].foreground);
      await action.hover();
      await expect(action).toHaveCSS("background-color", COLORS[theme].hover);
      const track = page.getByRole("group", { name: "Usage type" });
      await expectAligned(track);
      await track.getByRole("button", { name: "API", exact: true }).focus();
      for (const key of ["ArrowDown", "ArrowUp"]) {
        await page.keyboard.press(key);
        await expect(page.getByRole("status")).toHaveText("api");
        await expect(
          track.getByRole("button", { name: "API", exact: true }),
        ).toBeFocused();
      }
      await page.keyboard.press("ArrowRight");
      await expect(
        track.getByRole("button", { name: "Containers", exact: true }),
      ).toBeFocused();
      await expect(page.getByRole("status")).toHaveText("containers");
      await expectAligned(track);
      await page.keyboard.press("End");
      await page.getByRole("button", { name: "Expand bunker label" }).click();
      await expect(
        track.getByRole("button", {
          name: "Bunkers and persistent workspaces",
        }),
      ).toHaveAttribute("aria-pressed", "true");
      await expectAligned(track);
      const overflow = await page.evaluate(
        () => document.documentElement.scrollWidth - innerWidth,
      );
      expect(overflow).toBeLessThanOrEqual(LAYOUT_TOLERANCE_PX);
      await expect(track.locator(".tab-bar-pill")).toHaveCSS(
        "background-color",
        COLORS[theme].selection,
      );
      await expect(track.locator('[aria-pressed="true"]')).toHaveCSS(
        "color",
        "rgb(5, 37, 46)",
      );
      await page.screenshot({
        path: `test-results/tabs-${width}-${theme}.png`,
      });
      await page.getByRole("button", { name: "Clear selection" }).click();
      await expect(track.locator(".tab-bar-pill")).toHaveCount(0);
    });
  }
}

test("reduced motion updates selection without animation", async ({ page }) => {
  await page.emulateMedia({ reducedMotion: "reduce" });
  await page.goto("/app/tests/browser/tabs.html");
  const track = page.getByRole("group", { name: "Usage type" });
  await track.getByRole("button", { name: "Containers", exact: true }).click();
  await expectAligned(track);
  await expect(track.locator(".tab-bar-pill")).toHaveCSS(
    "transition-duration",
    "0s",
  );
});
