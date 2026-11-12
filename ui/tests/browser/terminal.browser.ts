import { expect, test } from "@playwright/test";

const WIDTHS = [390, 1000, 1440];
const HEIGHT = 900;
const TOLERANCE = 1;
const DESKTOP_ROW_HEIGHT = 48;
const PETROL = "rgb(5, 37, 46)";
const BONE = "rgb(249, 248, 246)";
const SWITCH_COLORS = {
  light: { track: "rgb(4, 120, 87)", thumb: "rgb(255, 255, 255)" },
  dark: { track: "rgb(110, 231, 183)", thumb: "rgb(28, 28, 30)" },
};

test("an existing group override can change all tools and clear child exceptions", async ({
  page,
}) => {
  await page.goto(
    "/app/tests/browser/terminal.html?root-override#agents/new-bunker",
  );
  await page
    .getByRole("button", { name: "Actions for tinfoil-websearch" })
    .click();
  const group = page.getByLabel("Use permission", { exact: true });
  await expect(group).toHaveValue("");
  await group.selectOption("allow");
  await expect(group).toHaveValue("allow");
  await page
    .locator('.access-action-group > summary[aria-label="Use"]')
    .click();
  await expect(page.getByLabel("Search the web permission")).toHaveValue(
    "allow",
  );
  await expect(page.getByLabel("Fetch web pages permission")).toHaveValue(
    "allow",
  );
});

test("a lone tool still exposes its inherited permission control", async ({
  page,
}) => {
  await page.goto(
    "/app/tests/browser/terminal.html?single-tool#agents/new-bunker",
  );
  await page
    .getByRole("button", { name: "Actions for tinfoil-websearch" })
    .click();
  const permission = page.getByLabel("Use · Search the web permission");
  await expect(permission).toHaveValue("ask");
  await permission.selectOption("off");
  await expect(permission).toHaveValue("off");
});

test("approval counts include every tool and update after approval", async ({
  page,
}) => {
  await page.goto("/app/tests/browser/terminal.html?review#connections");
  const sidebar = page.locator('#tree a[href="#connections"] .nav-count');
  const needsApproval = page.getByRole("region", { name: "Needs approval" });
  await expect(sidebar).toHaveText("3 waiting for approval");
  await expect(
    needsApproval.getByRole("heading", { name: "Needs approval 3" }),
  ).toBeVisible();
  await expect(page).toHaveTitle("(3) Perimeter");
  await needsApproval.locator(".approval-tools-item > summary").click();
  await needsApproval
    .getByRole("button", { name: "Approve tools", exact: true })
    .click();
  await expect(sidebar).toHaveText("1 waiting for approval");
  await expect(
    needsApproval.getByRole("heading", { name: "Needs approval 1" }),
  ).toBeVisible();
  await expect(page).toHaveTitle("(1) Perimeter");
  await expect(needsApproval.getByText("Connect to example.com")).toBeVisible();
  await page.evaluate(() => {
    location.hash = "#activity";
  });
  await expect(
    page.getByRole("link", { name: /^Review \(\d+:\d{2}\)$/ }),
  ).toBeVisible();
});

for (const theme of ["light", "dark"] as const) {
  for (const width of WIDTHS) {
    test(`settings rows join their headers and switches show their state at ${width}px in ${theme} mode`, async ({
      page,
    }) => {
      await page.setViewportSize({ width, height: HEIGHT });
      await page.addInitScript(
        (theme) => localStorage.setItem("monitor-theme", theme),
        theme,
      );
      await page.goto("/app/tests/browser/terminal.html#connections");
      await page.evaluate(() => document.fonts.ready);
      for (const name of ["Payments", "Dangerous"]) {
        const section = page.locator(".settings-section").filter({
          has: page.getByRole("heading", { name, exact: true }),
        });
        await section.scrollIntoViewIfNeeded();
        const header = (await section
          .locator(":scope > .resource-heading")
          .boundingBox())!;
        const rows = await section.locator(":scope > label").all();
        let bottom = header.y + header.height;
        for (const row of rows) {
          const box = (await row.boundingBox())!;
          expect(Math.abs(box.y - bottom)).toBeLessThanOrEqual(TOLERANCE);
          bottom = box.y + box.height;
        }
        const panel = (await section.boundingBox())!;
        expect(Math.abs(panel.y + panel.height - bottom)).toBeLessThanOrEqual(
          TOLERANCE,
        );
      }

      const payment = page.getByRole("switch", {
        name: /^Ask before any payment/,
      });
      const inference = page.getByRole("switch", {
        name: /^Allow AI inference without asking/,
      });
      await expect(payment).toBeChecked();
      await expect(inference).not.toBeChecked();
      await expect(payment).toHaveCSS(
        "background-color",
        SWITCH_COLORS[theme].track,
      );
      await expect
        .poll(() =>
          payment.evaluate(
            (el) => getComputedStyle(el, "::before").backgroundColor,
          ),
        )
        .toBe(SWITCH_COLORS[theme].thumb);
      await payment.uncheck();
      await inference.check();
      await expect(payment).not.toHaveCSS(
        "background-color",
        SWITCH_COLORS[theme].track,
      );
      await expect(inference).toHaveCSS(
        "background-color",
        SWITCH_COLORS[theme].track,
      );
      await page.evaluate(() => {
        location.hash = "#agents";
      });
      await expect(payment).toHaveCount(0);
      await page.evaluate(() => {
        location.hash = "#connections";
      });
      await expect(payment).not.toBeChecked();
      await expect(inference).toBeChecked();
      await payment.check();

      const unrestricted = page.getByRole("switch", {
        name: /^Allow everything/,
      });
      await unrestricted.check();
      const confirmation = page.getByRole("dialog", {
        name: "Allow everything?",
      });
      await expect(confirmation).toBeVisible();
      await confirmation
        .getByRole("button", { name: "Cancel", exact: true })
        .click();
      await expect(confirmation).not.toBeVisible();
      await expect(unrestricted).not.toBeChecked();
      expect(
        await page
          .locator("#workspace")
          .evaluate((el) => el.scrollWidth - el.clientWidth),
      ).toBeLessThanOrEqual(TOLERANCE);
      await page.locator(".settings").screenshot({
        path: `test-results/settings-${width}-${theme}.png`,
        animations: "disabled",
      });
    });

    test(`request rows and shared headers fit at ${width}px in ${theme} mode`, async ({
      page,
    }) => {
      const errors: string[] = [];
      page.on("pageerror", (error) => errors.push(error.message));
      await page.setViewportSize({ width, height: HEIGHT });
      await page.addInitScript(
        (theme) => localStorage.setItem("monitor-theme", theme),
        theme,
      );
      await page.goto("/app/tests/browser/terminal.html#activity");
      const list = page.locator(".request-list");
      const row = list.locator(":scope > .request-item > summary").first();
      await expect(row).toContainText("Connect to registry.npmjs.org:443");
      await expect(row).toContainText("new-bunker");
      await expect(row.locator(".resource-link strong")).toBeVisible();
      await expect(row.locator(".request-count")).toHaveText(
        "Request count: 2",
      );
      await expect(row).toHaveAccessibleName(
        /Request: .*Bunker: new-bunker.*Service: network.*Status: Expired.*Requested at:/,
      );
      const header = list.locator(":scope > .resource-heading");
      const box = (await list.boundingBox())!;
      const heading = (await header.boundingBox())!;
      expect(heading.x).toBeLessThan(box.x);
      expect(heading.x + heading.width).toBeGreaterThan(box.x + box.width);
      expect(
        await header.evaluate((el) => {
          const rect = el.getBoundingClientRect();
          return (
            document
              .elementFromPoint(rect.left + 2, rect.top + rect.height / 2)
              ?.closest(".resource-heading") === el
          );
        }),
      ).toBe(true);
      expect(
        await page
          .locator("#workspace")
          .evaluate((el) => el.scrollWidth - el.clientWidth),
      ).toBeLessThanOrEqual(TOLERANCE);
      if (width === WIDTHS.at(-1)) {
        expect((await row.boundingBox())!.height).toBeLessThanOrEqual(
          DESKTOP_ROW_HEIGHT + TOLERANCE,
        );
        await expect(page.getByText("Status", { exact: true })).toBeVisible();
        const countHeading = (await header
          .locator("+ .request-table-heading .request-count")
          .boundingBox())!;
        const count = (await row.locator(".request-count").boundingBox())!;
        expect(
          Math.abs(countHeading.x + countHeading.width - count.x - count.width),
        ).toBeLessThanOrEqual(TOLERANCE);
      }
      await row.focus();
      await page.keyboard.press("Enter");
      const child = list
        .locator(".request-stack .request-item > summary")
        .first();
      await expect(child).toBeVisible();
      await expect(child.locator(".resource-link strong")).toBeVisible();
      await expect(child.locator(".request-count")).toHaveText(
        "Request count: 1",
      );
      const parentCount = (await row.locator(".request-count").boundingBox())!;
      const childCount = (await child.locator(".request-count").boundingBox())!;
      expect(
        Math.abs(
          parentCount.x + parentCount.width - childCount.x - childCount.width,
        ),
      ).toBeLessThanOrEqual(TOLERANCE);
      await child.click();
      await expect(list.getByText("Nobody answered in time.")).toBeVisible();
      const detail = list.locator(".request-inline").first();
      expect(
        await detail.evaluate((el) => el.scrollWidth - el.clientWidth),
      ).toBeLessThanOrEqual(TOLERANCE);
      if (width === WIDTHS.at(-1)) {
        const bunker = (await detail
          .getByText("Bunker", { exact: true })
          .boundingBox())!;
        const service = (await detail
          .getByText("Service", { exact: true })
          .boundingBox())!;
        const requested = (await detail
          .getByText("Requested", { exact: true })
          .boundingBox())!;
        const review = (await detail
          .getByText("Review", { exact: true })
          .boundingBox())!;
        expect(Math.abs(bunker.y - service.y)).toBeLessThanOrEqual(TOLERANCE);
        expect(Math.abs(bunker.y - requested.y)).toBeLessThanOrEqual(TOLERANCE);
        expect(bunker.x).toBeLessThan(service.x);
        expect(service.x).toBeLessThan(requested.x);
        expect(review.y).toBeGreaterThan(requested.y + requested.height);
      }
      await row.click();
      await expect(child).not.toBeVisible();
      await page.evaluate(() => {
        location.hash = "#agents/new-bunker";
      });
      const advanced = page.locator(".agent-maintenance > summary");
      await expect(advanced).toBeVisible();
      await advanced.hover();
      const outer = (await page.locator(".agent-maintenance").boundingBox())!;
      const inner = (await advanced.boundingBox())!;
      expect(inner.x - outer.x).toBeLessThanOrEqual(TOLERANCE);
      expect(outer.width - inner.width).toBeLessThanOrEqual(TOLERANCE * 2);
      await advanced.click();
      await expect(
        page.getByText("Only needed if you set up SSH by hand."),
      ).toBeVisible();
      const access = page.getByRole("button", {
        name: "Actions for tinfoil-websearch",
      });
      await access.click();
      const search = page.getByLabel("Search the web permission");
      await expect(search).toBeVisible();
      await expect(search).toHaveValue("ask");
      await search.selectOption("off");
      await expect(search).toHaveValue("off");
      await expect(page.getByLabel("Fetch web pages permission")).toHaveValue(
        "ask",
      );
      await page.evaluate(() => {
        location.hash = "#connections";
      });
      await expect(
        page.locator(".resource-heading").getByRole("searchbox"),
      ).toBeVisible();
      expect(
        await page
          .locator("#workspace")
          .evaluate((el) => el.scrollWidth - el.clientWidth),
      ).toBeLessThanOrEqual(TOLERANCE);
      expect(errors).toEqual([]);
      await page.goto(
        "/app/tests/browser/terminal.html?proposals#activity/proposals",
      );
      const history = page.locator(".proposal-history-row");
      await expect(
        history.getByRole("link", { name: /Update network access/ }),
      ).toBeVisible();
      await expect(
        page.getByRole("link", { name: "Review in Permissions" }),
      ).toBeVisible();
      if (width === WIDTHS.at(-1)) {
        const title = (await history.locator(".resource-link").boundingBox())!;
        const meta = (await history.locator(".resource-meta").boundingBox())!;
        expect(meta.x).toBeGreaterThanOrEqual(title.x + title.width);
        expect(
          Math.abs(title.y + title.height / 2 - meta.y - meta.height / 2),
        ).toBeLessThanOrEqual(TOLERANCE);
      }
      expect(
        await history.evaluate((el) => el.scrollWidth - el.clientWidth),
      ).toBeLessThanOrEqual(TOLERANCE);
    });
  }
}

for (const width of WIDTHS) {
  test(`theme selection stays readable on the dark sidebar at ${width}px`, async ({
    page,
  }) => {
    await page.setViewportSize({ width, height: HEIGHT });
    await page.emulateMedia({ colorScheme: "light" });
    await page.addInitScript(() =>
      localStorage.setItem("monitor-theme", "light"),
    );
    await page.goto("/app/tests/browser/terminal.html#connections");
    const menu = page.getByRole("button", { name: "Toggle navigation" });
    if (await menu.isVisible()) await menu.click();
    const themes = page.getByRole("group", { name: "Color theme" });
    for (const [name, resolved] of [
      ["Light theme", "light"],
      ["Dark theme", "dark"],
      ["System theme", "light"],
    ]) {
      const selected = themes.getByRole("button", { name, exact: true });
      await selected.click();
      await expect(page.locator("html")).toHaveAttribute(
        "data-theme",
        resolved,
      );
      await expect(selected).toHaveAttribute("aria-pressed", "true");
      await expect(themes).toHaveCSS("background-color", PETROL);
      await expect(themes.locator(".tab-bar-pill")).toHaveCSS(
        "background-color",
        BONE,
      );
      await expect(selected.locator(".icon")).toHaveCSS("color", PETROL);
    }
    await page.emulateMedia({ colorScheme: "dark" });
    await expect(page.locator("html")).toHaveAttribute("data-theme", "dark");
    await expect(
      themes.getByRole("button", { name: "System theme" }),
    ).toHaveAttribute("aria-pressed", "true");
    await page.keyboard.press("ArrowRight");
    await expect(
      themes.getByRole("button", { name: "Light theme" }),
    ).toHaveAttribute("aria-pressed", "true");
    await expect(page.locator("html")).toHaveAttribute("data-theme", "light");
    await themes.screenshot({
      path: `test-results/theme-switch-${width}.png`,
      animations: "disabled",
    });
  });
}
