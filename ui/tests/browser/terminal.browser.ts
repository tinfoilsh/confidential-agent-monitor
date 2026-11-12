import { expect, test } from "@playwright/test";

const WIDTHS = [390, 1000, 1440];
const HEIGHT = 900;
const TOLERANCE = 1;
const DESKTOP_ROW_HEIGHT = 48;

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

for (const theme of ["light", "dark"]) {
  for (const width of WIDTHS) {
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
      await expect(row).toContainText("×2");
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
      }
      await row.focus();
      await page.keyboard.press("Enter");
      const child = list
        .locator(".request-stack .request-item > summary")
        .first();
      await expect(child).toBeVisible();
      await child.click();
      await expect(list.getByText("Nobody answered in time.")).toBeVisible();
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
