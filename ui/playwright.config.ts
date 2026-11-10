import { defineConfig } from "@playwright/test";

const BROWSER_PORT = 5179;
const BASE_URL = `http://127.0.0.1:${BROWSER_PORT}`;

export default defineConfig({
  testDir: "./tests/browser",
  testMatch: "*.browser.ts",
  use: { baseURL: BASE_URL, browserName: "chromium", headless: true },
  webServer: {
    command: `bun run dev --port ${BROWSER_PORT}`,
    url: `${BASE_URL}/app/tests/browser/tabs.html`,
    reuseExistingServer: !process.env.CI,
  },
});
