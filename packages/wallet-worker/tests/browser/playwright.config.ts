import { defineConfig } from "@playwright/test";
import type { PlaywrightTestConfig } from "@playwright/test";

const config: PlaywrightTestConfig = defineConfig({
  testDir: ".",
  testMatch: "*.spec.ts",
  timeout: 60_000,
  workers: 1,
  retries: process.env["CI"] === undefined ? 0 : 1,
  reporter: process.env["CI"] === undefined ? "list" : "github",
  use: {
    baseURL: "http://localhost:4174",
    headless: true,
  },
  webServer: {
    command: "bun ./serve.ts",
    cwd: new URL(".", import.meta.url).pathname,
    url: "http://localhost:4174",
    reuseExistingServer: process.env["CI"] === undefined,
    timeout: 120_000,
  },
});

export default config;
