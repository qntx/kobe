import { tmpdir } from "node:os";
import { join } from "node:path";

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
  // Tests tagged @webauthn drive the CDP virtual authenticator, which only Chromium has; the
  // remaining tests cover IndexedDB, Web Locks and BroadcastChannel on the other engines.
  projects: [
    { name: "chromium", use: { browserName: "chromium" } },
    { name: "webkit", use: { browserName: "webkit" }, grepInvert: /@webauthn/ },
    {
      name: "firefox",
      use: {
        browserName: "firefox",
        launchOptions: {
          // macOS ≥ 26 TCC-protects ~/Library/Application Support/Firefox: the bundled Nightly
          // exits with "Could not find profile folder" when launched by a terminal without Full
          // Disk Access. Redirect the app-data root (microsoft/playwright#42768); harmless on CI.
          env: { ...process.env, MOZ_APP_DATA: join(tmpdir(), "pw-firefox-appdata") },
        },
      },
      grepInvert: /@webauthn/,
    },
  ],
});

export default config;
