// SPDX-License-Identifier: Apache-2.0

import { defineConfig, devices } from "@playwright/test";

// The screenshots of the user guide (docs/guide/images/README.md), taken in light theme at
// 1440×900 against the seeded all-in-one that test/webe2e's TestScreens runs; it passes its URL
// and the SPKI hash of its UI certificate, which the browser trusts alone.
export default defineConfig({
  testDir: "screens",
  workers: 1,
  forbidOnly: true,
  timeout: 300_000,
  reporter: [["list"]],
  outputDir: "test-results/screens",
  use: {
    baseURL: process.env.RPMGR_URL,
    colorScheme: "light",
    locale: "en-GB",
    timezoneId: "UTC",
    launchOptions: { args: [`--ignore-certificate-errors-spki-list=${process.env.RPMGR_SPKI ?? ""}`] },
  },
  projects: [{ name: "chromium", use: { ...devices["Desktop Chrome"], viewport: { width: 1440, height: 900 } } }],
});
