// SPDX-License-Identifier: Apache-2.0

import { defineConfig, devices } from "@playwright/test";

// Browser tests of the UI against a running all-in-one (docs/12-testing-and-quality.md, "Test
// layers"), started by test/webe2e, which passes its URL, its first-user link and the SPKI hash of
// its UI certificate. The browser trusts that key only, rather than ignoring certificate errors.
export default defineConfig({
  testDir: "e2e",
  workers: 1,
  forbidOnly: true,
  reporter: [["list"]],
  outputDir: "test-results",
  use: {
    baseURL: process.env.RPMGR_URL,
    trace: "retain-on-failure",
    launchOptions: { args: [`--ignore-certificate-errors-spki-list=${process.env.RPMGR_SPKI ?? ""}`] },
  },
  projects: [{ name: "chromium", use: { ...devices["Desktop Chrome"] } }],
});
