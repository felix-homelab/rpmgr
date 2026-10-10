// SPDX-License-Identifier: Apache-2.0

import { expect, test } from "@playwright/test";
import { email, expectAccessible, password, totp, watchCSP } from "./helpers";

// The flows of docs/09-web-ui.md, "Testing the UI": first-run setup, sign-in with and without a
// second factor, the step-up prompt, token creation and revocation, the settings, sign-out; each
// page under the controller's CSP, with no violation, nothing in browser storage, and no
// accessibility violation that axe finds.
test.describe.configure({ mode: "serial" });

test("first-run setup creates the first user and signs them in", async ({ page }) => {
  const violations = await watchCSP(page);
  const res = await page.goto(process.env.RPMGR_SETUP!);
  expect(res?.headers()["content-security-policy"]).toMatch(/style-src 'self' 'nonce-[A-Za-z0-9+/=]+'/);
  await expect(page.getByRole("heading", { name: "Create the first account" })).toBeVisible();
  await expect(page).toHaveURL(/\/setup$/); // the token left the address bar
  await expectAccessible(page);

  await page.getByLabel("E-mail address").fill(email);
  await page.getByLabel("Your name").fill("Ada");
  await page.getByLabel("New password", { exact: true }).fill(password);
  await page.getByLabel("Repeat the new password").fill(password);
  await page.getByRole("button", { name: "Create the account" }).click();
  await expect(page.getByText("Signed in as Ada")).toBeVisible();
  await expectAccessible(page);
  expect(await page.evaluate(() => [localStorage.length, sessionStorage.length])).toEqual([0, 0]);
  expect(violations).toEqual([]);
});

test("signs in, creates an API token with a step-up, sets up an authenticator and signs in with it", async ({ page }) => {
  const violations = await watchCSP(page);
  await page.goto("/");
  await expect(page).toHaveURL(/\/login\?redirect=/);
  await expectAccessible(page);
  await page.getByLabel("E-mail address").fill(email);
  await page.getByLabel("Password", { exact: true }).fill("wrong password!");
  await page.getByRole("button", { name: "Sign in" }).click();
  await expect(page.getByRole("alert")).toHaveText("The e-mail address or the password is wrong.");
  await page.getByLabel("Password", { exact: true }).fill(password);
  await page.getByRole("button", { name: "Sign in" }).click();
  await expect(page.getByText("Signed in as Ada")).toBeVisible();
  await expect(page.getByRole("region", { name: "Traffic, last 24 hours" }).getByText(/^In 0 B · out 0 B/)).toBeVisible();
  await expectAccessible(page);

  // The instance settings, which the first user changes as the Instance Admin.
  await page.getByRole("link", { name: "Settings" }).click();
  const instance = page.getByRole("region", { name: "Instance settings" });
  await expect(instance.getByLabel("Keep hourly statistics (days)")).toHaveValue(/^\d+$/);
  await expectAccessible(page);
  await instance.getByLabel("Keep hourly statistics (days)").fill("30");
  await instance.getByRole("button", { name: "Save" }).click();
  await expect(instance.getByRole("status")).toHaveText("Saved.");
  await expect(instance.getByLabel("Keep hourly statistics (days)")).toHaveValue("30");
  await page.getByRole("link", { name: "Updates" }).click();
  await expect(page.getByLabel("Check for releases once a day")).toBeVisible();
  await expectAccessible(page);
  await page.getByRole("main").getByRole("link", { name: "Settings" }).click();
  await page.getByRole("link", { name: "PKI" }).click();
  await expect(page.getByRole("cell", { name: "Root", exact: true })).toBeVisible();
  await expect(page.getByRole("cell", { name: "Intermediate", exact: true })).toBeVisible();
  await expectAccessible(page);

  // An API token: its creation needs a step-up, which the dialog asks for in the page.
  await page.getByRole("link", { name: "Ada" }).click();
  await expect(page.getByRole("heading", { name: "Account", level: 1 })).toBeVisible();
  await expectAccessible(page);
  const tokens = page.getByRole("region", { name: "API tokens" });
  await tokens.getByRole("button", { name: "New token…" }).click();
  await tokens.getByLabel("Name").fill("e2e");
  await tokens.getByRole("button", { name: "Create the token" }).click();
  const dialog = page.getByRole("dialog", { name: "Confirm it is you" });
  await expect(dialog).toBeVisible();
  await expectAccessible(page);
  await dialog.getByLabel("Password").fill(password);
  await dialog.getByRole("button", { name: "Confirm" }).click();
  await expect(tokens.getByLabel("The new token")).toHaveText(/^rpmgr_pat_[0-9A-Za-z]{43}_[0-9A-Za-z]{6}$/);
  await tokens.getByRole("button", { name: "I have copied it" }).click();
  await tokens.getByRole("button", { name: "Revoke…" }).click();
  await tokens.getByRole("button", { name: "Revoke it" }).click();
  await expect(tokens.getByText("You have no API tokens.")).toBeVisible();

  // An authenticator, still within the step-up.
  const mfa = page.getByRole("region", { name: "Two-factor authentication" });
  await mfa.getByRole("button", { name: "Set up an authenticator" }).click();
  await expect(mfa.getByRole("img", { name: "QR code for your authenticator app" })).toBeVisible();
  await expectAccessible(page);
  const key = (await mfa.locator("code").innerText()).replace(/\s+/g, "");
  await mfa.getByLabel("Code from the app").fill(totp(key));
  await mfa.getByRole("button", { name: "Turn on" }).click();
  const codes = await mfa.getByRole("list", { name: "Recovery codes" }).getByRole("listitem").allInnerTexts();
  expect(codes).toHaveLength(10);
  await mfa.getByRole("button", { name: "I have saved them" }).click();
  await expect(mfa.getByText("An authenticator is set up.")).toBeVisible();

  await page.getByRole("button", { name: "Sign out" }).click();
  await expect(page.getByRole("heading", { name: "Sign in to rpmgr" })).toBeVisible();
  await page.getByLabel("E-mail address").fill(email);
  await page.getByLabel("Password", { exact: true }).fill(password);
  await page.getByRole("button", { name: "Sign in" }).click();
  const code = page.getByLabel("Authenticator code or recovery code");
  await expect(code).toBeVisible();
  await expectAccessible(page);
  await code.fill(codes[0]!); // the authenticator's current code was used to turn it on
  await page.getByRole("button", { name: "Sign in" }).click();
  await expect(page.getByText("Signed in as Ada")).toBeVisible();
  expect(await page.evaluate(() => [localStorage.length, sessionStorage.length])).toEqual([0, 0]);
  expect(violations).toEqual([]);
});
