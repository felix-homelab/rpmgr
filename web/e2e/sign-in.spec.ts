// SPDX-License-Identifier: Apache-2.0

import { expect, test } from "@playwright/test";
import { call, email, expectAccessible, password, totp, watchCSP } from "./helpers";

// The flows of docs/09-web-ui.md, "Testing the UI": first-run setup, sign-in with and without a
// second factor, sign-out; each page under the controller's CSP, with no violation, nothing in
// browser storage, and no accessibility violation that axe finds.
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

test("signs in with a password, then with a second factor", async ({ page }) => {
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

  // An authenticator, set up through the API until the account page exists.
  await call(page, "AuthService/StepUp", { password });
  const { secret } = await call<{ secret: string }>(page, "UserService/EnrollTOTP", {});
  const { recoveryCodes } = await call<{ recoveryCodes: string[] }>(page, "UserService/ConfirmTOTP", { code: totp(secret) });

  await page.getByRole("button", { name: "Sign out" }).click();
  await expect(page.getByRole("heading", { name: "Sign in to rpmgr" })).toBeVisible();
  await page.getByLabel("E-mail address").fill(email);
  await page.getByLabel("Password", { exact: true }).fill(password);
  await page.getByRole("button", { name: "Sign in" }).click();
  const code = page.getByLabel("Authenticator code or recovery code");
  await expect(code).toBeVisible();
  await expectAccessible(page);
  await code.fill(recoveryCodes[0]!); // the authenticator's current code was used to confirm it
  await page.getByRole("button", { name: "Sign in" }).click();
  await expect(page.getByText("Signed in as Ada")).toBeVisible();
  expect(violations).toEqual([]);
});
