// SPDX-License-Identifier: Apache-2.0

import { expect, test } from "@playwright/test";
import { email, expectAccessible, password, sideways, totp, unfilled, unmarked, watchCSP } from "./helpers";
import { fakeUpdates, type FakeRollout } from "./rollout-fakes";

// The flows of docs/09-web-ui.md, "Testing the UI": first-run setup, sign-in with and without a
// second factor, the step-up prompt, token creation and revocation, the enroll dialog, the
// settings, sign-out; each page under the controller's CSP, with no violation, nothing in browser
// storage, and no accessibility violation that axe finds.
test.describe.configure({ mode: "serial" });

test("first-run setup creates the first user and signs them in", async ({ page }) => {
  const violations = await watchCSP(page);
  const res = await page.goto(process.env.RPMGR_SETUP!);
  expect(res?.headers()["content-security-policy"]).toMatch(/style-src 'self' 'nonce-[A-Za-z0-9+/=]+'/);
  await expect(page.getByRole("heading", { name: "Create the first account" })).toBeVisible();
  await expect(page).toHaveURL(/\/setup$/); // the token left the address bar
  await expectAccessible(page);
  // Every field is required: its label ends in a red asterisk, which is not part of its name.
  await expect(page.locator(".required-mark")).toHaveText(["E-mail address", "Your name", "New password", "Repeat the new password"]);
  expect(await unmarked(page)).toEqual([]);
  await expect(page.getByRole("textbox", { name: "Your name", exact: true })).toBeVisible();

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
  // One long walk through the pages, both kinds of rollout among them: more than the default 30 s.
  test.setTimeout(90_000);
  const violations = await watchCSP(page);
  await page.goto("/");
  await expect(page).toHaveURL(/\/login\?redirect=/);
  await expectAccessible(page);
  expect(await unmarked(page)).toEqual([]);
  await page.getByLabel("E-mail address").fill(email);
  await page.getByLabel("Password", { exact: true }).fill("wrong password!");
  await page.getByRole("button", { name: "Sign in" }).click();
  await expect(page.getByRole("alert")).toHaveText("The e-mail address or the password is wrong.");
  await page.getByLabel("Password", { exact: true }).fill(password);
  await page.getByRole("button", { name: "Sign in" }).click();
  await expect(page.getByText("Signed in as Ada")).toBeVisible();
  await expect(page.getByRole("region", { name: "Traffic, last 24 hours" }).getByText("No traffic in this period.")).toBeVisible();
  await expect(page.getByRole("list", { name: "Summary" }).getByRole("link", { name: /^Agents connected\s*2\s*of 2\b/ })).toBeVisible();
  await expectAccessible(page);

  // The theme switch (U10) applies the dark theme at once and saves it, so the page keeps it after a
  // reload; axe checks the dark theme as well.
  const saved = page.waitForResponse((r) => r.url().endsWith("/rpmgr.v1.UserService/UpdateMe") && r.ok());
  await page.getByTitle("Dark").click(); // the icon, which labels the radio button
  await expect(page.locator("html")).toHaveAttribute("data-theme", "dark");
  await saved;
  await page.reload();
  await expect(page.getByRole("radio", { name: "Dark" })).toBeChecked();
  await expect(page.locator("html")).toHaveAttribute("data-theme", "dark");
  await expectAccessible(page);
  await page.getByTitle("Like the system").click();
  await expect(page.locator("html")).toHaveAttribute("data-theme", "system");

  // The command palette (U9) closes on Escape, the page staying as it was, and leads to the
  // instance settings, which the first user changes as the Instance Admin.
  await page.keyboard.press("Control+K");
  const palette = page.getByRole("dialog", { name: "Go to" });
  await palette.getByRole("combobox").fill("o");
  await palette.getByRole("combobox").press("ArrowDown");
  await palette.getByRole("combobox").press("Escape");
  await expect(palette).toBeHidden();
  await expect(page.getByRole("heading", { name: "Overview", level: 1 })).toBeVisible();
  await page.keyboard.press("Control+K");
  await palette.getByRole("combobox").fill("sett");
  await expect(palette.getByRole("option", { selected: true })).toHaveText(/^Settings/);
  await expectAccessible(page);
  await palette.getByRole("combobox").press("Enter");
  await expect(palette).toBeHidden();
  const instance = page.getByRole("region", { name: "Instance settings" });
  await expect(instance.getByLabel("Keep hourly statistics (days)")).toHaveValue(/^\d+$/);
  await expectAccessible(page);
  // A mail relay needs a sender address, so it is marked only while a relay is set.
  await instance.getByLabel("Relay host:port").fill("mail.example.com:587");
  await expect(page.locator(".required-mark")).toHaveText(["Sender address"]);
  expect(await unmarked(page)).toEqual([]);
  await instance.getByLabel("Relay host:port").fill("");
  await expect(page.locator(".required-mark")).toHaveCount(0);
  await instance.getByLabel("Keep hourly statistics (days)").fill("30");
  await instance.getByRole("button", { name: "Save" }).click();
  await expect(instance.getByRole("status")).toHaveText("Saved.");
  await expect(instance.getByLabel("Keep hourly statistics (days)")).toHaveValue("30");
  await page.getByRole("link", { name: "Updates" }).click();
  await expect(page.getByLabel("Check for releases once a day")).toBeVisible();
  await expectAccessible(page);
  // The upload dialog shows a button to choose the signed files and says what Upload waits for.
  await page.getByRole("button", { name: "Upload release…" }).click();
  const upload = page.getByRole("dialog", { name: "Upload a release" });
  await expect(upload.getByRole("button", { name: "Choose files…" })).toBeVisible();
  await expect(upload.getByRole("button", { name: "Upload" })).toBeDisabled();
  await expect(upload.getByText(/^Still missing: signing-key\.json/)).toBeVisible();
  await expectAccessible(page);
  await upload.getByRole("button", { name: "Cancel" }).click();
  await expect(upload).toBeHidden();
  // The rollout dialogs and running rollouts, from made-up answers: the instance has no signed
  // release. None scrolls sideways, in a desktop window or on a phone (#877).
  let rollout: FakeRollout = "none";
  await fakeUpdates(page, () => rollout);
  await page.reload();
  // Check now asks for a release check, and the page shows how the last one ended (#890).
  const releasesCard = page.getByRole("region", { name: "Releases" });
  await expect(releasesCard.getByRole("status")).toHaveText(/^Last checked .*: ok$/);
  await releasesCard.getByRole("button", { name: "Check now" }).click();
  await expect(releasesCard.getByRole("button", { name: "Check now" })).toBeEnabled();
  await expectAccessible(page);
  // A new instance starts easy rollouts (D129): tick agents, order them, start.
  await page.getByRole("button", { name: "Roll out…" }).first().click();
  const easy = page.getByRole("dialog", { name: "Roll out 0.2.0" });
  await easy.getByRole("checkbox", { name: /^gw-eu-1/ }).check();
  await easy.getByRole("checkbox", { name: /^db-host-1/ }).check();
  await expect(easy.getByRole("list", { name: "Order" }).getByRole("listitem")).toHaveCount(2);
  await expect(easy.getByText("local: built in, updates with the controller")).toBeVisible();
  await easy.getByRole("button", { name: "Move gw-eu-1 up" }).click();
  await expect(easy.getByRole("button", { name: "Start: update 2 agents" })).toBeEnabled();
  await expectAccessible(page);
  const desktopSize = page.viewportSize()!;
  for (const width of [desktopSize.width, 390]) {
    await page.setViewportSize({ width, height: desktopSize.height });
    expect(await sideways(page), `easy dialog, ${width} px wide`).toEqual([]);
  }
  await page.setViewportSize(desktopSize);
  await page.keyboard.press("Escape");
  for (const s of ["easy", "easy-paused"] as const) {
    rollout = s;
    await page.reload();
    const easyCard = page.getByRole("region", { name: "Rollout" });
    await expect(easyCard.getByText(s === "easy" ? "1 failed" : "3 failed")).toBeVisible();
    await expect(easyCard.getByRole("button", { name: s === "easy" ? "Pause" : "Resume" })).toBeVisible();
    await expectAccessible(page);
    for (const width of [desktopSize.width, 390]) {
      await page.setViewportSize({ width, height: desktopSize.height });
      expect(await page.evaluate(() => document.documentElement.scrollWidth - document.documentElement.clientWidth), `${s}, ${width} px wide`).toBe(0);
    }
    await page.setViewportSize(desktopSize);
  }
  // Advanced keeps the staged rollout.
  rollout = "none";
  await page.reload();
  const updatesForm = page.getByRole("form", { name: "Updates" });
  await updatesForm.getByLabel("Rollouts").selectOption({ label: "Advanced: test agents, then stages you approve" });
  await updatesForm.getByRole("button", { name: "Save" }).click();
  await expect(page.getByText("Saved.", { exact: true })).toBeVisible();
  await page.getByRole("button", { name: "Roll out…" }).first().click();
  const start = page.getByRole("dialog", { name: "Roll out 0.2.0" });
  await expect(start.getByRole("checkbox", { name: /^gw-eu-1/ })).toBeChecked();
  await expectAccessible(page);
  await start.getByRole("button", { name: "Next" }).click();
  await expect(start.getByRole("list", { name: "The plan" })).toBeVisible();
  await expectAccessible(page);
  for (const width of [desktopSize.width, 390]) {
    await page.setViewportSize({ width, height: desktopSize.height });
    expect(await sideways(page), `${width} px wide`).toEqual([]);
  }
  await page.setViewportSize(desktopSize);
  await page.keyboard.press("Escape");
  rollout = "running";
  await page.reload();
  const card = page.getByRole("region", { name: "Rollout" });
  await expect(card.getByRole("button", { name: "Continue to all agents (4 more agents)" })).toBeDisabled();
  await card.getByRole("button", { name: "Choose another stage" }).click();
  await expectAccessible(page);
  for (const width of [desktopSize.width, 390]) {
    await page.setViewportSize({ width, height: desktopSize.height });
    expect(await page.evaluate(() => document.documentElement.scrollWidth - document.documentElement.clientWidth), `${width} px wide`).toBe(0);
  }
  await page.setViewportSize(desktopSize);
  await page.unrouteAll({ behavior: "wait" });
  await page.reload();
  await updatesForm.getByLabel("Rollouts").selectOption({ label: "Easy: the agents you choose, one after another" });
  await updatesForm.getByRole("button", { name: "Save" }).click();
  await expect(page.getByText("Saved.", { exact: true })).toBeVisible();
  await page.getByRole("main").getByRole("link", { name: "Settings" }).click();
  await page.getByRole("link", { name: "PKI" }).click();
  await expect(page.getByRole("cell", { name: "Root", exact: true })).toBeVisible();
  await expect(page.getByRole("cell", { name: "Intermediate", exact: true })).toBeVisible();
  await expectAccessible(page);

  // On a wide screen every page fills the window beside the sidebar, and the route form stands in
  // two columns, which a phone stacks.
  const desktop = page.viewportSize()!;
  await page.setViewportSize({ width: 2560, height: 1440 });
  for (const path of ["/", "/routes", "/routes/new", "/gateways", "/settings", "/account", "/settings/pki"]) {
    await page.goto(path);
    await expect(page.getByRole("heading", { level: 1 })).toBeVisible();
    expect(await unfilled(page), path).toEqual([]);
  }
  await page.goto("/routes/new");
  await expect(page.locator(".required-mark")).toHaveText(["Gateway group", "Name", "Hostnames", "HSTS max-age (seconds)", "Largest request body (bytes, 0 for no limit)"]);
  expect(await unmarked(page)).toEqual([]);
  // A CONNECT route: its fields come with the mode, and basic auth in the clear stays warned of.
  await page.getByRole("radio", { name: "TCP", exact: true }).check();
  await page.getByLabel("Listener", { exact: true }).selectOption({ label: "A CONNECT listener shared with other routes (HTTP proxy)" });
  await expect(page.getByLabel("CONNECT names")).toBeVisible();
  await page.getByLabel("Proxy credentials").selectOption({ label: "Basic auth in the clear" });
  await expect(page.getByText(/anyone on the network between them and the gateway can read and use it/)).toBeVisible();
  await expectAccessible(page);
  await page.goto("/routes/new");
  const top = async (label: string) => (await page.getByLabel(label, { exact: true }).boundingBox())!.y;
  expect(await top("Name")).toBe(await top("Gateway group"));
  await page.setViewportSize({ width: 390, height: desktop.height });
  expect(await top("Name")).toBeGreaterThan(await top("Gateway group"));
  await page.setViewportSize(desktop);
  await page.goto("/settings/pki");

  // A gateway group's own page: uploaded, then previewed as the controller renders it, with its
  // inline style applied and its placeholders filled in, in a frame that runs no script (D136).
  await page.getByRole("link", { name: "Gateways" }).click();
  await page.getByRole("link", { name: "default", exact: true }).click();
  const maintenance = page.getByRole("region", { name: "Pages" }).getByRole("listitem", { name: "Maintenance" });
  await maintenance.getByLabel("Upload HTML…").setInputFiles({ name: "maintenance.html", mimeType: "text/html", buffer: Buffer.from(
    "<!doctype html><html lang=\"en\"><head><title>Back soon</title><style>h1{color:rgb(200, 0, 0)}</style></head>" +
    "<body><h1>{{status}} at {{hostname}}</h1><p>{{message}}</p><script>document.title = 'ran'</script></body></html>") });
  await expect(maintenance.getByText("Own")).toBeVisible();
  await maintenance.getByRole("button", { name: "Preview" }).click();
  const frame = page.frameLocator('iframe[title="Preview of the page Maintenance"]');
  await expect(frame.locator("h1")).toHaveText(/^503 at /);
  await expect(frame.locator("h1")).toHaveCSS("color", "rgb(200, 0, 0)");
  await expect(frame.locator("p")).toHaveText("Back soon: the service is being updated.");
  expect(await frame.locator("title").textContent()).toBe("Back soon"); // the script did not run
  // The frame shows the group's own HTML, whose accessibility is its author's; the card is ours.
  await expectAccessible(page, ['iframe[title="Preview of the page Maintenance"]']);
  await maintenance.getByRole("button", { name: "Reset…" }).click();
  await maintenance.getByRole("button", { name: "Use the built-in page" }).click();
  await expect(maintenance.getByText("Built in")).toBeVisible();

  // The YAML view: CodeMirror's style elements carry the page's nonce, so its styles apply (VB-07).
  await page.getByRole("link", { name: "Routes" }).click();
  await page.getByRole("button", { name: "Export YAML" }).click();
  const yaml = page.getByRole("dialog", { name: "Routes as YAML" });
  await expect(yaml.getByRole("textbox", { name: "Routes as YAML" })).toBeVisible();
  await expect(yaml.locator(".cm-editor")).toHaveCSS("display", "flex");
  await expect(yaml.locator(".cm-gutters")).toHaveCSS("border-right-style", "none");
  await expectAccessible(page);
  await yaml.getByRole("button", { name: "Close" }).click();

  // An API token: its creation needs a step-up, which the dialog asks for in the page.
  await page.getByRole("button", { name: "User menu: Ada" }).click();
  await expectAccessible(page);
  await page.getByRole("link", { name: "Your account" }).click();
  await expect(page.getByRole("heading", { name: "Account", level: 1 })).toBeVisible();
  await expectAccessible(page);
  const tokens = page.getByRole("region", { name: "API tokens" });
  await tokens.getByRole("button", { name: "New token…" }).click();
  // No scope checkbox can be required, so the group's name says it.
  await expect(tokens.getByRole("group", { name: "Scopes (required)" })).toBeVisible();
  expect(await unmarked(page)).toEqual([]);
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

  // The enroll dialog, still within the step-up: the install command and the token wrap, so neither
  // the dialog nor a part of it scrolls sideways, in a desktop window or on a phone.
  await page.getByRole("link", { name: "Connectors", exact: true }).click();
  await page.getByRole("button", { name: "Enroll a connector" }).first().click();
  const enroll = page.getByRole("dialog", { name: "Enroll a connector" });
  await enroll.getByLabel("Targets the connector may reach").fill("10.0.0.5:5432\n192.168.100.200:8443");
  await enroll.getByRole("button", { name: "Create the token" }).click();
  await expect(enroll.getByLabel("Install command")).toContainText("--allow-target '192.168.100.200:8443'");
  await enroll.getByRole("button", { name: "Show" }).click();
  await expect(enroll.getByLabel("Enrollment token")).toHaveText(/^rpmgr_enr_/);
  await expectAccessible(page);
  const size = page.viewportSize()!;
  for (const width of [size.width, 390]) {
    await page.setViewportSize({ width, height: size.height });
    expect(await sideways(page), `${width} px wide`).toEqual([]);
  }
  await page.setViewportSize(size);
  await enroll.getByRole("button", { name: "Close" }).click();

  // The audit log: the request of an opened entry, one line of JSON, wraps, so the page does not
  // scroll sideways, in a desktop window or on a phone (#563).
  await page.getByRole("link", { name: "Audit log" }).click();
  const created = page.locator("details").filter({ has: page.locator("summary", { hasText: "CreateEnrollmentToken" }) }).first();
  await created.locator("summary").click();
  await expect(created.locator("pre")).toContainText('"org_id":');
  for (const width of [size.width, 390]) {
    await page.setViewportSize({ width, height: size.height });
    expect(await page.evaluate(() => document.documentElement.scrollWidth - document.documentElement.clientWidth), `${width} px wide`).toBe(0);
  }
  await page.setViewportSize(size);
  await page.getByRole("button", { name: "User menu: Ada" }).click();
  await page.getByRole("link", { name: "Your account" }).click();

  // An authenticator, still within the step-up.
  const mfa = page.getByRole("region", { name: "Two-factor authentication" });
  await mfa.getByRole("button", { name: "Set up an authenticator" }).click();
  await expect(mfa.getByRole("img", { name: "QR code for your authenticator app" })).toBeVisible();
  await expectAccessible(page);
  const key = (await mfa.locator("code").innerText()).replace(/\s+/g, "");
  await mfa.getByLabel("Code from the app").fill(totp(key));
  await mfa.getByRole("button", { name: "Turn on" }).click();
  // The codes appear once the server has turned the authenticator on.
  const shown = mfa.getByRole("list", { name: "Recovery codes" }).getByRole("listitem");
  await expect(shown).toHaveCount(10);
  const codes = await shown.allInnerTexts();
  await mfa.getByRole("button", { name: "I have saved them" }).click();
  await expect(mfa.getByText("An authenticator is set up.")).toBeVisible();

  await page.getByRole("button", { name: "User menu: Ada" }).click();
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
