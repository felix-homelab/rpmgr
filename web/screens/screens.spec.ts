// SPDX-License-Identifier: Apache-2.0

import { expect, test, type Browser, type Page } from "@playwright/test";
import { fakeUpdates } from "../e2e/rollout-fakes";

// The screenshots of the user guide, one PNG per page in SCREENS_OUT (docs/guide/images/web),
// taken against the instance that test/webe2e's TestScreens seeded: the org "Example Lab" with its
// users, routes, connectors, gateways, domains and policies. SCREENS is "all" or a
// comma-separated list of the screenshots to write; the walk through the UI is the same either way.

const password = process.env.SCREENS_PASSWORD ?? "";
const only = (process.env.SCREENS ?? "all").split(",").map((s) => s.trim()).filter((s) => s && s !== "all" && s !== "1");

// shot writes a screenshot of the window; full makes the window as tall as the page first, so that
// the whole page, with its sidebar and top bar, is in it, then sets the window back.
async function shot(page: Page, name: string, full = false) {
  if (only.length > 0 && !only.includes(name)) {
    return;
  }
  await page.mouse.move(0, 0);
  const size = page.viewportSize()!;
  if (full) {
    await page.evaluate(() => window.scrollTo(0, 0));
    const height = await page.evaluate(() => document.documentElement.scrollHeight);
    await page.setViewportSize({ width: size.width, height: Math.max(size.height, height) });
  }
  await page.waitForTimeout(500);
  await page.screenshot({ path: `${process.env.SCREENS_OUT}/${name}.png`, animations: "disabled" });
  await page.setViewportSize(size);
}

const nav = (page: Page) => page.getByRole("navigation", { name: "Main navigation" });

async function open(page: Page, link: string, heading: string | RegExp) {
  await nav(page).getByRole("link", { name: link }).click();
  await expect(page.getByRole("heading", { name: heading, level: 1 })).toBeVisible();
  await page.waitForTimeout(800);
}

async function signIn(page: Page, email: string) {
  await page.goto("/login");
  await page.getByLabel("E-mail address").fill(email);
  await page.getByLabel("Password").fill(password);
  await page.getByRole("button", { name: "Sign in" }).click();
}

// call is an API call with the page's session, as the UI makes it.
async function call(page: Page, method: string, body: object) {
  return page.evaluate(async ([method, body]) => {
    const r = await fetch(`/rpmgr.v1.${method}`, {
      method: "POST", headers: { "Content-Type": "application/json", "Connect-Protocol-Version": "1" }, body: JSON.stringify(body),
    });
    return { status: r.status, body: await r.json() };
  }, [method, body] as const);
}

// changeAsAlan changes a route's description as another member, the Operator Alan Turing, in a
// browser of his own, so that a form opened before shows the conflict.
async function changeAsAlan(browser: Browser, routeId: string) {
  const context = await browser.newContext();
  const page = await context.newPage();
  await signIn(page, "alan@example.com");
  await expect(page.getByRole("heading", { name: "Overview", level: 1 })).toBeVisible();
  const got = await call(page, "RouteService/GetRoute", { routeId });
  const r = await call(page, "RouteService/UpdateRoute", {
    route: { ...got.body.route, description: "The wiki of the whole lab" }, updateMask: "description", etag: got.body.route.etag,
  });
  expect(r.status).toBe(200);
  await context.close();
}

test("screenshots of the user guide", async ({ page, browser }) => {
  page.on("pageerror", (e) => console.log("PAGEERROR", e.message));

  // The pages that need no session. Their one-time links need only a token in the fragment to show
  // their form; nothing here is sent.
  await page.goto("/setup#example");
  await page.getByLabel("E-mail address").fill("ada@example.com");
  await page.getByLabel("Your name").fill("Ada Lovelace");
  await page.getByLabel("New password", { exact: true }).fill(password);
  await page.getByLabel("Repeat the new password").fill(password);
  await shot(page, "setup");
  await page.goto("/forgot");
  await page.getByLabel("E-mail address").fill("ada@example.com");
  await shot(page, "forgot");
  await page.goto("/reset#example");
  await page.getByLabel("New password", { exact: true }).fill(password);
  await page.getByLabel("Repeat the new password").fill(password);
  await shot(page, "reset");
  await page.goto("/invite#example");
  await page.getByLabel("Your name").fill("Linus Example");
  await page.getByLabel("New password", { exact: true }).fill(password);
  await page.getByLabel("Repeat the new password").fill(password);
  await shot(page, "invite");

  // Signing in, and the second step of a user with an authenticator.
  await page.goto("/login");
  await page.getByLabel("E-mail address").fill("ada@example.com");
  await page.getByLabel("Password").fill(password);
  await shot(page, "sign-in");
  await signIn(page, "grace@example.com");
  await expect(page.getByLabel("Authenticator code or recovery code")).toBeVisible();
  await shot(page, "sign-in-code");
  await signIn(page, "ada@example.com");
  await expect(page.getByRole("heading", { name: "Overview", level: 1 })).toBeVisible();
  await page.waitForTimeout(1500);
  await shot(page, "overview", true);

  await page.keyboard.press("Control+k");
  await page.getByRole("combobox", { name: "Page, resource or action" }).fill("gr");
  await shot(page, "command-palette");
  await page.keyboard.press("Escape");

  // Routes.
  await open(page, "Routes", "Routes");
  await shot(page, "routes", true);
  await page.getByRole("button", { name: "Export YAML" }).click();
  await expect(page.getByRole("textbox", { name: "Routes as YAML" })).toBeVisible();
  await page.waitForTimeout(800);
  await shot(page, "yaml-view");
  await page.getByRole("button", { name: "Close" }).click();
  await page.getByRole("link", { name: "wiki", exact: true }).click();
  await expect(page.getByRole("heading", { name: "Route wiki (HTTP)", level: 1 })).toBeVisible();
  // The health check's first round marks the unreachable target unhealthy.
  await expect(async () => {
    await page.reload();
    await expect(page.getByText("unhealthy", { exact: true })).toBeVisible({ timeout: 2000 });
  }).toPass({ timeout: 60_000 });
  await page.waitForTimeout(1200);
  await shot(page, "route-detail", true);
  const wiki = page.url().split("/routes/")[1]!;
  await page.getByRole("button", { name: "Add a target" }).click();
  await page.getByLabel("Connector").selectOption({ label: "nas-01" });
  await page.getByLabel("Host", { exact: true }).fill("192.0.2.10");
  await page.getByLabel("Port", { exact: true }).fill("8443");
  await page.getByLabel("Protocol to the target").selectOption({ label: "HTTPS, pinned key" });
  await shot(page, "route-target-form", true);
  await page.getByRole("form", { name: "New target" }).getByRole("button", { name: "Cancel" }).click();
  await page.goto("/routes/new");
  await expect(page.getByRole("heading", { name: "New route", level: 1 })).toBeVisible();
  await page.getByLabel("Name", { exact: true }).fill("photos");
  await page.getByLabel("Hostnames").fill("photos.example.com");
  await page.waitForTimeout(800);
  await shot(page, "route-new", true);

  // A new CONNECT route: a tcp route on a CONNECT listener, with its names and proxy credentials.
  await page.goto("/routes/new");
  await page.getByRole("radio", { name: "TCP", exact: true }).check();
  await page.getByLabel("Name", { exact: true }).fill("bastion");
  await page.getByLabel("Listener", { exact: true }).selectOption({ label: "A CONNECT listener shared with other routes (HTTP proxy)" });
  await page.getByLabel("CONNECT names").fill("bastion.internal\njump");
  await page.getByLabel("Proxy credentials").selectOption({ label: "Basic auth in the clear" });
  await page.waitForTimeout(800);
  await shot(page, "route-new-connect", true);

  // A save that meets a newer version shows the conflict.
  await page.goto(`/routes/${wiki}/edit`);
  await expect(page.getByRole("heading", { name: "Edit route wiki (HTTP)", level: 1 })).toBeVisible();
  await page.waitForTimeout(800);
  await shot(page, "route-edit", true);
  await page.getByLabel("Description").fill("Team wiki");
  await page.getByLabel("Labels").fill("team=docs");
  await changeAsAlan(browser, wiki);
  await page.getByRole("button", { name: "Save" }).click();
  await expect(page.getByRole("heading", { name: "The route changed since you opened it" })).toBeVisible();
  await page.evaluate(() => window.scrollTo(0, 0));
  await shot(page, "route-edit-conflict");
  await page.getByRole("button", { name: "Drop my changes" }).click();

  // Connectors, and the enroll dialog with its step-up.
  await open(page, "Connectors", "Connectors");
  await shot(page, "connectors", true);
  await page.getByRole("button", { name: "Enroll a connector" }).first().click();
  const enroll = page.getByRole("dialog", { name: "Enroll a connector" });
  await enroll.getByLabel("Labels").fill("site=office");
  await enroll.getByLabel("Targets the connector may reach").fill("192.0.2.30:8080\n192.0.2.31:443");
  await enroll.getByRole("button", { name: "Create the token" }).click();
  const stepUp = page.getByRole("dialog", { name: "Confirm it is you" });
  await expect(stepUp).toBeVisible();
  await stepUp.getByLabel("Password").fill(password);
  await shot(page, "step-up");
  await stepUp.getByRole("button", { name: "Confirm" }).click();
  await expect(enroll.getByText("1. On the host, run:")).toBeVisible();
  await shot(page, "enroll-command");
  await enroll.getByRole("button", { name: "Close" }).click();
  await page.getByRole("link", { name: "nas-01", exact: true }).click();
  await expect(page.getByRole("heading", { name: "Connector nas-01", level: 1 })).toBeVisible();
  await page.waitForTimeout(1000);
  await shot(page, "connector-detail", true);

  // Gateways.
  await open(page, "Gateways", "Gateway groups");
  await shot(page, "gateways");
  await page.getByRole("link", { name: "default", exact: true }).click();
  await expect(page.getByRole("heading", { name: "Gateway group default", level: 1 })).toBeVisible();
  await page.getByRole("listitem", { name: "Maintenance" }).getByRole("button", { name: "Preview" }).click();
  await page.waitForTimeout(1000);
  await shot(page, "gateway-group", true);

  // Security and administration.
  await open(page, "Domains & certificates", "Domains & certificates");
  await shot(page, "domains", true);
  await open(page, "Access policies", "Access policies");
  await shot(page, "policies", true);
  await open(page, "Organisation", "Example Lab");
  await shot(page, "organisation", true);
  await open(page, "Audit log", "Audit log");
  // An entry opened, whose long request wraps within the page.
  await page.locator("details summary").filter({ hasText: "RouteService.UpdateRoute" }).first().click();
  await shot(page, "audit");
  await open(page, "Settings", "Settings");
  await shot(page, "settings", true);
  await page.getByRole("link", { name: "PKI" }).click();
  await expect(page.getByRole("heading", { name: "PKI", level: 1 })).toBeVisible();
  await page.waitForTimeout(800);
  await shot(page, "settings-pki", true);
  // The installation knows no release, and its release check fetches its own from GitHub, which
  // can take long: the page is shown with that list and a check that ended.
  const listReleases = "**/rpmgr.v1.ReleaseService/ListReleases";
  await page.route(listReleases, (route) => route.fulfill({ json: { releases: [], controllerVersion: "0.1.0",
    releaseCheck: { checkTime: "2026-10-24T08:00:00Z", outcome: "RELEASE_CHECK_OUTCOME_OK" } } }));
  await page.getByRole("link", { name: "Updates" }).click();
  await expect(page.getByRole("heading", { name: "Updates", level: 1 })).toBeVisible();
  await expect(page.getByRole("region", { name: "Releases" }).getByRole("status")).toHaveText(/^Last checked/);
  await page.waitForTimeout(800);
  await shot(page, "settings-updates", true);
  // The upload dialog with three of the four signed files chosen, which is cancelled.
  await page.getByRole("button", { name: "Upload release…" }).click();
  const upload = page.getByRole("dialog", { name: "Upload a release" });
  await upload.getByLabel("Choose files…").setInputFiles(["signing-key.json", "signing-key.json.minisig", "manifest.json"]
    .map((name) => ({ name, mimeType: "application/octet-stream", buffer: Buffer.from(name) })));
  await expect(upload.getByText("Still missing: manifest.json.minisig")).toBeVisible();
  await shot(page, "release-upload");
  await upload.getByRole("button", { name: "Cancel" }).click();
  await page.unroute(listReleases);
  await page.getByRole("link", { name: "Users" }).click();
  await expect(page.getByRole("heading", { name: "Users", level: 1 })).toBeVisible();
  await page.waitForTimeout(800);
  await shot(page, "settings-users", true);

  // The account: a new API token first, which is not pictured, then the page and the setup of an
  // authenticator, which is cancelled.
  await page.getByRole("button", { name: /^User menu/ }).click();
  await page.getByRole("link", { name: "Your account" }).click();
  await expect(page.getByRole("heading", { name: "Account", level: 1 })).toBeVisible();
  await page.getByRole("button", { name: "New token…" }).click();
  await page.getByLabel("Name", { exact: true }).fill("laptop-cli");
  await page.getByRole("checkbox", { name: /routes\.write/ }).check();
  await page.getByRole("button", { name: "Create the token" }).click();
  await page.getByRole("button", { name: "I have copied it" }).click();
  await page.waitForTimeout(800);
  await shot(page, "account", true);
  await page.getByRole("button", { name: "Set up an authenticator" }).click();
  await expect(page.getByText("Scan this code with your authenticator app")).toBeVisible();
  await shot(page, "account-authenticator", true);
  await page.getByRole("button", { name: "Cancel" }).click();

  // The menu on small screens.
  await page.setViewportSize({ width: 390, height: 844 });
  await page.goto("/");
  await page.getByRole("button", { name: "Open the menu" }).click();
  await expect(page.getByRole("dialog", { name: "Menu" })).toBeVisible();
  await shot(page, "mobile-menu");
});

// The rollout pictures: the start dialog's two steps and a rollout in progress, running and paused.
// The instance has no signed release to roll out, so fakeUpdates answers the release, rollout and
// agent calls with a made-up fleet of Example Lab. The check- shots, in dark and at a phone's
// width, are taken only when named, to look at the layout; the guide does not show them. The guide
// shows the staged rollout, which the dialog starts once Rollouts is Advanced: a new instance
// starts easy rollouts (D129).
test("screenshots of a rollout", async ({ page }) => {
  let state: "none" | "running" | "paused" = "none";
  await fakeUpdates(page, () => state);
  await signIn(page, "ada@example.com");
  await expect(page.getByRole("heading", { name: "Overview", level: 1 })).toBeVisible();
  await page.goto("/settings/updates");
  const updatesForm = page.getByRole("form", { name: "Updates" });
  await updatesForm.getByLabel("Rollouts").selectOption({ label: "Advanced: test agents, then stages you approve" });
  await updatesForm.getByRole("button", { name: "Save" }).click();
  await expect(page.getByText("Saved.", { exact: true })).toBeVisible();
  for (const [suffix, width, scheme] of [["", 1440, "light"], ["-dark", 1440, "dark"], ["-narrow", 400, "light"], ["-narrow-dark", 400, "dark"]] as const) {
    const named = (name: string) => suffix ? `check-${name}${suffix}` : name;
    await page.setViewportSize({ width, height: 900 });
    await page.emulateMedia({ colorScheme: scheme });
    state = "none";
    await page.goto("/settings/updates");
    const releasesCard = page.getByRole("region", { name: "Releases" });
    await expect(releasesCard.getByRole("status")).toHaveText(/^Last checked/);
    await part(page, releasesCard, named("release-check"), !!suffix);
    await page.getByRole("button", { name: "Roll out…" }).first().click();
    const dialog = page.getByRole("dialog", { name: "Roll out 0.2.0" });
    await expect(dialog.getByRole("checkbox", { name: /^gw-eu-1/ })).toBeChecked();
    await part(page, dialog, named("rollout-start"), !!suffix);
    await dialog.getByRole("button", { name: "Next" }).click();
    await expect(dialog.getByText("Step 2 of 2: review the plan")).toBeVisible();
    await part(page, dialog, named("rollout-plan"), !!suffix);
    await page.keyboard.press("Escape");
    for (const s of ["running", "paused"] as const) {
      state = s;
      await page.reload();
      const card = page.getByRole("region", { name: "Rollout" });
      await expect(card.getByRole("list", { name: "Stages" })).toBeVisible();
      await part(page, card, named(s === "running" ? "rollout" : "rollout-paused"), !!suffix);
    }
  }
});

// part writes a screenshot of one part of the page, such as a dialog or a card; a check shot, only
// when named, is of the whole page instead, to show what overflows it.
async function part(page: Page, locator: ReturnType<Page["locator"]>, name: string, check: boolean) {
  if (check ? !only.includes(name) : only.length > 0 && !only.includes(name)) {
    return;
  }
  await page.mouse.move(0, 0);
  await page.waitForTimeout(500);
  if (check) {
    await page.screenshot({ path: `${process.env.SCREENS_OUT}/${name}.png`, animations: "disabled", fullPage: true });
    return;
  }
  await locator.screenshot({ path: `${process.env.SCREENS_OUT}/${name}.png`, animations: "disabled" });
}
