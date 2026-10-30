// SPDX-License-Identifier: Apache-2.0

import { Code, ConnectError } from "@connectrpc/connect";
import { cleanup, fireEvent, screen, waitFor, within } from "@testing-library/react";
import { afterEach, describe, expect, it } from "vitest";
import { Theme, UserService } from "@/gen/rpmgr/v1/user_pb";
import { WebhookService, type CreateWebhookRequest, type UpdateWebhookRequest } from "@/gen/rpmgr/v1/webhook_pb";
import { apiError, auth, show } from "@/testing/api";
import { marked, unmatched } from "@/testing/required";

afterEach(cleanup);

const ts = (s: number) => ({ seconds: BigInt(s) });
const live = { id: "whk_1", orgId: "org_1", url: "https://hooks.example.com/a", eventTypes: ["route.*"], enabled: true, secretSet: true, etag: "e1", lastSuccessTime: ts(1_700_000_000) };
const dead = { id: "whk_2", orgId: "org_1", url: "https://hooks.example.com/b", eventTypes: [], enabled: false, secretSet: true, etag: "e2", failingSinceTime: ts(1_700_000_000) };

interface Calls { creates: CreateWebhookRequest[]; updates: UpdateWebhookRequest[]; rotated: string[]; deleted: string[]; tested: string[]; listed: number; deliveryPages: string[] }

// webhooks renders /webhooks for a user with role in org_1; the options refuse or shape single calls.
function webhooks(role = "owner", opts: { hooks?: object[]; create?: ConnectError; rotate?: ConnectError; test?: { delivered: boolean; statusCode: number; error: string }; deliveries?: object[][] } = {}) {
  const c: Calls = { creates: [], updates: [], rotated: [], deleted: [], tested: [], listed: 0, deliveryPages: [] };
  let hooks = opts.hooks ?? [live, dead];
  show("/webhooks", auth({
    getSession: () => ({ userId: "usr_ada", displayName: "Ada", memberships: [{ orgId: "org_1", role }] }),
  }), (router) => {
    router.service(UserService, { getMe: () => ({ user: { id: "usr_ada", theme: Theme.SYSTEM } }) });
    router.service(WebhookService, {
      listWebhooks: () => (c.listed++, { webhooks: hooks }),
      createWebhook: (req) => {
        c.creates.push(req);
        if (opts.create) {
          throw opts.create;
        }
        hooks = [...hooks, { ...req.webhook, id: "whk_new", orgId: "org_1", secretSet: true }];
        return { webhook: hooks.at(-1), secret: "rpmgr_whs_SECRET1" };
      },
      updateWebhook: (req) => {
        c.updates.push(req);
        const w = req.webhook!;
        const camel = (k: string) => k.replace(/_(\w)/g, (_m, ch: string) => ch.toUpperCase());
        const set: Record<string, unknown> = { url: w.url, eventTypes: w.eventTypes, enabled: w.enabled };
        const patch = Object.fromEntries((req.updateMask?.paths ?? []).map((k) => [camel(k), set[camel(k)]]));
        hooks = hooks.map((h) => ((h as { id: string }).id === w.id ? { ...h, ...patch } : h));
        return {};
      },
      rotateWebhookSecret: (req) => {
        c.rotated.push(req.webhookId);
        if (opts.rotate) {
          throw opts.rotate;
        }
        return { secret: "rpmgr_whs_SECRET2" };
      },
      deleteWebhook: (req) => (c.deleted.push(`${req.webhookId} ${req.etag}`), (hooks = hooks.filter((h) => (h as { id: string }).id !== req.webhookId)), {}),
      testWebhook: (req) => (c.tested.push(req.webhookId), opts.test ?? { delivered: true, statusCode: 204, error: "" }),
      listWebhookDeliveries: (req) => {
        c.deliveryPages.push(req.pageToken);
        const pages = opts.deliveries ?? [[]];
        const i = req.pageToken === "" ? 0 : Number(req.pageToken);
        return { deliveries: pages[i], nextPageToken: i + 1 < pages.length ? String(i + 1) : "" };
      },
    });
  });
  return c;
}

const page = async () => within(await screen.findByRole("region", { name: "Webhooks" }));
const rowOf = async (url: string) => within((await screen.findByText(url)).closest("li")!);

async function fillCreate(s: Awaited<ReturnType<typeof page>>, url: string, types = "route.*, connector.*") {
  fireEvent.click(await s.findByRole("button", { name: "New webhook…" }));
  fireEvent.change(s.getByLabelText("URL"), { target: { value: url } });
  fireEvent.change(s.getByLabelText("Event types"), { target: { value: types } });
}

describe("Webhooks", () => {
  it("lists the endpoints with their state, event types and last delivery", async () => {
    webhooks();
    const a = await rowOf("https://hooks.example.com/a");
    expect(a.getByText("Enabled")).toBeTruthy();
    expect(a.getByText(/route\.\*/)).toBeTruthy();
    expect(a.queryByRole("button", { name: "Enable again" })).toBeNull();
    const b = await rowOf("https://hooks.example.com/b");
    expect(b.getByText(/^Disabled: failing since/)).toBeTruthy();
    expect(b.getByText(/All events/)).toBeTruthy();
    expect(b.getByText(/nothing delivered yet/)).toBeTruthy();
  });

  it("says so when there is no endpoint", async () => {
    webhooks("owner", { hooks: [] });
    expect(await screen.findByText(/No webhook yet/)).toBeTruthy();
  });

  it("creates an endpoint and shows the secret once, until it is stored", async () => {
    const c = webhooks();
    const s = await page();
    await fillCreate(s, "https://hooks.example.com/new");
    expect([marked(screen.getByRole("form", { name: "New webhook…" })), unmatched(screen.getByRole("form", { name: "New webhook…" }))]).toEqual([["URL"], []]);
    fireEvent.click(s.getByRole("button", { name: "Create the webhook" }));
    const secret = within(await screen.findByRole("region", { name: "Signing secret" }));
    expect(secret.getByText(/Store this secret now/)).toBeTruthy();
    fireEvent.click(secret.getByRole("button", { name: "Show" }));
    expect(secret.getByLabelText("Signing secret").textContent).toBe("rpmgr_whs_SECRET1");
    expect(await s.findByText("https://hooks.example.com/new")).toBeTruthy();
    expect(c.creates.map((r) => [r.orgId, r.webhook?.url, r.webhook?.eventTypes, r.webhook?.enabled])).toEqual([["org_1", "https://hooks.example.com/new", ["route.*", "connector.*"], true]]);
    fireEvent.click(secret.getByRole("button", { name: "I have stored it" }));
    expect(screen.queryByRole("region", { name: "Signing secret" })).toBeNull();
    expect(document.body.textContent).not.toContain("SECRET1");
  });

  it.each([
    ["not a URL", "hooks.example.com", "This is not a URL"],
    ["http", "http://hooks.example.com/x", "The URL must start with https://."],
    ["credentials", "https://user:pw@hooks.example.com/x", "must not carry a user name"],
  ])("refuses %s before it sends anything", async (_n, url, message) => {
    const c = webhooks();
    const s = await page();
    await fillCreate(s, url);
    fireEvent.click(s.getByRole("button", { name: "Create the webhook" }));
    expect((await s.findByText(new RegExp(message))).textContent).toContain(message);
    expect(c.creates).toEqual([]);
  });

  it("shows why the server refused an endpoint, and shows no secret", async () => {
    webhooks("owner", { create: new ConnectError("api: the event type \"bogus\" is not an event type or a prefix such as route.*", Code.InvalidArgument) });
    const s = await page();
    await fillCreate(s, "https://hooks.example.com/new", "bogus");
    fireEvent.click(s.getByRole("button", { name: "Create the webhook" }));
    expect((await s.findByRole("alert")).textContent).toContain("bogus");
    expect(screen.queryByRole("region", { name: "Signing secret" })).toBeNull();
  });

  it("edits an endpoint with an update mask and its etag", async () => {
    const c = webhooks();
    const a = await rowOf("https://hooks.example.com/a");
    fireEvent.click(a.getByRole("button", { name: "Edit" }));
    fireEvent.change(a.getByLabelText("Event types"), { target: { value: "audit.*" } });
    fireEvent.click(a.getByRole("button", { name: "Save" }));
    expect(await screen.findByText(/audit\.\*/)).toBeTruthy();
    expect(c.updates.map((u) => [u.webhook?.id, u.webhook?.eventTypes, u.updateMask?.paths, u.etag])).toEqual([["whk_1", ["audit.*"], ["url", "event_types", "enabled"], "e1"]]);
  });

  it("enables a disabled endpoint again", async () => {
    const c = webhooks();
    const b = await rowOf("https://hooks.example.com/b");
    fireEvent.click(b.getByRole("button", { name: "Enable again" }));
    await waitFor(() => expect(b.queryByRole("button", { name: "Enable again" })).toBeNull());
    expect(c.updates.map((u) => [u.webhook?.id, u.webhook?.enabled, u.updateMask?.paths, u.etag])).toEqual([["whk_2", true, ["enabled"], "e2"]]);
  });

  it("rotates the secret after a confirmation and shows the new one once", async () => {
    const c = webhooks();
    const a = await rowOf("https://hooks.example.com/a");
    fireEvent.click(a.getByRole("button", { name: "Rotate secret…" }));
    expect(c.rotated).toEqual([]);
    fireEvent.click(a.getByRole("button", { name: "Rotate the secret" }));
    const secret = within(await screen.findByRole("region", { name: "Signing secret" }));
    fireEvent.click(secret.getByRole("button", { name: "Show" }));
    expect(secret.getByLabelText("Signing secret").textContent).toBe("rpmgr_whs_SECRET2");
    expect(c.rotated).toEqual(["whk_1"]);
    fireEvent.click(secret.getByRole("button", { name: "I have stored it" }));
    expect(document.body.textContent).not.toContain("SECRET2");
  });

  it("does not rotate when the confirmation is cancelled", async () => {
    const c = webhooks();
    const a = await rowOf("https://hooks.example.com/a");
    fireEvent.click(a.getByRole("button", { name: "Rotate secret…" }));
    fireEvent.click(a.getByRole("button", { name: "Cancel" }));
    expect(c.rotated).toEqual([]);
    expect(a.getByRole("button", { name: "Rotate secret…" })).toBeTruthy();
  });

  it("shows an error of the rotation in the row and no secret", async () => {
    webhooks("owner", { rotate: new ConnectError("api: nope", Code.PermissionDenied) });
    const a = await rowOf("https://hooks.example.com/a");
    fireEvent.click(a.getByRole("button", { name: "Rotate secret…" }));
    fireEvent.click(a.getByRole("button", { name: "Rotate the secret" }));
    expect((await a.findByRole("alert")).textContent).toBe("api: nope");
    expect(screen.queryByRole("region", { name: "Signing secret" })).toBeNull();
  });

  it("sends a test event and says what the receiver answered", async () => {
    const c = webhooks();
    const a = await rowOf("https://hooks.example.com/a");
    fireEvent.click(a.getByRole("button", { name: "Send test event" }));
    expect((await a.findByRole("status")).textContent).toBe("The receiver answered 204.");
    expect(c.tested).toEqual(["whk_1"]);
  });

  it("says why a test event was not delivered", async () => {
    webhooks("owner", { test: { delivered: false, statusCode: 0, error: "refused: private range 10.0.0.0/8" } });
    const a = await rowOf("https://hooks.example.com/a");
    fireEvent.click(a.getByRole("button", { name: "Send test event" }));
    expect((await a.findByRole("status")).textContent).toBe("The test event was not delivered: refused: private range 10.0.0.0/8");
  });

  it("deletes an endpoint after a confirmation that names it", async () => {
    const c = webhooks();
    const a = await rowOf("https://hooks.example.com/a");
    fireEvent.click(a.getByRole("button", { name: "Delete…" }));
    expect(a.getByText(/^Delete https:\/\/hooks\.example\.com\/a and its deliveries\?/)).toBeTruthy();
    expect(c.deleted).toEqual([]);
    fireEvent.click(a.getByRole("button", { name: "Delete the webhook" }));
    await waitFor(() => expect(screen.queryByText("https://hooks.example.com/a")).toBeNull());
    expect(screen.getByText("https://hooks.example.com/b")).toBeTruthy();
    expect(c.deleted).toEqual(["whk_1 e1"]);
  });

  it("shows the deliveries a page at a time", async () => {
    const c = webhooks("owner", { deliveries: [
      [{ id: "d1", eventType: "route.create", attempt: 1, statusCode: 200, sendTime: ts(1_700_000_100) }],
      [{ id: "d2", eventType: "route.delete", attempt: 3, statusCode: 500, sendTime: ts(1_700_000_000), nextAttemptTime: ts(1_700_000_900) },
        { id: "d3", eventType: "route.update", attempt: 2, error: "timeout", sendTime: ts(1_699_999_000) }],
    ] });
    const a = await rowOf("https://hooks.example.com/a");
    fireEvent.click(a.getByRole("button", { name: "Deliveries" }));
    const log = within(await a.findByRole("region", { name: "Deliveries" }));
    expect(await log.findByText("route.create")).toBeTruthy();
    expect(log.getByText("HTTP 200")).toBeTruthy();
    fireEvent.click(log.getByRole("button", { name: "Show older deliveries" }));
    expect(await log.findByText("route.delete")).toBeTruthy();
    expect(log.getByText("HTTP 500")).toBeTruthy();
    expect(log.getByText("attempt 3")).toBeTruthy();
    expect(log.getByText(/^next retry/)).toBeTruthy();
    expect(log.getByText("timeout")).toBeTruthy();
    expect(log.queryByRole("button", { name: "Show older deliveries" })).toBeNull();
    expect(c.deliveryPages).toEqual(["", "1"]);
  });

  it("says so when nothing was delivered", async () => {
    webhooks();
    const a = await rowOf("https://hooks.example.com/a");
    fireEvent.click(a.getByRole("button", { name: "Deliveries" }));
    expect(await a.findByText("Nothing has been sent to this endpoint yet.")).toBeTruthy();
  });

  it.each(["viewer", "operator"])("shows a %s no endpoint and no write button, and asks the API for nothing", async (role) => {
    const c = webhooks(role);
    const s = await page();
    expect(await s.findByText(/need the webhooks\.write permission/)).toBeTruthy();
    expect(s.queryByRole("button", { name: "New webhook…" })).toBeNull();
    expect(c.listed).toBe(0);
  });

  it("shows an error of the list", async () => {
    show("/webhooks", auth({ getSession: () => ({ userId: "usr_ada", displayName: "Ada", memberships: [{ orgId: "org_1", role: "admin" }] }) }), (router) => {
      router.service(UserService, { getMe: () => ({ user: { id: "usr_ada", theme: Theme.SYSTEM } }) });
      router.service(WebhookService, { listWebhooks: () => { throw apiError(Code.Internal); } });
    });
    expect((await (await page()).findByRole("alert")).textContent).toMatch(/failed|api error/i);
  });
});
