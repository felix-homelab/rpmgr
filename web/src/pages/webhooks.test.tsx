// SPDX-License-Identifier: Apache-2.0

import { Code, ConnectError } from "@connectrpc/connect";
import { cleanup, fireEvent, screen, waitFor, within } from "@testing-library/react";
import { afterEach, describe, expect, it } from "vitest";
import { Theme, UserService } from "@/gen/rpmgr/v1/user_pb";
import { WebhookFormat, WebhookMentionWhen, WebhookService, type CreateWebhookRequest, type PreviewWebhookMessageRequest, type UpdateWebhookRequest } from "@/gen/rpmgr/v1/webhook_pb";
import { apiError, auth, show } from "@/testing/api";
import { marked, unmatched } from "@/testing/required";

afterEach(cleanup);

const ts = (s: number) => ({ seconds: BigInt(s) });
const live = { id: "whk_1", orgId: "org_1", url: "https://hooks.example.com/a", eventTypes: ["route.*"], enabled: true, secretSet: true, etag: "e1", lastSuccessTime: ts(1_700_000_000) };
const chat = { id: "whk_3", orgId: "org_1", url: "https://discord.com", format: WebhookFormat.DISCORD, eventTypes: ["alert.*"], enabled: true, secretSet: false, etag: "e3" };
const dead = { id: "whk_2", orgId: "org_1", url: "https://hooks.example.com/b", eventTypes: [], enabled: false, secretSet: true, etag: "e2", failingSinceTime: ts(1_700_000_000) };

interface Calls { previews: PreviewWebhookMessageRequest[]; creates: CreateWebhookRequest[]; updates: UpdateWebhookRequest[]; rotated: string[]; deleted: string[]; tested: string[]; listed: number; deliveryPages: string[] }

// webhooks renders /webhooks for a user with role in org_1; the options refuse or shape single calls.
function webhooks(role = "owner", opts: { hooks?: object[]; create?: ConnectError; rotate?: ConnectError; test?: { delivered: boolean; statusCode: number; error: string }; deliveries?: object[][]; preview?: ConnectError } = {}) {
  const c: Calls = { previews: [], creates: [], updates: [], rotated: [], deleted: [], tested: [], listed: 0, deliveryPages: [] };
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
        const isChat = req.webhook!.format !== WebhookFormat.UNSPECIFIED && req.webhook!.format !== WebhookFormat.RPMGR;
        // A chat endpoint shows its host only and has no signing secret.
        hooks = [...hooks, { ...req.webhook, id: "whk_new", orgId: "org_1", secretSet: !isChat, secretUrl: "", url: isChat ? new URL(req.webhook!.secretUrl).origin : req.webhook!.url }];
        return { webhook: hooks.at(-1), secret: isChat ? "" : "rpmgr_whs_SECRET1" };
      },
      updateWebhook: (req) => {
        c.updates.push(req);
        const w = req.webhook!;
        const camel = (k: string) => k.replace(/_(\w)/g, (_m, ch: string) => ch.toUpperCase());
        const set: Record<string, unknown> = { url: w.url, eventTypes: w.eventTypes, enabled: w.enabled, format: w.format };
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
      previewWebhookMessage: (req) => {
        c.previews.push(req);
        if (opts.preview) {
          throw opts.preview;
        }
        const w = req.webhook!;
        return { previews: ["alert.fire", "alert.resolve", "route.update"].map((eventType) => ({ eventType, body: `{"sample":"${eventType}","mention":"${w.mention}","user":"${w.discordUsername}"}` })) };
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

  it("creates a chat endpoint with the service's URL in secretUrl and shows no secret", async () => {
    const c = webhooks();
    const s = await page();
    fireEvent.click(await s.findByRole("button", { name: "New webhook…" }));
    fireEvent.change(s.getByLabelText("Format"), { target: { value: String(WebhookFormat.SLACK) } });
    expect(s.getByText(/has no signing secret/)).toBeTruthy();
    fireEvent.change(s.getByLabelText("Webhook URL of the service"), { target: { value: "https://hooks.slack.com/services/T/B/TOKEN" } });
    fireEvent.click(s.getByRole("button", { name: "Create the webhook" }));
    const row = await rowOf("https://hooks.slack.com");
    expect(row.getByText("Slack")).toBeTruthy();
    expect(row.queryByRole("button", { name: "Rotate secret…" })).toBeNull();
    expect(screen.queryByRole("region", { name: "Signing secret" })).toBeNull();
    expect(c.creates.map((r) => [r.webhook?.format, r.webhook?.url, r.webhook?.secretUrl])).toEqual([[WebhookFormat.SLACK, "", "https://hooks.slack.com/services/T/B/TOKEN"]]);
    expect(document.body.textContent).not.toContain("TOKEN");
  });

  it("refuses a chat URL that is not https before it sends anything", async () => {
    const c = webhooks();
    const s = await page();
    fireEvent.click(await s.findByRole("button", { name: "New webhook…" }));
    fireEvent.change(s.getByLabelText("Format"), { target: { value: String(WebhookFormat.DISCORD) } });
    fireEvent.change(s.getByLabelText("Webhook URL of the service"), { target: { value: "http://discord.com/api/webhooks/1/x" } });
    fireEvent.click(s.getByRole("button", { name: "Create the webhook" }));
    expect(await s.findByText("The URL must start with https://.")).toBeTruthy();
    expect(c.creates).toEqual([]);
  });

  it("edits a chat endpoint without its URL: nothing of the URL is sent, and it cannot be rotated", async () => {
    const c = webhooks("owner", { hooks: [chat] });
    const d = await rowOf("https://discord.com");
    expect(d.getByText("Discord")).toBeTruthy();
    expect(d.queryByRole("button", { name: "Rotate secret…" })).toBeNull();
    fireEvent.click(d.getByRole("button", { name: "Edit" }));
    expect((d.getByLabelText("Webhook URL of the service") as HTMLInputElement).value).toBe("");
    expect(d.queryByRole("option", { name: "rpmgr (signed JSON)" })).toBeNull();
    fireEvent.change(d.getByLabelText("Event types"), { target: { value: "route.*" } });
    fireEvent.click(d.getByRole("button", { name: "Save" }));
    await waitFor(() => expect(c.updates).toHaveLength(1));
    expect(c.updates.map((u) => [u.updateMask?.paths, u.webhook?.secretUrl, u.webhook?.url, u.etag])).toEqual([[["event_types", "enabled"], "", "", "e3"]]);
  });

  it("keeps the browser from remembering a chat URL, which holds a token", async () => {
    webhooks();
    const s = await page();
    fireEvent.click(await s.findByRole("button", { name: "New webhook…" }));
    expect((s.getByLabelText("URL") as HTMLInputElement).autocomplete).not.toBe("off");
    fireEvent.change(s.getByLabelText("Format"), { target: { value: String(WebhookFormat.TEAMS) } });
    const input = s.getByLabelText("Webhook URL of the service") as HTMLInputElement;
    expect([input.autocomplete, input.getAttribute("spellcheck"), input.getAttribute("autocorrect")]).toEqual(["off", "false", "off"]);
  });

  it("changes a chat endpoint's URL, and its format only with a new URL", async () => {
    const c = webhooks("owner", { hooks: [chat] });
    const d = await rowOf("https://discord.com");
    fireEvent.click(d.getByRole("button", { name: "Edit" }));
    fireEvent.change(d.getByLabelText("Format"), { target: { value: String(WebhookFormat.TEAMS) } });
    // A new format needs a new URL: a URL belongs to its service.
    expect((d.getByRole("button", { name: "Save" }) as HTMLButtonElement).disabled).toBe(true);
    expect(c.updates).toEqual([]);
    fireEvent.change(d.getByLabelText("Webhook URL of the service"), { target: { value: "https://prod-1.logic.azure.com/workflows/x?sig=y" } });
    fireEvent.click(d.getByRole("button", { name: "Save" }));
    await waitFor(() => expect(c.updates).toHaveLength(1));
    expect(c.updates.map((u) => [u.updateMask?.paths, u.webhook?.format, u.webhook?.secretUrl])).toEqual([
      [["event_types", "enabled", "format", "secret_url"], WebhookFormat.TEAMS, "https://prod-1.logic.azure.com/workflows/x?sig=y"]]);
  });

  it("turns an rpmgr endpoint into a chat one with a new URL", async () => {
    const c = webhooks();
    const a = await rowOf("https://hooks.example.com/a");
    fireEvent.click(a.getByRole("button", { name: "Edit" }));
    fireEvent.change(a.getByLabelText("Format"), { target: { value: String(WebhookFormat.DISCORD) } });
    fireEvent.change(a.getByLabelText("Webhook URL of the service"), { target: { value: "https://discord.com/api/webhooks/1/x" } });
    fireEvent.click(a.getByRole("button", { name: "Save" }));
    await waitFor(() => expect(c.updates).toHaveLength(1));
    expect(c.updates[0]!.updateMask?.paths).toEqual(["event_types", "enabled", "format", "secret_url"]);
  });

  it("shows why the server refused a chat endpoint", async () => {
    webhooks("owner", { create: new ConnectError("api: the url of a chat service has a path that holds its token, and this has none", Code.InvalidArgument) });
    const s = await page();
    fireEvent.click(await s.findByRole("button", { name: "New webhook…" }));
    fireEvent.change(s.getByLabelText("Format"), { target: { value: String(WebhookFormat.DISCORD) } });
    fireEvent.change(s.getByLabelText("Webhook URL of the service"), { target: { value: "https://discord.com" } });
    fireEvent.click(s.getByRole("button", { name: "Create the webhook" }));
    expect((await s.findByRole("alert")).textContent).toContain("holds its token");
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

  describe("chat options (D170)", () => {
    const withOptions = { ...chat, mention: "role:1", mentionWhen: WebhookMentionWhen.ALL, discordUsername: "alerts", discordAvatarUrl: "https://cdn.example/a.png", threadName: "t" };

    it("shows the options of a chat format and none for rpmgr, Discord's only for Discord", async () => {
      webhooks();
      const s = await page();
      fireEvent.click(await s.findByRole("button", { name: "New webhook…" }));
      expect(s.queryByLabelText("Mention")).toBeNull();
      expect(s.queryByRole("button", { name: "Preview the message" })).toBeNull();
      fireEvent.change(s.getByLabelText("Format"), { target: { value: String(WebhookFormat.SLACK) } });
      expect(s.getByLabelText("Mention")).toBeTruthy();
      expect(s.getByLabelText("Mention when")).toBeTruthy();
      expect(s.getByText(/subteam:<id>/)).toBeTruthy();
      expect(s.queryByLabelText("Discord user name")).toBeNull();
      fireEvent.change(s.getByLabelText("Format"), { target: { value: String(WebhookFormat.DISCORD) } });
      for (const l of ["Discord user name", "Discord avatar URL", "Discord thread name"]) {
        expect(s.getByLabelText(l)).toBeTruthy();
      }
      fireEvent.change(s.getByLabelText("Format"), { target: { value: String(WebhookFormat.TEAMS) } });
      expect(s.queryByLabelText("Discord user name")).toBeNull();
      expect(s.getByText(/Microsoft Entra object ID/)).toBeTruthy();
    });

    it("creates a Discord endpoint with its options", async () => {
      const c = webhooks();
      const s = await page();
      fireEvent.click(await s.findByRole("button", { name: "New webhook…" }));
      fireEvent.change(s.getByLabelText("Format"), { target: { value: String(WebhookFormat.DISCORD) } });
      fireEvent.change(s.getByLabelText("Webhook URL of the service"), { target: { value: "https://discord.com/api/webhooks/1/x" } });
      fireEvent.change(s.getByLabelText("Mention"), { target: { value: " role:123 " } });
      fireEvent.change(s.getByLabelText("Mention when"), { target: { value: String(WebhookMentionWhen.CRITICAL) } });
      fireEvent.change(s.getByLabelText("Discord user name"), { target: { value: "rpmgr alerts" } });
      fireEvent.change(s.getByLabelText("Discord avatar URL"), { target: { value: "https://cdn.example/a.png" } });
      fireEvent.change(s.getByLabelText("Discord thread name"), { target: { value: "alerts" } });
      fireEvent.click(s.getByRole("button", { name: "Create the webhook" }));
      await waitFor(() => expect(c.creates).toHaveLength(1));
      const w = c.creates[0]!.webhook!;
      expect([w.mention, w.mentionWhen, w.discordUsername, w.discordAvatarUrl, w.threadName]).toEqual(["role:123", WebhookMentionWhen.CRITICAL, "rpmgr alerts", "https://cdn.example/a.png", "alerts"]);
    });

    it("sends no Discord option for another service, even one typed before the format changed", async () => {
      const c = webhooks();
      const s = await page();
      fireEvent.click(await s.findByRole("button", { name: "New webhook…" }));
      fireEvent.change(s.getByLabelText("Format"), { target: { value: String(WebhookFormat.DISCORD) } });
      fireEvent.change(s.getByLabelText("Discord user name"), { target: { value: "typed" } });
      fireEvent.change(s.getByLabelText("Format"), { target: { value: String(WebhookFormat.SLACK) } });
      fireEvent.change(s.getByLabelText("Webhook URL of the service"), { target: { value: "https://hooks.slack.com/services/T/B/X" } });
      fireEvent.click(s.getByRole("button", { name: "Create the webhook" }));
      await waitFor(() => expect(c.creates).toHaveLength(1));
      expect(c.creates[0]!.webhook!.discordUsername).toBe("");
    });

    it("an edit names only the options that changed, and starts from the stored ones", async () => {
      const c = webhooks("owner", { hooks: [withOptions] });
      const d = await rowOf("https://discord.com");
      fireEvent.click(d.getByRole("button", { name: "Edit" }));
      expect((d.getByLabelText("Mention") as HTMLInputElement).value).toBe("role:1");
      expect((d.getByLabelText("Mention when") as HTMLSelectElement).value).toBe(String(WebhookMentionWhen.ALL));
      expect((d.getByLabelText("Discord user name") as HTMLInputElement).value).toBe("alerts");
      fireEvent.change(d.getByLabelText("Mention"), { target: { value: "" } });
      fireEvent.click(d.getByRole("button", { name: "Save" }));
      await waitFor(() => expect(c.updates).toHaveLength(1));
      expect(c.updates[0]!.updateMask?.paths).toEqual(["event_types", "enabled", "mention"]);
      expect(c.updates[0]!.webhook!.mention).toBe("");
    });

    it("moving to another service clears the Discord options in the same update", async () => {
      const c = webhooks("owner", { hooks: [withOptions] });
      const d = await rowOf("https://discord.com");
      fireEvent.click(d.getByRole("button", { name: "Edit" }));
      fireEvent.change(d.getByLabelText("Format"), { target: { value: String(WebhookFormat.SLACK) } });
      fireEvent.change(d.getByLabelText("Webhook URL of the service"), { target: { value: "https://hooks.slack.com/services/T/B/X" } });
      fireEvent.click(d.getByRole("button", { name: "Save" }));
      await waitFor(() => expect(c.updates).toHaveLength(1));
      expect(c.updates[0]!.updateMask?.paths).toEqual(["event_types", "enabled", "discord_username", "discord_avatar_url", "thread_name", "format", "secret_url"]);
      const w = c.updates[0]!.webhook!;
      expect([w.discordUsername, w.discordAvatarUrl, w.threadName, w.mention]).toEqual(["", "", "", "role:1"]);
    });

    it("previews the message as the server makes it, again when the options change", async () => {
      const c = webhooks();
      const s = await page();
      fireEvent.click(await s.findByRole("button", { name: "New webhook…" }));
      fireEvent.change(s.getByLabelText("Format"), { target: { value: String(WebhookFormat.DISCORD) } });
      expect(c.previews).toEqual([]); // nothing is asked until the preview is
      fireEvent.click(s.getByRole("button", { name: "Preview the message" }));
      const box = within(await screen.findByRole("region", { name: "The message as the service would show it" }));
      expect((await box.findByLabelText("alert.fire")).textContent).toContain('"sample":"alert.fire"');
      expect(c.previews.map((p) => [p.orgId, p.webhook?.format])).toEqual([["org_1", WebhookFormat.DISCORD]]);
      fireEvent.change(box.getByLabelText("Sample"), { target: { value: "alert.resolve" } });
      expect(box.getByLabelText("alert.resolve").textContent).toContain("alert.resolve");
      fireEvent.change(s.getByLabelText("Discord user name"), { target: { value: "bot" } });
      await waitFor(() => expect(box.getByLabelText("alert.resolve").textContent).toContain('"user":"bot"'), { timeout: 3000 });
      expect(c.previews).toHaveLength(2);
      // Closing it hides the preview.
      fireEvent.click(s.getByRole("button", { name: "Preview the message" }));
      expect(screen.queryByRole("region", { name: "The message as the service would show it" })).toBeNull();
    });

    it("shows why a preview failed", async () => {
      webhooks("owner", { preview: new ConnectError("webhook: mention is not valid for the discord format", Code.InvalidArgument) });
      const s = await page();
      fireEvent.click(await s.findByRole("button", { name: "New webhook…" }));
      fireEvent.change(s.getByLabelText("Format"), { target: { value: String(WebhookFormat.DISCORD) } });
      fireEvent.click(s.getByRole("button", { name: "Preview the message" }));
      expect((await screen.findByText(/The preview failed: .*mention is not valid/)).textContent).toBeTruthy();
    });
  });
});
