// SPDX-License-Identifier: Apache-2.0

import { create } from "@bufbuild/protobuf";
import { Code, ConnectError } from "@connectrpc/connect";
import { cleanup, fireEvent, screen, waitFor, within } from "@testing-library/react";
import { afterEach, describe, expect, it } from "vitest";
import { InstanceSettingsSchema, SettingsService, type UpdateInstanceSettingsRequest } from "@/gen/rpmgr/v1/settings_pb";
import { Theme, UserService } from "@/gen/rpmgr/v1/user_pb";
import { InstanceWebhookService, WebhookService, type CreateInstanceWebhookRequest } from "@/gen/rpmgr/v1/webhook_pb";
import { apiError, auth, show } from "@/testing/api";

afterEach(cleanup);

const live = { id: "whk_i1", url: "https://ops.example.com/events", eventTypes: ["release.*"], enabled: true, secretSet: true, etag: "e1" };

interface Calls { creates: CreateInstanceWebhookRequest[]; rotated: string[]; deleted: string[]; tested: string[]; orgCalls: number; saves: UpdateInstanceSettingsRequest[] }

// page renders Settings → Webhooks for a user; the options refuse or shape single calls.
function webhooks(admin = true, opts: { hooks?: object[]; create?: ConnectError; ranges?: string[]; save?: ConnectError } = {}) {
  const c: Calls = { creates: [], rotated: [], deleted: [], tested: [], orgCalls: 0, saves: [] };
  let hooks = opts.hooks ?? [live];
  const settings = create(InstanceSettingsSchema, { webhookPrivateRanges: opts.ranges ?? [] });
  show("/settings/webhooks", auth({
    getSession: () => ({ userId: "usr_ada", displayName: "Ada", instanceAdmin: admin, memberships: [{ orgId: "org_1", role: "owner" }] }),
  }), (router) => {
    router.service(UserService, { getMe: () => ({ user: { id: "usr_ada", theme: Theme.SYSTEM } }) });
    router.service(WebhookService, { listWebhooks: () => (c.orgCalls++, { webhooks: [] }) });
    router.service(SettingsService, {
      getInstanceSettings: () => ({ settings, etag: "i1", revocationLog: { sink: true } }),
      updateInstanceSettings: (req) => {
        if (opts.save) {
          throw opts.save;
        }
        c.saves.push(req);
        return { settings: req.settings, etag: "i2" };
      },
    });
    router.service(InstanceWebhookService, {
      listInstanceWebhooks: () => ({ webhooks: hooks }),
      createInstanceWebhook: (req) => {
        c.creates.push(req);
        if (opts.create) {
          throw opts.create;
        }
        hooks = [...hooks, { ...req.webhook, id: "whk_i2", secretSet: true }];
        return { webhook: hooks.at(-1), secret: "SECRET-I1" };
      },
      rotateInstanceWebhookSecret: (req) => (c.rotated.push(req.webhookId), { secret: "SECRET-I2" }),
      deleteInstanceWebhook: (req) => (c.deleted.push(`${req.webhookId} ${req.etag}`), (hooks = hooks.filter((h) => (h as { id: string }).id !== req.webhookId)), {}),
      testInstanceWebhook: (req) => (c.tested.push(req.webhookId), { delivered: true, statusCode: 200, error: "" }),
      listInstanceWebhookDeliveries: () => ({ deliveries: [] }),
    });
  });
  return c;
}

const card = async () => within(await screen.findByRole("region", { name: "Instance webhooks" }));
const rowOf = async (url: string) => within((await screen.findByText(url)).closest("li")!);

describe("Instance webhooks", () => {
  it("lists the instance's endpoints from InstanceWebhookService, and asks no org service", async () => {
    const c = webhooks();
    const a = await rowOf("https://ops.example.com/events");
    expect(a.getByText("Enabled")).toBeTruthy();
    expect(a.getByText(/release\.\*/)).toBeTruthy();
    expect(c.orgCalls).toBe(0);
  });

  it("says so when there is no endpoint", async () => {
    webhooks(true, { hooks: [] });
    expect(await screen.findByText(/No webhook yet/)).toBeTruthy();
  });

  it("creates an endpoint without an organisation and shows the secret once", async () => {
    const c = webhooks();
    const s = await card();
    fireEvent.click(await s.findByRole("button", { name: "New webhook…" }));
    fireEvent.change(s.getByLabelText("URL"), { target: { value: "https://10.1.2.3/hook" } });
    fireEvent.click(s.getByRole("button", { name: "Create the webhook" }));
    const secret = within(await screen.findByRole("region", { name: "Signing secret" }));
    fireEvent.click(secret.getByRole("button", { name: "Show" }));
    expect(secret.getByLabelText("Signing secret").textContent).toBe("SECRET-I1");
    expect(c.creates.map((r) => [r.webhook?.url, r.webhook?.enabled, r.requestId !== ""])).toEqual([["https://10.1.2.3/hook", true, true]]);
    fireEvent.click(secret.getByRole("button", { name: "I have stored it" }));
    expect(document.body.textContent).not.toContain("SECRET-I1");
  });

  it("shows why the server refused an endpoint and no secret", async () => {
    webhooks(true, { create: new ConnectError("api: the event type \"bogus\" is not an event type", Code.InvalidArgument) });
    const s = await card();
    fireEvent.click(await s.findByRole("button", { name: "New webhook…" }));
    fireEvent.change(s.getByLabelText("URL"), { target: { value: "https://ops.example.com/x" } });
    fireEvent.change(s.getByLabelText("Event types"), { target: { value: "bogus" } });
    fireEvent.click(s.getByRole("button", { name: "Create the webhook" }));
    expect((await s.findByRole("alert")).textContent).toContain("bogus");
    expect(screen.queryByRole("region", { name: "Signing secret" })).toBeNull();
  });

  it("rotates, tests and deletes through the instance service", async () => {
    const c = webhooks();
    const a = await rowOf("https://ops.example.com/events");
    fireEvent.click(a.getByRole("button", { name: "Send test event" }));
    expect((await a.findByRole("status")).textContent).toBe("The receiver answered 200.");
    fireEvent.click(a.getByRole("button", { name: "Rotate secret…" }));
    fireEvent.click(a.getByRole("button", { name: "Rotate the secret" }));
    const secret = within(await screen.findByRole("region", { name: "Signing secret" }));
    fireEvent.click(secret.getByRole("button", { name: "Show" }));
    expect(secret.getByLabelText("Signing secret").textContent).toBe("SECRET-I2");
    fireEvent.click(secret.getByRole("button", { name: "I have stored it" }));
    expect(document.body.textContent).not.toContain("SECRET-I2");
    fireEvent.click(a.getByRole("button", { name: "Deliveries" }));
    expect(await a.findByText("Nothing has been sent to this endpoint yet.")).toBeTruthy();
    fireEvent.click(a.getByRole("button", { name: "Delete…" }));
    fireEvent.click(a.getByRole("button", { name: "Delete the webhook" }));
    await waitFor(() => expect(screen.queryByText("https://ops.example.com/events")).toBeNull());
    expect([c.tested, c.rotated, c.deleted]).toEqual([["whk_i1"], ["whk_i1"], ["whk_i1 e1"]]);
  });

  it("shows a user who is no Instance Admin a note and asks the API for nothing", async () => {
    const c = webhooks(false);
    expect(await screen.findByText(/Instance Admin/)).toBeTruthy();
    expect(screen.queryByRole("region", { name: "Instance webhooks" })).toBeNull();
    expect(c.creates).toEqual([]);
  });
});

const rangesForm = async () => within(await screen.findByRole("form", { name: "Webhook receivers" }));
const save = (c: Calls) => waitFor(() => expect(c.saves).toHaveLength(1));

describe("Private ranges", () => {
  it("explains what the ranges admit and what stays blocked", async () => {
    webhooks();
    const f = await rangesForm();
    const field = f.getByLabelText("Private networks admitted for organisations' webhook receivers");
    const hint = document.getElementById(field.getAttribute("aria-describedby") ?? "")?.textContent ?? "";
    expect(hint).toContain("Organisations' webhook endpoints");
    expect(hint).toContain("Loopback, link-local and cloud metadata addresses stay blocked");
  });

  it("saves the ranges with the mask and etag", async () => {
    const c = webhooks(true, { ranges: ["192.168.0.0/16"] });
    const f = await rangesForm();
    const field = f.getByLabelText(/^Private networks admitted/);
    expect((field as HTMLTextAreaElement).value).toBe("192.168.0.0/16");
    fireEvent.change(field, { target: { value: "10.0.0.0/8\n  fd00::/8 \n\n172.16.0.0/12" } });
    fireEvent.click(f.getByRole("button", { name: "Save" }));
    await save(c);
    expect(c.saves[0]).toMatchObject({ etag: "i1", settings: { webhookPrivateRanges: ["10.0.0.0/8", "fd00::/8", "172.16.0.0/12"] } });
    expect(c.saves[0]!.updateMask?.paths).toEqual(["webhook_private_ranges"]);
  });

  it("clears the ranges when the field is emptied", async () => {
    const c = webhooks(true, { ranges: ["10.0.0.0/8"] });
    const f = await rangesForm();
    fireEvent.change(f.getByLabelText(/^Private networks admitted/), { target: { value: "" } });
    fireEvent.click(f.getByRole("button", { name: "Save" }));
    await save(c);
    expect(c.saves[0]!.settings?.webhookPrivateRanges).toEqual([]);
  });

  it.each([
    ["not a range", "hooks.example.com", /"hooks.example.com" is not a range/],
    ["no prefix length", "10.0.0.0", /"10.0.0.0" is not a range/],
    ["an octet above 255", "10.0.0.256/8", /is not a range/],
    ["a prefix above 32", "10.0.0.0/33", /is not a range/],
    ["a prefix above 128", "fd00::/129", /is not a range/],
    ["a bad IPv6 address", "fd00:::1/8", /is not a range/],
    ["host bits in IPv4", "10.1.2.3/8", /Write the network address: 10\.0\.0\.0\/8/],
    ["host bits in IPv6", "fd00::1/8", /bits set beyond its prefix length/],
    ["a duplicate", "10.0.0.0/8\n10.0.0.0/8", /"10.0.0.0\/8" is listed twice/],
    ["more than 32", Array.from({ length: 33 }, (_, i) => `10.${i}.0.0/16`).join("\n"), /At most 32 ranges/],
  ])("refuses %s before it sends anything", async (_n, text, message) => {
    const c = webhooks();
    const f = await rangesForm();
    const field = f.getByLabelText(/^Private networks admitted/);
    fireEvent.change(field, { target: { value: text } });
    fireEvent.click(f.getByRole("button", { name: "Save" }));
    expect((await f.findByText(message)).textContent).toMatch(message);
    expect(field.getAttribute("aria-invalid")).toBe("true");
    expect(c.saves).toEqual([]);
  });

  it("accepts a range of every length at its edges", async () => {
    const c = webhooks();
    const f = await rangesForm();
    fireEvent.change(f.getByLabelText(/^Private networks admitted/), { target: { value: "0.0.0.0/0\n10.1.2.3/32\n::/0\nfd00::1/128" } });
    fireEvent.click(f.getByRole("button", { name: "Save" }));
    await save(c);
  });

  it("shows what the server refused", async () => {
    webhooks(true, { save: apiError(Code.InvalidArgument, "api: webhook_private_ranges: not a prefix") });
    const f = await rangesForm();
    fireEvent.change(f.getByLabelText(/^Private networks admitted/), { target: { value: "10.0.0.0/8" } });
    fireEvent.click(f.getByRole("button", { name: "Save" }));
    expect((await screen.findByRole("alert")).textContent).toMatch(/not a prefix|api error/i);
  });
});
