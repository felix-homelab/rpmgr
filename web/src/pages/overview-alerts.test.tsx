// SPDX-License-Identifier: Apache-2.0

import { timestampFromMs } from "@bufbuild/protobuf/wkt";
import { Code } from "@connectrpc/connect";
import { cleanup, fireEvent, screen, waitFor, within } from "@testing-library/react";
import { afterEach, describe, expect, it } from "vitest";
import { RouteService } from "@/gen/rpmgr/v1/route_pb";
import { StatusService, type ListAlertsRequest } from "@/gen/rpmgr/v1/status_pb";
import { Theme, UserService } from "@/gen/rpmgr/v1/user_pb";
import { InstanceWebhookService, WebhookDisabledReason, WebhookService } from "@/gen/rpmgr/v1/webhook_pb";
import { when } from "@/lib/format";
import { apiError, auth, show } from "@/testing/api";

afterEach(cleanup);

const ts = (s: number) => timestampFromMs(s * 1000);
const since = ts(1_700_000_000);

const offline = { id: "alr_1", kind: "agent_offline", subjectType: "gateway", subjectId: "gw_1", subjectName: "edge-1", since };
const noTarget = { id: "alr_2", kind: "route_no_ready_connector", subjectType: "route", subjectId: "rte_1", subjectName: "web", since: ts(1_700_003_600) };
const onHost = { id: "alr_3", kind: "revocation_log_on_host", subjectType: "instance", subjectId: "instance", subjectName: "instance", since };

const failing = { id: "whk_1", orgId: "org_1", url: "https://hooks.example.com/a", enabled: false, disabledReason: WebhookDisabledReason.FAILING, etag: "e1" };
const byPerson = { id: "whk_2", orgId: "org_1", url: "https://hooks.example.com/b", enabled: false, disabledReason: WebhookDisabledReason.PERSON, etag: "e2" };

interface Fixture {
  role?: string;
  admin?: boolean;
  alerts?: object[];
  instanceAlerts?: object[];
  hooks?: object[];
  instanceHooks?: object[];
  alertsError?: boolean;
}

// overview renders / for a user with role in org_1; the lists can be changed while it stands.
function overview(f: Fixture = {}) {
  const state = { alerts: f.alerts ?? [], instanceAlerts: f.instanceAlerts ?? [], hooks: f.hooks ?? [] };
  const asked = { alerts: [] as ListAlertsRequest[], instanceAlerts: 0, hooks: 0, instanceHooks: 0 };
  const view = show("/", auth({
    getSession: () => ({ userId: "usr_ada", displayName: "Ada", instanceAdmin: f.admin ?? false, memberships: [{ orgId: "org_1", role: f.role ?? "viewer" }] }),
  }), (router) => {
    router.service(UserService, { getMe: () => ({ user: { id: "usr_ada", theme: Theme.SYSTEM } }) });
    router.service(RouteService, { listRoutes: () => ({ routes: [] }) });
    router.service(StatusService, {
      listAlerts: (req) => {
        asked.alerts.push(req);
        if (f.alertsError) {
          throw apiError(Code.Unavailable);
        }
        return { alerts: state.alerts };
      },
      listInstanceAlerts: () => (asked.instanceAlerts++, { alerts: state.instanceAlerts }),
    });
    router.service(WebhookService, {
      listWebhooks: () => (asked.hooks++, { webhooks: state.hooks }),
      updateWebhook: (req) => {
        state.hooks = state.hooks.map((h) => ((h as { id: string }).id === req.webhook?.id ? { ...h, enabled: true, disabledReason: WebhookDisabledReason.UNSPECIFIED } : h));
        return {};
      },
    });
    router.service(InstanceWebhookService, { listInstanceWebhooks: () => (asked.instanceHooks++, { webhooks: f.instanceHooks ?? [] }) });
  });
  return { ...view, state, asked };
}

const alertsCard = async () => within(await screen.findByRole("region", { name: "Alerts" }));

describe("Overview alerts", () => {
  it("says that no alert fires", async () => {
    const { asked } = overview();
    const card = await alertsCard();
    expect(await card.findByText("No alert is firing.")).toBeTruthy();
    expect(card.queryByRole("list")).toBeNull();
    expect(asked.alerts.map((r) => [r.orgId, r.state])).toEqual([["org_1", 0]]); // the default: the alerts that fire
    expect(asked.instanceAlerts).toBe(0); // only the Instance Admin reads the instance's
  });

  it("lists the firing alerts with their subject and since when, to a Viewer as well", async () => {
    overview({ role: "viewer", alerts: [offline, noTarget] });
    const card = await alertsCard();
    const list = within(await card.findByRole("list", { name: "Alerts" }));
    const rows = list.getAllByRole("listitem");
    expect(rows.map((li) => li.textContent)).toEqual([
      `Agent offlineedge-1since ${when(offline.since)}`,
      `Route has no ready connectorwebsince ${when(noTarget.since)}`,
    ]);
    expect(within(rows[0]!).queryByRole("link")).toBeNull(); // a gateway has no page of its own to lead to
    expect(within(rows[1]!).getByRole("link", { name: "web" }).getAttribute("href")).toBe("/routes/rte_1");
    expect(card.queryByText("No alert is firing.")).toBeNull();
    expect(screen.queryAllByText(/^alerts\./)).toEqual([]); // U11: never a raw key
  });

  it("shows an alert of a kind it does not know as it is", async () => {
    overview({ alerts: [{ ...offline, kind: "dns_sync_failing" }] });
    expect(await (await alertsCard()).findByText("dns_sync_failing")).toBeTruthy();
  });

  it("lists the instance's alerts apart, for the Instance Admin only", async () => {
    const { asked } = overview({ role: "owner", admin: true, alerts: [offline], instanceAlerts: [onHost] });
    const card = await alertsCard();
    expect(within(await card.findByRole("list", { name: "Organisation" })).getAllByRole("listitem")).toHaveLength(1);
    const inst = within(await card.findByRole("list", { name: "Instance" }));
    expect(inst.getByText("Revocation log not yet off-host")).toBeTruthy();
    expect(asked.instanceAlerts).toBeGreaterThan(0);

    cleanup();
    const other = overview({ role: "owner", admin: false, alerts: [offline], instanceAlerts: [onHost] });
    await (await alertsCard()).findByText("Agent offline");
    expect(screen.queryByText("Revocation log not yet off-host")).toBeNull();
    expect(other.asked.instanceAlerts).toBe(0);
  });

  it("drops an alert that resolved at the next look", async () => {
    const { state } = overview({ alerts: [offline, noTarget] });
    const card = await alertsCard();
    await card.findByText("Agent offline");
    state.alerts = [noTarget];
    const nav = screen.getByRole("navigation", { name: "Main navigation" });
    fireEvent.click(within(nav).getByRole("link", { name: "Routes" }));
    await screen.findByRole("heading", { name: "Routes", level: 1 });
    fireEvent.click(within(nav).getByRole("link", { name: "Overview" }));
    const again = await alertsCard();
    await again.findByText("Route has no ready connector");
    expect(again.queryByText("Agent offline")).toBeNull();

    state.alerts = [];
    fireEvent.click(within(nav).getByRole("link", { name: "Routes" }));
    await screen.findByRole("heading", { name: "Routes", level: 1 });
    fireEvent.click(within(nav).getByRole("link", { name: "Overview" }));
    expect(await (await alertsCard()).findByText("No alert is firing.")).toBeTruthy();
  });

  it("says why the alerts could not be read, and not that none fires", async () => {
    overview({ alertsError: true });
    const card = await alertsCard();
    expect((await card.findByRole("alert")).textContent).toBe("The alerts could not be read: api error");
    expect(card.queryByText("No alert is firing.")).toBeNull();
  });
});

describe("Overview, disabled webhook endpoints", () => {
  const notice = () => screen.queryByRole("list", { name: "Disabled webhook endpoints" });

  it("tells an Admin of an endpoint the controller disabled, and leads to the page that enables it again", async () => {
    const { asked } = overview({ role: "admin", hooks: [failing, byPerson] });
    const list = within(await screen.findByRole("list", { name: "Disabled webhook endpoints" }));
    const items = list.getAllByRole("alert");
    expect(items).toHaveLength(1); // the one a person disabled is their choice
    expect(items[0]!.textContent).toBe("The webhook endpoint https://hooks.example.com/a was disabled because deliveries to it kept failing.Enable it again");
    expect(list.getByRole("link", { name: "Enable it again" }).getAttribute("href")).toBe("/webhooks");
    expect(asked.hooks).toBeGreaterThan(0);
  });

  it("does not ask a Viewer or an Operator, who may not read the endpoints", async () => {
    for (const role of ["viewer", "operator"]) {
      const { asked } = overview({ role, hooks: [failing] });
      await alertsCard();
      expect(notice()).toBeNull();
      expect(asked.hooks).toBe(0);
      cleanup();
    }
  });

  it("shows no notice while every endpoint is enabled or none exists", async () => {
    overview({ role: "owner", hooks: [{ ...failing, enabled: true, disabledReason: WebhookDisabledReason.UNSPECIFIED }] });
    await alertsCard();
    expect(notice()).toBeNull();
  });

  it("tells the Instance Admin of the instance's endpoints too, leading to Settings", async () => {
    overview({ role: "owner", admin: true, instanceHooks: [{ ...failing, id: "whk_9", orgId: "", url: "https://ops.example.com/x" }] });
    const list = within(await screen.findByRole("list", { name: "Disabled webhook endpoints" }));
    expect(list.getByText(/https:\/\/ops\.example\.com\/x/)).toBeTruthy();
    expect(list.getByRole("link", { name: "Enable it again" }).getAttribute("href")).toBe("/settings/webhooks");
  });

  it("goes away once the endpoint is enabled again", async () => {
    overview({ role: "owner", hooks: [failing] });
    const list = within(await screen.findByRole("list", { name: "Disabled webhook endpoints" }));
    fireEvent.click(list.getByRole("link", { name: "Enable it again" }));
    const page = within(await screen.findByRole("region", { name: "Webhooks" }));
    fireEvent.click(await page.findByRole("button", { name: "Enable again" }));
    await waitFor(() => expect(page.queryByRole("button", { name: "Enable again" })).toBeNull());
    fireEvent.click(within(screen.getByRole("navigation", { name: "Main navigation" })).getByRole("link", { name: "Overview" }));
    await alertsCard();
    await waitFor(() => expect(notice()).toBeNull());
  });
});
