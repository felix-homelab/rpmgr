// SPDX-License-Identifier: Apache-2.0

import { timestampFromDate } from "@bufbuild/protobuf/wkt";
import { Code } from "@connectrpc/connect";
import { cleanup, fireEvent, screen, waitFor, within } from "@testing-library/react";
import { afterEach, describe, expect, it } from "vitest";
import { ConnectorService, type EndConnectorDrainRequest } from "@/gen/rpmgr/v1/connector_pb";
import { GatewayService, type EndGatewayDrainRequest } from "@/gen/rpmgr/v1/gateway_pb";
import { StatusService } from "@/gen/rpmgr/v1/status_pb";
import { Theme, UserService } from "@/gen/rpmgr/v1/user_pb";
import { apiError, auth, show } from "@/testing/api";

afterEach(cleanup);

const drain = { connections: 12n, flows: 3n, sessions: 2n, since: timestampFromDate(new Date("2026-10-29T10:00:00Z")), ends: timestampFromDate(new Date("2026-10-29T10:05:00Z")) };

// page renders path for a user with role; the gateway gw-eu and the connector office report an old
// process unless without is set, and EndGatewayDrain fails with refuse, if given.
function page(path: string, role = "admin", opts: { without?: boolean; builtIn?: boolean; instanceAdmin?: boolean; refuse?: Error } = {}) {
  const gateways: EndGatewayDrainRequest[] = [];
  const connectors: EndConnectorDrainRequest[] = [];
  show(path, auth({
    getSession: () => ({ userId: "usr_ada", instanceAdmin: !!opts.instanceAdmin, memberships: [{ orgId: "org_1", role }] }),
    stepUp: () => ({}),
  }), (router) => {
    router.service(UserService, { getMe: () => ({ user: { id: "usr_ada", theme: Theme.SYSTEM } }) });
    router.service(StatusService, { async *watchApplyStatus() {} });
    router.service(GatewayService, {
      listGatewayGroups: () => ({ gatewayGroups: [{ id: "ggr_eu", name: "eu" }] }),
      listGateways: () => ({ gateways: [
        { id: "gtw_1", gatewayGroupId: "ggr_eu", name: "gw-eu", slot: 1, enabled: true, builtIn: !!opts.builtIn, status: { enrolled: true, connected: true, draining: opts.without ? undefined : drain } },
        { id: "gtw_2", gatewayGroupId: "ggr_eu", name: "gw-quiet", slot: 2, enabled: true, status: { enrolled: true, connected: true } },
      ] }),
      endGatewayDrain: (req) => {
        if (opts.refuse) throw opts.refuse;
        gateways.push(req);
        return { ended: drain };
      },
    });
    const office = { id: "con_1", name: "office", enabled: true, session: { connected: true, draining: opts.without ? undefined : { ...drain, connections: 40n, flows: 0n } } };
    router.service(ConnectorService, {
      listConnectors: () => ({ connectors: [office] }),
      getConnector: () => ({ connector: office }),
      getConnectorStatus: () => ({ status: { session: office.session } }),
      endConnectorDrain: (req) => (connectors.push(req), { ended: drain }),
    });
  });
  return { gateways, connectors };
}

describe("Restarting", () => {
  it("lists the old processes on the dashboard with their counts and ends one after naming what it cuts", async () => {
    const { gateways } = page("/");
    const card = within(await screen.findByRole("region", { name: "Restarting" }));
    const lines = await card.findAllByRole("listitem");
    expect(lines.map((li) => li.textContent?.split("draining since")[0])).toEqual([
      "gw-eu12 connections, 3 UDP flows, 2 sessions", "office40 streams, 2 sessions"]);
    expect(card.queryByText("gw-quiet")).toBeNull();
    fireEvent.click(within(lines[0]!).getByRole("button", { name: "End now" }));
    const ask = within(within(lines[0]!).getByRole("alertdialog"));
    expect(ask.getByRole("alert").textContent).toContain("closes its 15 open connections and flows at once");
    fireEvent.click(ask.getByRole("button", { name: "End the old process of gw-eu now" }));
    await waitFor(() => expect(gateways.map((g) => g.gatewayId)).toEqual(["gtw_1"]));
  });

  it("shows nothing when no agent has an old process", async () => {
    page("/", "admin", { without: true });
    await screen.findByRole("list", { name: "Summary" });
    await waitFor(() => expect(screen.queryByRole("region", { name: "Restarting" })).toBeNull());
  });

  it("offers a viewer the counts but no button", async () => {
    page("/", "viewer");
    const card = within(await screen.findByRole("region", { name: "Restarting" }));
    await card.findAllByRole("listitem");
    expect(card.queryByRole("button", { name: "End now" })).toBeNull();
  });

  it("leaves the all-in-one's own gateway to the Instance Admin", async () => {
    page("/", "admin", { builtIn: true });
    const card = within(await screen.findByRole("region", { name: "Restarting" }));
    const gw = (await card.findAllByRole("listitem"))[0]!;
    expect(within(gw).queryByRole("button", { name: "End now" })).toBeNull();
    cleanup();
    page("/", "admin", { builtIn: true, instanceAdmin: true });
    const again = within(await screen.findByRole("region", { name: "Restarting" }));
    expect(within((await again.findAllByRole("listitem"))[0]!).getByRole("button", { name: "End now" })).toBeTruthy();
  });

  it("shows the refusal of the API and keeps the line", async () => {
    page("/", "admin", { refuse: apiError(Code.FailedPrecondition) });
    const card = within(await screen.findByRole("region", { name: "Restarting" }));
    const line = (await card.findAllByRole("listitem"))[0]!;
    fireEvent.click(within(line).getByRole("button", { name: "End now" }));
    fireEvent.click(within(line).getByRole("button", { name: "End the old process of gw-eu now" }));
    await waitFor(() => expect(within(line).getAllByRole("alert").map((a) => a.textContent).join()).toContain("api error"));
    expect(within(line).getByText("gw-eu")).toBeTruthy();
  });
});

describe("the agent pages", () => {
  it("show the old process on the gateway group page", async () => {
    const { gateways } = page("/gateways/ggr_eu");
    const group = within(await screen.findByRole("group", { name: "Restarting" }));
    expect(await group.findByText("12 connections, 3 UDP flows, 2 sessions")).toBeTruthy();
    fireEvent.click(group.getByRole("button", { name: "End now" }));
    fireEvent.click(group.getByRole("button", { name: "End the old process of gw-eu now" }));
    await waitFor(() => expect(gateways).toHaveLength(1));
  });

  it("show it on the connector page", async () => {
    const { connectors } = page("/connectors/con_1");
    expect(await screen.findByText("40 streams, 2 sessions")).toBeTruthy();
    fireEvent.click(screen.getByRole("button", { name: "End now" }));
    expect(screen.getByRole("alert").textContent).toContain("closes its 40 open connections and flows");
    fireEvent.click(screen.getByRole("button", { name: "End the old process of office now" }));
    await waitFor(() => expect(connectors.map((c) => c.connectorId)).toEqual(["con_1"]));
  });
});
