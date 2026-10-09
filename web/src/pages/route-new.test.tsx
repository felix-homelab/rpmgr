// SPDX-License-Identifier: Apache-2.0

import { Code, ConnectError } from "@connectrpc/connect";
import { cleanup, fireEvent, screen, waitFor, within } from "@testing-library/react";
import { afterEach, describe, expect, it } from "vitest";
import { ConnectorService } from "@/gen/rpmgr/v1/connector_pb";
import { GatewayService } from "@/gen/rpmgr/v1/gateway_pb";
import { Port80Mode, RouteService, TLSMode, type CreateRouteRequest, type PreviewRouteRequest } from "@/gen/rpmgr/v1/route_pb";
import { ApplyState, StatusService } from "@/gen/rpmgr/v1/status_pb";
import { Theme, UserService } from "@/gen/rpmgr/v1/user_pb";
import { auth, show } from "@/testing/api";

afterEach(cleanup);

// chooseGroup chooses the gateway group "eu" once it is listed.
async function chooseGroup() {
  await screen.findByRole("option", { name: "eu" });
  fireEvent.change(screen.getByLabelText("Gateway group"), { target: { value: "ggr_eu" } });
}

// page renders path with a gateway group "eu"; CreateRoute answers with create, if given.
function page(path: string, create?: (req: CreateRouteRequest) => object) {
  const creates: CreateRouteRequest[] = [];
  const previews: PreviewRouteRequest[] = [];
  const view = show(path, auth({ getSession: () => ({ userId: "usr_ada", memberships: [{ orgId: "org_1", role: "owner" }] }) }), (router) => {
    router.service(UserService, { getMe: () => ({ user: { id: "usr_ada", theme: Theme.SYSTEM } }) });
    router.service(GatewayService, {
      listGatewayGroups: () => ({ gatewayGroups: [{ id: "ggr_eu", name: "eu" }] }),
      listGateways: () => ({ gateways: [{ id: "gtw_1", name: "gw-eu-1" }] }),
    });
    router.service(ConnectorService, { listConnectors: () => ({ connectors: [{ id: "con_1", name: "db-host-1" }] }) });
    router.service(StatusService, { async *watchApplyStatus() {} });
    router.service(RouteService, {
      listRoutes: () => ({}),
      getRoute: () => ({ route: { id: "rte_1", name: "wiki", etag: "7", spec: { case: "tcp", value: { port: 25432 } } } }),
      createRoute: (req) => (creates.push(req), create ? create(req) : {
        route: { ...req.route, id: "rte_new" }, revision: { dbEpoch: "e", seq: 5n }, applyStatus: { state: ApplyState.APPLIED, agentsTotal: 1, agentsApplied: 1 },
      }),
      previewRoute: (req) => (previews.push(req), {
        route: req.route, gatewayIds: ["gtw_1"], connectorIds: req.updateMask ? ["con_1"] : [],
        problems: req.route?.name === "bad" ? [{ message: "port 25432 in use on gw-eu-1" }] : [],
      }),
    });
  });
  return { ...view, creates, previews };
}

describe("RouteNew", () => {
  it("creates an HTTP route with ACME and a port-80 redirect, then follows it to the agents", async () => {
    const { creates } = page("/routes/new");
    await chooseGroup();
    fireEvent.change(screen.getByLabelText("Name"), { target: { value: "wiki" } });
    fireEvent.change(screen.getByLabelText("Hostnames"), { target: { value: "wiki.example.com" } });
    fireEvent.click(screen.getByRole("button", { name: "Create the route" }));
    expect(await screen.findByText("Revision 5: applied by all 1 agents.")).toBeTruthy();
    expect(screen.getByRole("link", { name: "Open wiki to add its targets" }).getAttribute("href")).toBe("/routes/rte_new");
    const r = creates[0]!;
    expect([r.orgId, r.route?.name, r.route?.gatewayGroupId, r.route?.enabled]).toEqual(["org_1", "wiki", "ggr_eu", true]);
    expect(r.route?.spec.case === "http" && [r.route.spec.value.hostnames, r.route.spec.value.tlsMode, r.route.spec.value.port80])
      .toEqual([["wiki.example.com"], TLSMode.TLS_MODE_ACME, Port80Mode.REDIRECT]);
    expect(r.requestId).toMatch(/^[0-9a-f-]{36}$/);
  });

  it("creates a TCP route on a free port of the pools", async () => {
    const { creates } = page("/routes/new");
    fireEvent.click(await screen.findByLabelText("TCP"));
    await chooseGroup();
    fireEvent.change(screen.getByLabelText("Name"), { target: { value: "pg" } });
    expect((screen.getByLabelText("Public port") as HTMLInputElement).value).toBe("0");
    fireEvent.click(screen.getByRole("button", { name: "Create the route" }));
    await waitFor(() => expect(creates).toHaveLength(1));
    expect(creates[0]!.route?.spec).toMatchObject({ case: "tcp", value: { port: 0 } });
  });

  it("needs a gateway group, and shows the server's refusal", async () => {
    const { creates } = page("/routes/new", () => { throw new ConnectError("apisvc: the org's port quota is used up", Code.ResourceExhausted); });
    fireEvent.change(await screen.findByLabelText("Name"), { target: { value: "wiki" } });
    fireEvent.change(screen.getByLabelText("Hostnames"), { target: { value: "wiki.example.com" } });
    fireEvent.click(screen.getByRole("button", { name: "Create the route" }));
    expect((await screen.findByRole("alert")).textContent).toBe("Choose the gateway group that serves the route.");
    expect(creates).toEqual([]);
    await chooseGroup();
    fireEvent.click(screen.getByRole("button", { name: "Create the route" }));
    expect(await screen.findByText("apisvc: the org's port quota is used up")).toBeTruthy();
  });

  it("previews a new route without creating it", async () => {
    const { creates, previews } = page("/routes/new");
    await chooseGroup();
    fireEvent.change(screen.getByLabelText("Name"), { target: { value: "bad" } });
    fireEvent.change(screen.getByLabelText("Hostnames"), { target: { value: "wiki.example.com" } });
    fireEvent.click(screen.getByRole("button", { name: "Preview" }));
    const panel = within(await screen.findByRole("region", { name: "Preview" }));
    expect(panel.getByText("Reached at wiki.example.com")).toBeTruthy();
    expect(panel.getByText("Gateways that would serve it: gw-eu-1")).toBeTruthy();
    expect(panel.getByRole("alert").textContent).toBe("port 25432 in use on gw-eu-1");
    expect(previews.map((p) => [p.orgId, p.route?.name, p.updateMask])).toEqual([["org_1", "bad", undefined]]);
    expect(creates).toEqual([]);
  });

  it("previews a change of a route with its mask and etag", async () => {
    const { previews } = page("/routes/rte_1/edit");
    fireEvent.change(await screen.findByLabelText("Public port"), { target: { value: "25433" } });
    fireEvent.click(screen.getByRole("button", { name: "Preview" }));
    const panel = within(await screen.findByRole("region", { name: "Preview" }));
    expect(panel.getByText("Connectors its streams would go to: db-host-1")).toBeTruthy();
    expect(previews[0]!.etag).toBe("7");
    expect(previews[0]!.updateMask?.paths).toContain("tcp.port");
    expect(previews[0]!.route?.spec).toMatchObject({ case: "tcp", value: { port: 25433 } });
  });
});
