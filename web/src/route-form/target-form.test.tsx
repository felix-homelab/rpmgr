// SPDX-License-Identifier: Apache-2.0

import { create, equals } from "@bufbuild/protobuf";
import { cleanup, fireEvent, screen, waitFor, within } from "@testing-library/react";
import { afterEach, describe, expect, it } from "vitest";
import { ConnectorService } from "@/gen/rpmgr/v1/connector_pb";
import { GatewayService } from "@/gen/rpmgr/v1/gateway_pb";
import {
  ProxyProtocol, RouteService, RouteState, RouteTargetSchema, UpstreamProtocol,
  type CreateRouteTargetRequest, type DeleteRouteTargetRequest, type UpdateRouteTargetRequest,
} from "@/gen/rpmgr/v1/route_pb";
import { ApplyState, StatusService } from "@/gen/rpmgr/v1/status_pb";
import { Theme, UserService } from "@/gen/rpmgr/v1/user_pb";
import { targetMask } from "@/route-form/target-form";
import { auth, show } from "@/testing/api";

afterEach(cleanup);

const target = create(RouteTargetSchema, {
  id: "tgt_1", connectorId: "con_db", enabled: true, weight: 100, priority: 2, etag: "3", upstreamProtocol: UpstreamProtocol.HTTP,
  address: { case: "hostPort", value: { host: "10.0.0.5", port: 8080 } },
});
const applied = { revision: { dbEpoch: "e", seq: 11n }, applyStatus: { state: ApplyState.APPLIED, agentsTotal: 1, agentsApplied: 1 } };

// detail renders the detail of a route of type case with the target above.
function detail(spec: { case: "http" | "tcp"; value: object }) {
  const creates: CreateRouteTargetRequest[] = [];
  const updates: UpdateRouteTargetRequest[] = [];
  const deletes: DeleteRouteTargetRequest[] = [];
  const route = { id: "rte_1", name: "app", gatewayGroupId: "ggr_eu", enabled: true, etag: "7", spec, targets: [target],
    status: { state: RouteState.READY, targetsTotal: 1, targetsReady: 1 } };
  show("/routes/rte_1", auth({ getSession: () => ({ userId: "usr_ada", memberships: [{ orgId: "org_1", role: "owner" }] }) }), (router) => {
    router.service(UserService, { getMe: () => ({ user: { id: "usr_ada", theme: Theme.SYSTEM } }) });
    router.service(GatewayService, { listGatewayGroups: () => ({}), listGateways: () => ({}) });
    router.service(ConnectorService, {
      listConnectors: () => ({ connectors: [{ id: "con_db", name: "db-host-1" }, { id: "con_app", name: "app-host" }] }),
      getConnectorStatus: () => ({}),
    });
    router.service(StatusService, { async *watchApplyStatus() {} });
    router.service(RouteService, {
      getRoute: () => ({ route }),
      createRouteTarget: (req) => (creates.push(req), { target: req.target, ...applied }),
      updateRouteTarget: (req) => (updates.push(req), { target: req.target, ...applied }),
      deleteRouteTarget: (req) => (deletes.push(req), applied),
    });
  });
  return { creates, updates, deletes };
}

async function form(name: string) {
  return within(await screen.findByRole("form", { name }));
}

describe("targets", () => {
  it("adds a target to a TCP route, with a PROXY header", async () => {
    const { creates } = detail({ case: "tcp", value: { port: 25432 } });
    fireEvent.click(await screen.findByRole("button", { name: "Add a target" }));
    const f = await form("New target");
    await f.findByRole("option", { name: "app-host" });
    fireEvent.click(f.getByRole("button", { name: "Add the target" }));
    expect(await f.findByText("Choose the connector that reaches the target.")).toBeTruthy();
    expect(creates).toEqual([]);
    fireEvent.change(f.getByLabelText("Connector"), { target: { value: "con_app" } });
    fireEvent.change(f.getByLabelText("Host"), { target: { value: " 10.0.0.6 " } });
    fireEvent.change(f.getByLabelText("Port"), { target: { value: "5432" } });
    fireEvent.change(f.getByLabelText("PROXY protocol"), { target: { value: String(ProxyProtocol.V2) } });
    fireEvent.click(f.getByRole("button", { name: "Add the target" }));
    expect(await screen.findByText("Revision 11: applied by all 1 agents.")).toBeTruthy();
    const t = creates[0]!.target!;
    expect([creates[0]!.routeId, t.connectorId, t.address, t.upstreamProtocol, t.proxyProtocol, t.weight, t.enabled])
      .toEqual(["rte_1", "con_app", { case: "hostPort", value: expect.objectContaining({ host: "10.0.0.6", port: 5432 }) }, UpstreamProtocol.TCP, ProxyProtocol.V2, 100, true]);
    expect(creates[0]!.requestId).toMatch(/^[0-9a-f-]{36}$/);
  });

  it("sends a target back unchanged when nothing was edited", async () => {
    const { updates } = detail({ case: "http", value: { hostnames: ["app.example.com"] } });
    fireEvent.click(await screen.findByRole("button", { name: "Edit…" }));
    const f = await form("Edit target");
    expect((f.getByLabelText("Connector") as HTMLSelectElement).disabled).toBe(true);
    fireEvent.click(f.getByRole("button", { name: "Save" }));
    await waitFor(() => expect(updates).toHaveLength(1));
    expect(equals(RouteTargetSchema, updates[0]!.target!, target)).toBe(true);
    expect([updates[0]!.updateMask?.paths, updates[0]!.etag]).toEqual([targetMask, "3"]);
  });

  it("verifies an HTTPS upstream, and moves a target to a socket", async () => {
    const { updates } = detail({ case: "http", value: { hostnames: ["app.example.com"] } });
    fireEvent.click(await screen.findByRole("button", { name: "Edit…" }));
    const f = await form("Edit target");
    expect(f.queryByLabelText(/TLS server name/)).toBeNull();
    fireEvent.change(f.getByLabelText("Protocol to the target"), { target: { value: String(UpstreamProtocol.HTTPS) } });
    fireEvent.change(await f.findByLabelText(/TLS server name/), { target: { value: "app.internal" } });
    fireEvent.change(f.getByLabelText("Address"), { target: { value: "unixPath" } });
    fireEvent.change(await f.findByLabelText("Socket path"), { target: { value: "/run/app.sock" } });
    fireEvent.click(f.getByRole("button", { name: "Save" }));
    await waitFor(() => expect(updates).toHaveLength(1));
    const t = updates[0]!.target!;
    expect([t.connectorId, t.upstreamProtocol, t.tls?.serverName, t.address]).toEqual(["con_db", UpstreamProtocol.HTTPS, "app.internal", { case: "unixPath", value: "/run/app.sock" }]);
  });

  it("removes a target after a confirmation that names it", async () => {
    const { deletes } = detail({ case: "tcp", value: { port: 25432 } });
    fireEvent.click(await screen.findByRole("button", { name: "Remove…" }));
    expect(screen.getByText("Remove the target 10.0.0.5:8080?")).toBeTruthy();
    fireEvent.click(screen.getByRole("button", { name: "Remove it" }));
    expect(await screen.findByText("Revision 11: applied by all 1 agents.")).toBeTruthy();
    expect(deletes.map((d) => [d.routeTargetId, d.etag])).toEqual([["tgt_1", "3"]]);
  });
});
