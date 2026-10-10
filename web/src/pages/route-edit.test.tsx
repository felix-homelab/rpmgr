// SPDX-License-Identifier: Apache-2.0

import { create, equals } from "@bufbuild/protobuf";
import { timestampFromDate } from "@bufbuild/protobuf/wkt";
import { Code, ConnectError } from "@connectrpc/connect";
import { FieldDescriptorProto_Type } from "@bufbuild/protobuf/wkt";
import { cleanup, fireEvent, screen, waitFor } from "@testing-library/react";
import { afterEach, describe, expect, it } from "vitest";
import { ViolationsSchema } from "@/gen/buf/validate/validate_pb";
import { ConnectorService, DataTransport } from "@/gen/rpmgr/v1/connector_pb";
import { GatewayService } from "@/gen/rpmgr/v1/gateway_pb";
import { Port80Mode, RouteSchema, RouteService, RouteState, TLSMode, type Route, type UpdateRouteRequest } from "@/gen/rpmgr/v1/route_pb";
import { ApplyState, StatusService } from "@/gen/rpmgr/v1/status_pb";
import { Theme, UserService } from "@/gen/rpmgr/v1/user_pb";
import { auth, show } from "@/testing/api";

afterEach(cleanup);

// Routes of every type with every field set, output-only ones included, which no save may lose
// (docs/09-web-ui.md, U1).
const common = {
  id: "rte_1", name: "wiki", gatewayGroupId: "ggr_eu", enabled: true, labels: { team: "ops", env: "prod" }, description: "the wiki",
  policyIds: ["pol_1", "pol_2"], transport: DataTransport.QUIC, etag: "7",
  createTime: timestampFromDate(new Date("2026-10-01T00:00:00Z")), updateTime: timestampFromDate(new Date("2026-10-02T00:00:00Z")),
  targets: [{ id: "tgt_1", connectorId: "con_1", weight: 100, enabled: true, address: { case: "hostPort" as const, value: { host: "10.0.0.5", port: 80 } } }],
  status: { state: RouteState.READY, targetsTotal: 1, targetsReady: 1 },
};
const routes: Record<string, Route> = {
  http: create(RouteSchema, { ...common, spec: { case: "http", value: {
    hostnames: ["wiki.example.com", "w.example.com"], pathPrefix: "/docs", tlsMode: TLSMode.TLS_MODE_CERTIFICATE, certificateId: "crt_1",
    port80: Port80Mode.SERVE, hstsMaxAgeSeconds: 3600, hostHeader: "internal", requestHeadersSet: { "X-A": "1" },
    responseHeadersSet: { "X-B": "a: b" }, websocket: false, maxBodyBytes: 1024n } } }),
  tcp: create(RouteSchema, { ...common, spec: { case: "tcp", value: { port: 25432, idleTimeoutSeconds: 600 } } }),
  udp: create(RouteSchema, { ...common, spec: { case: "udp", value: { port: 53, flowIdleTimeoutSeconds: 30 } } }),
  tlsPassthrough: create(RouteSchema, { ...common, spec: { case: "tlsPassthrough", value: { hostnames: ["db.example.com"] } } }),
};

// edit renders the edit page of route; UpdateRoute answers with answer.
function edit(route: Route, answer: (req: UpdateRouteRequest) => object = (req) => ({ route: req.route, revision: { dbEpoch: "e", seq: 9n }, applyStatus: { state: ApplyState.APPLIED, agentsTotal: 1, agentsApplied: 1 } })) {
  const updates: UpdateRouteRequest[] = [];
  show("/routes/rte_1/edit", auth({ getSession: () => ({ userId: "usr_ada", memberships: [{ orgId: "org_1", role: "owner" }] }) }), (router) => {
    router.service(UserService, { getMe: () => ({ user: { id: "usr_ada", theme: Theme.SYSTEM } }) });
    router.service(GatewayService, { listGateways: () => ({}) });
    router.service(ConnectorService, { listConnectors: () => ({}) });
    router.service(StatusService, { async *watchApplyStatus() {} });
    router.service(RouteService, { getRoute: () => ({ route }), updateRoute: (req) => (updates.push(req), answer(req)) });
  });
  return updates;
}

const save = () => fireEvent.click(screen.getByRole("button", { name: "Save" }));

describe("RouteEdit", () => {
  it.each(Object.entries(routes))("sends a %s route back unchanged when nothing was edited", async (_, route) => {
    const updates = edit(route);
    await screen.findByLabelText("Name");
    save();
    expect(await screen.findByText("Revision 9: applied by all 1 agents.")).toBeTruthy();
    expect(updates).toHaveLength(1);
    expect(equals(RouteSchema, updates[0]!.route!, route)).toBe(true);
    expect(updates[0]!.etag).toBe("7");
    expect(updates[0]!.updateMask?.paths.slice(0, 4)).toEqual(["name", "description", "labels", "transport"]);
  });

  it("changes only the fields edited", async () => {
    const updates = edit(routes.http!);
    fireEvent.change(await screen.findByLabelText("Name"), { target: { value: "docs" } });
    fireEvent.change(screen.getByLabelText("Hostnames"), { target: { value: "docs.example.com\n\n  d.example.com  " } });
    fireEvent.change(screen.getByLabelText("Labels"), { target: { value: "team=web" } });
    fireEvent.change(screen.getByLabelText("WebSocket"), { target: { value: "" } });
    fireEvent.change(screen.getByLabelText("Request headers to set"), { target: { value: "X-A: 2\nX-C: x: y" } });
    save();
    await waitFor(() => expect(updates).toHaveLength(1));
    const want = create(RouteSchema, routes.http!);
    want.name = "docs";
    want.labels = { team: "web" };
    if (want.spec.case === "http") {
      want.spec.value.hostnames = ["docs.example.com", "d.example.com"];
      want.spec.value.websocket = undefined;
      want.spec.value.requestHeadersSet = { "X-A": "2", "X-C": "x: y" };
    }
    expect(equals(RouteSchema, updates[0]!.route!, want)).toBe(true);
    expect(updates[0]!.updateMask?.paths).toContain("http.websocket");
  });

  it("checks the API's rules before sending", async () => {
    const updates = edit(routes.tcp!);
    fireEvent.change(await screen.findByLabelText("Name"), { target: { value: "Bad_Name" } });
    save();
    expect((await screen.findByRole("alert")).textContent).toMatch(/does not match regex pattern/);
    fireEvent.change(screen.getByLabelText("Name"), { target: { value: "ok" } });
    fireEvent.change(screen.getByLabelText("Public port"), { target: { value: "8o" } });
    save();
    expect(await screen.findByText("Enter a whole number.")).toBeTruthy();
    await waitFor(() => expect(screen.queryByText(/does not match regex pattern/)).toBeNull());
    expect(updates).toEqual([]);
  });

  it("shows the server's violations on their fields", async () => {
    edit(routes.http!, () => {
      const el = (name: string, n: number, t: FieldDescriptorProto_Type) => ({ fieldName: name, fieldNumber: n, fieldType: t });
      const v = create(ViolationsSchema, { violations: [
        { field: { elements: [el("route", 1, FieldDescriptorProto_Type.MESSAGE), el("http", 10, FieldDescriptorProto_Type.MESSAGE), { ...el("hostnames", 1, FieldDescriptorProto_Type.STRING), subscript: { case: "index", value: 0n } }] },
          message: "the domain is not verified" },
      ] });
      throw new ConnectError("invalid", Code.InvalidArgument, undefined, [{ desc: ViolationsSchema, value: v }]);
    });
    await screen.findByLabelText("Name");
    save();
    const hostnames = screen.getByLabelText("Hostnames");
    await waitFor(() => expect(hostnames.getAttribute("aria-invalid")).toBe("true"));
    expect(screen.getByText("the domain is not verified")).toBeTruthy();
  });
});
