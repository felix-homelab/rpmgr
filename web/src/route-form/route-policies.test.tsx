// SPDX-License-Identifier: Apache-2.0

import { create, equals } from "@bufbuild/protobuf";
import { cleanup, fireEvent, screen, waitFor, within } from "@testing-library/react";
import { afterEach, describe, expect, it } from "vitest";
import { ConnectorService } from "@/gen/rpmgr/v1/connector_pb";
import { GatewayService } from "@/gen/rpmgr/v1/gateway_pb";
import { PolicyService } from "@/gen/rpmgr/v1/policy_pb";
import { RouteSchema, RouteService, RouteState, type UpdateRouteRequest } from "@/gen/rpmgr/v1/route_pb";
import { ApplyState, StatusService } from "@/gen/rpmgr/v1/status_pb";
import { Theme, UserService } from "@/gen/rpmgr/v1/user_pb";
import { auth, show } from "@/testing/api";

afterEach(cleanup);

const route = create(RouteSchema, { id: "rte_1", name: "wiki", gatewayGroupId: "ggr_eu", enabled: true, etag: "7", policyIds: ["pol_a", "pol_b"],
  spec: { case: "http", value: { hostnames: ["wiki.example.com"] } }, status: { state: RouteState.READY } });

function page() {
  const updates: UpdateRouteRequest[] = [];
  show("/routes/rte_1", auth({ getSession: () => ({ userId: "usr_ada", memberships: [{ orgId: "org_1", role: "owner" }] }) }), (router) => {
    router.service(UserService, { getMe: () => ({ user: { id: "usr_ada", theme: Theme.SYSTEM } }) });
    router.service(GatewayService, { listGatewayGroups: () => ({}), listGateways: () => ({}) });
    router.service(ConnectorService, { listConnectors: () => ({}), getConnectorStatus: () => ({}) });
    router.service(StatusService, { async *watchApplyStatus() {} });
    router.service(PolicyService, { listAccessPolicies: () => ({ accessPolicies: [{ id: "pol_a", name: "office" }, { id: "pol_b", name: "admins" }, { id: "pol_c", name: "lab" }] }) });
    router.service(RouteService, {
      getRoute: () => ({ route }),
      updateRoute: (req) => (updates.push(req), { route: req.route, revision: { dbEpoch: "e", seq: 41n }, applyStatus: { state: ApplyState.APPLIED, agentsTotal: 1, agentsApplied: 1 } }),
    });
  });
  return updates;
}

describe("RoutePolicies", () => {
  it("attaches, detaches and reorders the route's policies, then saves them as one change", async () => {
    const updates = page();
    const s = within(await screen.findByRole("region", { name: "Access policies" }));
    await waitFor(() => expect(s.getAllByRole("listitem").map((li) => li.querySelector("span")?.textContent)).toEqual(["1. office", "2. admins"]));
    expect(s.getByRole("button", { name: "Save" })).toHaveProperty("disabled", true);
    fireEvent.change(s.getByLabelText("Add a policy"), { target: { value: "pol_c" } });
    fireEvent.click(s.getByRole("button", { name: "Attach" }));
    fireEvent.click(within(s.getAllByRole("listitem")[0]!).getByRole("button", { name: "Detach" }));
    fireEvent.click(within(s.getAllByRole("listitem")[1]!).getByRole("button", { name: "Up" }));
    expect(s.getAllByRole("listitem").map((li) => li.querySelector("span")?.textContent)).toEqual(["1. lab", "2. admins"]);
    fireEvent.click(s.getByRole("button", { name: "Save" }));
    expect(await screen.findByText("Revision 41: applied by all 1 agents.")).toBeTruthy();
    const want = create(RouteSchema, { ...route, policyIds: ["pol_c", "pol_b"] });
    expect(equals(RouteSchema, updates[0]!.route!, want)).toBe(true);
    expect([updates[0]!.updateMask?.paths, updates[0]!.etag]).toEqual([["policy_ids"], "7"]);
  });
});
