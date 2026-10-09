// SPDX-License-Identifier: Apache-2.0

import { create } from "@bufbuild/protobuf";
import { timestampFromDate } from "@bufbuild/protobuf/wkt";
import { Code } from "@connectrpc/connect";
import { cleanup, fireEvent, render, screen, waitFor } from "@testing-library/react";
import { I18nextProvider } from "react-i18next";
import { afterEach, describe, expect, it } from "vitest";
import { ApplyStatusView } from "@/components/apply-status";
import { RevisionSchema } from "@/gen/rpmgr/v1/common_pb";
import { ConnectorService } from "@/gen/rpmgr/v1/connector_pb";
import { GatewayService } from "@/gen/rpmgr/v1/gateway_pb";
import { RouteService, RouteState, type UpdateRouteRequest } from "@/gen/rpmgr/v1/route_pb";
import { ApplyState, ApplyStatusSchema, StatusService } from "@/gen/rpmgr/v1/status_pb";
import { Theme, UserService } from "@/gen/rpmgr/v1/user_pb";
import { i18n } from "@/i18n";
import { apiError, auth, show } from "@/testing/api";

afterEach(cleanup);

const names = new Map([["gtw_1", "gw-eu-1"], ["con_1", "db-host-1"], ["con_2", "app-host"]]);
const name = (id: string) => names.get(id) ?? id;

function view(status: Parameters<typeof create<typeof ApplyStatusSchema>>[1]) {
  render(
    <I18nextProvider i18n={i18n}>
      <ApplyStatusView status={create(ApplyStatusSchema, status)} revision={create(RevisionSchema, { dbEpoch: "e", seq: 42n })} name={name} />
    </I18nextProvider>,
  );
  return screen.getByRole("status");
}

describe("ApplyStatusView", () => {
  it.each([
    [{ state: ApplyState.PENDING, agentsTotal: 3, agentsApplied: 1 }, "Revision 42: applied by 1 of 3 agents so far."],
    [{ state: ApplyState.APPLIED, agentsTotal: 3, agentsApplied: 3 }, "Revision 42: applied by all 3 agents."],
    [{ state: ApplyState.REJECTED, agentsTotal: 3 }, "Revision 42: rejected."],
    [{ state: ApplyState.APPLY_TIMEOUT, agentsTotal: 3 }, "Revision 42: an agent did not answer in time."],
  ])("states %o", (status, want) => {
    expect(view(status).querySelector("p")?.textContent).toContain(want);
  });

  it("lists the agents that have not applied it, with their reasons, and the offline ones", () => {
    const s = view({
      state: ApplyState.REJECTED, agentsTotal: 2,
      agents: [{ agentId: "gtw_1", state: ApplyState.REJECTED, errors: [{ message: "port 25432 in use" }] }, { agentId: "con_1", state: ApplyState.PENDING }],
      offline: [{ agentId: "con_2", lastSeenTime: timestampFromDate(new Date("2026-10-01T12:00:00Z")) }, { agentId: "con_9" }],
    });
    expect(s.getAttribute("aria-live")).toBe("polite");
    expect([...s.querySelectorAll("li")].map((li) => li.textContent)).toEqual(["gw-eu-1: rejected — port 25432 in use", "db-host-1: pending"]);
    expect(s.textContent).toContain("Offline, they get it when they connect: app-host (Oct 1, 2026");
    expect(s.textContent).toContain(", con_9");
  });
});

describe("the route's switch", () => {
  const route = {
    id: "rte_2", name: "postgres", gatewayGroupId: "ggr_eu", enabled: true, etag: "7",
    spec: { case: "tcp" as const, value: { port: 25432 } }, status: { state: RouteState.READY },
  };

  function detail(update: (req: UpdateRouteRequest) => object) {
    const updates: UpdateRouteRequest[] = [];
    show("/routes/rte_2", auth({ getSession: () => ({ userId: "usr_ada", memberships: [{ orgId: "org_1", role: "owner" }] }) }), (router) => {
      router.service(UserService, { getMe: () => ({ user: { id: "usr_ada", theme: Theme.SYSTEM } }) });
      router.service(GatewayService, { listGatewayGroups: () => ({}), listGateways: () => ({ gateways: [{ id: "gtw_1", name: "gw-eu-1" }] }) });
      router.service(ConnectorService, { listConnectors: () => ({}), getConnectorStatus: () => ({}) });
      router.service(RouteService, { getRoute: () => ({ route }), updateRoute: (req) => (updates.push(req), update(req)) });
      router.service(StatusService, {
        async *watchApplyStatus(req) {
          expect([req.orgId, req.revision?.seq]).toEqual(["org_1", 43n]);
          yield { applyStatus: { state: ApplyState.PENDING, agentsTotal: 2, agentsApplied: 1, agents: [{ agentId: "gtw_1", state: ApplyState.PENDING }] } };
          yield { applyStatus: { state: ApplyState.APPLIED, agentsTotal: 2, agentsApplied: 2 } };
        },
      });
    });
    return updates;
  }

  it("turns the route off and follows the change to the agents", async () => {
    const updates = detail(() => ({ route: { ...route, enabled: false }, revision: { dbEpoch: "e", seq: 43n }, applyStatus: { state: ApplyState.PENDING, agentsTotal: 2 } }));
    const toggle = await screen.findByRole("switch", { name: "Enabled: on" });
    expect(toggle.getAttribute("aria-checked")).toBe("true");
    fireEvent.click(toggle);
    await waitFor(() => expect(screen.getByRole("status").textContent).toContain("Revision 43: applied by all 2 agents."));
    expect(updates.map((u) => [u.route?.id, u.route?.enabled, u.updateMask?.paths, u.etag])).toEqual([["rte_2", false, ["enabled"], "7"]]);
  });

  it("says when the route changed meanwhile", async () => {
    detail(() => { throw apiError(Code.FailedPrecondition, "ETAG_MISMATCH"); });
    fireEvent.click(await screen.findByRole("switch", { name: "Enabled: on" }));
    expect((await screen.findByRole("alert")).textContent).toContain("The route changed since this page loaded it.");
  });
});
