// SPDX-License-Identifier: Apache-2.0

import { create } from "@bufbuild/protobuf";
import { timestampFromDate } from "@bufbuild/protobuf/wkt";
import { Code } from "@connectrpc/connect";
import { cleanup, fireEvent, screen, waitFor, within } from "@testing-library/react";
import { afterEach, describe, expect, it } from "vitest";
import { ConnectorService } from "@/gen/rpmgr/v1/connector_pb";
import { GatewayService } from "@/gen/rpmgr/v1/gateway_pb";
import { OrgService } from "@/gen/rpmgr/v1/org_pb";
import { RouteSchema, RouteService, type UpdateRouteRequest } from "@/gen/rpmgr/v1/route_pb";
import { ApplyState, StatusService } from "@/gen/rpmgr/v1/status_pb";
import { Theme, UserService } from "@/gen/rpmgr/v1/user_pb";
import { changes, onTop } from "@/route-form/conflict";
import { valuesOf } from "@/route-form/fields";
import { apiError, auth, show } from "@/testing/api";

afterEach(cleanup);

const mine = create(RouteSchema, { id: "rte_1", name: "wiki", description: "old", labels: { team: "ops" }, etag: "7",
  spec: { case: "tcp", value: { port: 25432 } } });
const theirs = create(RouteSchema, { ...mine, description: "new", labels: { team: "web" }, etag: "8", updateUserId: "usr_bob",
  updateTime: timestampFromDate(new Date(Date.now() - 2 * 60_000)) });

describe("changes", () => {
  it("lists the fields either side changed", () => {
    const values = { ...valuesOf(mine), name: "docs", labels: "team=dev" };
    expect(changes(mine, values, theirs)).toEqual([
      { key: "name", mine: "docs", theirs: undefined },
      { key: "description", mine: undefined, theirs: "new" },
      { key: "labels", mine: "team=dev", theirs: "team=web" },
    ]);
    expect(onTop(mine, values, theirs)).toEqual({ ...valuesOf(theirs), name: "docs", labels: "team=dev" });
  });
});

describe("a save that meets a newer version", () => {
  function edit() {
    const updates: UpdateRouteRequest[] = [];
    show("/routes/rte_1/edit", auth({ getSession: () => ({ userId: "usr_ada", memberships: [{ orgId: "org_1", role: "owner" }] }) }), (router) => {
      router.service(UserService, { getMe: () => ({ user: { id: "usr_ada", theme: Theme.SYSTEM } }) });
      router.service(GatewayService, { listGateways: () => ({}) });
      router.service(ConnectorService, { listConnectors: () => ({}) });
      router.service(OrgService, { listMembers: () => ({ members: [{ userId: "usr_bob", displayName: "Bob" }] }) });
      router.service(StatusService, { async *watchApplyStatus() {} });
      let saved = mine;
      router.service(RouteService, {
        getRoute: () => ({ route: saved }),
        updateRoute: (req) => {
          updates.push(req);
          if (req.etag !== theirs.etag) {
            saved = theirs; // Bob saved first
            throw apiError(Code.FailedPrecondition, "ETAG_MISMATCH");
          }
          return { route: req.route, revision: { dbEpoch: "e", seq: 9n }, applyStatus: { state: ApplyState.APPLIED, agentsTotal: 1, agentsApplied: 1 } };
        },
      });
    });
    return updates;
  }

  it("names who changed what, and puts the user's changes on the new version", async () => {
    const updates = edit();
    fireEvent.change(await screen.findByLabelText("Name"), { target: { value: "docs" } });
    fireEvent.click(screen.getByRole("button", { name: "Save" }));
    const panel = within(await screen.findByRole("region", { name: "The route changed since you opened it" }));
    await waitFor(() => expect(panel.getByRole("alert").textContent).toBe("Changed by Bob 2 minutes ago. Your changes are not saved yet."));
    expect(panel.getAllByRole("row").slice(1).map((r) => r.textContent)).toEqual(["Namedocs—", "Description—new", "Labels—team=web"]);
    fireEvent.click(panel.getByRole("button", { name: "Put my changes on the new version" }));
    await waitFor(() => expect((screen.getByLabelText("Description") as HTMLTextAreaElement).value).toBe("new"));
    expect((screen.getByLabelText("Name") as HTMLInputElement).value).toBe("docs");
    fireEvent.click(screen.getByRole("button", { name: "Save" }));
    expect(await screen.findByText("Revision 9: applied by all 1 agents.")).toBeTruthy();
    expect(updates.map((u) => [u.etag, u.route?.name, u.route?.description, u.route?.labels])).toEqual([
      ["7", "docs", "old", { team: "ops" }],
      ["8", "docs", "new", { team: "web" }],
    ]);
  });

  it("drops the user's changes", async () => {
    edit();
    fireEvent.change(await screen.findByLabelText("Name"), { target: { value: "docs" } });
    fireEvent.click(screen.getByRole("button", { name: "Save" }));
    fireEvent.click(await screen.findByRole("button", { name: "Drop my changes" }));
    await waitFor(() => expect((screen.getByLabelText("Description") as HTMLTextAreaElement).value).toBe("new"));
    expect((screen.getByLabelText("Name") as HTMLInputElement).value).toBe("wiki");
    expect(screen.queryByRole("region", { name: "The route changed since you opened it" })).toBeNull();
  });
});
