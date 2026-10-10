// SPDX-License-Identifier: Apache-2.0

import { Code, ConnectError } from "@connectrpc/connect";
import { cleanup, fireEvent, screen, waitFor, within } from "@testing-library/react";
import { afterEach, describe, expect, it } from "vitest";
import { AgentRole, EnrollmentService, type CreateGatewayEnrollmentTokenRequest, type GetInstallCommandRequest } from "@/gen/rpmgr/v1/enrollment_pb";
import {
  GatewayService, type CreateGatewayRequest, type DecommissionGatewayRequest, type UpdateGatewayRequest,
} from "@/gen/rpmgr/v1/gateway_pb";
import { ConnectorService } from "@/gen/rpmgr/v1/connector_pb";
import { ApplyState, StatusService } from "@/gen/rpmgr/v1/status_pb";
import { Theme, UserService } from "@/gen/rpmgr/v1/user_pb";
import { apiError, auth, show } from "@/testing/api";

afterEach(cleanup);

const applied = { revision: { dbEpoch: "e", seq: 21n }, applyStatus: { state: ApplyState.APPLIED, agentsTotal: 1, agentsApplied: 1 } };
const token = "rpmgr_enr_fakefakefake0123456789_9x8y7z"; // not token-shaped, so the secrets scan passes it

function page(full = false) {
  const creates: CreateGatewayRequest[] = [];
  const updates: UpdateGatewayRequest[] = [];
  const decommissions: DecommissionGatewayRequest[] = [];
  const tokens: CreateGatewayEnrollmentTokenRequest[] = [];
  const commands: GetInstallCommandRequest[] = [];
  let steppedUp = false;
  show("/gateways/ggr_eu", auth({
    getSession: () => ({ userId: "usr_ada", memberships: [{ orgId: "org_1", role: "owner" }] }),
    stepUp: () => ((steppedUp = true), {}),
  }), (router) => {
    router.service(UserService, { getMe: () => ({ user: { id: "usr_ada", theme: Theme.SYSTEM } }) });
    router.service(ConnectorService, { listConnectors: () => ({}) });
    router.service(StatusService, { async *watchApplyStatus() {} });
    router.service(GatewayService, {
      listGatewayGroups: () => ({ gatewayGroups: [{ id: "ggr_eu", name: "eu" }] }),
      listGateways: () => ({ gateways: [
        { id: "gtw_1", gatewayGroupId: "ggr_eu", name: "gw-eu-1", slot: 1, enabled: true, etag: "5", tunnelEndpoints: ["198.51.100.1:443"], status: { enrolled: true, connected: true } },
        { id: "gtw_2", gatewayGroupId: "ggr_eu", name: "gw-eu-2", slot: 2, enabled: false, etag: "6", status: { enrolled: false } },
      ] }),
      createGateway: (req) => {
        creates.push(req);
        if (full) {
          throw new ConnectError("apisvc: a gateway group has at most 4 gateways", Code.FailedPrecondition);
        }
        return { gateway: req.gateway, ...applied };
      },
      updateGateway: (req) => (updates.push(req), { gateway: req.gateway, ...applied }),
      decommissionGateway: (req) => (decommissions.push(req), applied),
    });
    router.service(EnrollmentService, {
      createGatewayEnrollmentToken: (req) => {
        tokens.push(req);
        if (!steppedUp) {
          throw apiError(Code.Unauthenticated, "STEP_UP_REQUIRED");
        }
        return { token };
      },
      getInstallCommand: (req) => (commands.push(req), { command: "curl -fsSL https://panel.example.com/install.sh | sudo sh -s -- --role gateway --ca-pin sha256:x" }),
    });
  });
  return { creates, updates, decommissions, tokens, commands };
}

async function row(name: string) {
  const members = within(await screen.findByRole("region", { name: "Gateways" }));
  await members.findByText(name);
  return within(members.getByText(name).closest("tr")!);
}

describe("gateway actions", () => {
  it("adds a gateway with its own tunnel endpoints", async () => {
    const { creates } = page();
    fireEvent.click(await screen.findByRole("button", { name: "Add a gateway" }));
    const form = within(await screen.findByRole("form", { name: "New gateway" }));
    fireEvent.change(form.getByLabelText("Name"), { target: { value: "gw-eu-3" } });
    fireEvent.change(form.getByLabelText("Tunnel endpoints"), { target: { value: "198.51.100.3:443" } });
    fireEvent.click(form.getByRole("button", { name: "Add the gateway" }));
    expect(await screen.findByText("Revision 21: applied by all 1 agents.")).toBeTruthy();
    const g = creates[0]!.gateway!;
    expect([creates[0]!.orgId, g.gatewayGroupId, g.name, g.tunnelEndpoints, g.enabled]).toEqual(["org_1", "ggr_eu", "gw-eu-3", ["198.51.100.3:443"], true]);
  });

  it("says why a fifth gateway is refused", async () => {
    page(true);
    fireEvent.click(await screen.findByRole("button", { name: "Add a gateway" }));
    const form = within(await screen.findByRole("form", { name: "New gateway" }));
    fireEvent.change(form.getByLabelText("Name"), { target: { value: "gw-eu-5" } });
    fireEvent.click(form.getByRole("button", { name: "Add the gateway" }));
    expect((await form.findByRole("alert")).textContent).toBe("apisvc: a gateway group has at most 4 gateways");
  });

  it("drains a gateway and resumes a drained one", async () => {
    const { updates } = page();
    fireEvent.click((await row("gw-eu-1")).getByRole("button", { name: "Drain" }));
    await waitFor(() => expect(updates).toHaveLength(1));
    fireEvent.click((await row("gw-eu-2")).getByRole("button", { name: "Resume" }));
    await waitFor(() => expect(updates).toHaveLength(2));
    expect(updates.map((u) => [u.gateway?.id, u.gateway?.enabled, u.gateway?.tunnelEndpoints, u.updateMask?.paths, u.etag])).toEqual([
      ["gtw_1", false, ["198.51.100.1:443"], ["enabled"], "5"],
      ["gtw_2", true, [], ["enabled"], "6"],
    ]);
  });

  it("decommissions a gateway after a confirmation that names it", async () => {
    const { decommissions } = page();
    const r = await row("gw-eu-1");
    fireEvent.click(r.getByRole("button", { name: "Decommission…" }));
    expect(r.getByRole("alert").textContent).toContain("Decommissioning gw-eu-1 revokes its identity");
    fireEvent.click(r.getByRole("button", { name: "Decommission gw-eu-1" }));
    await waitFor(() => expect(decommissions.map((d) => [d.gatewayId, d.etag])).toEqual([["gtw_1", "5"]]));
  });

  it("mints a gateway's enrollment token after a step-up and keeps it out of the command", async () => {
    const { tokens, commands } = page();
    const r = await row("gw-eu-2");
    expect((await row("gw-eu-1")).queryByRole("button", { name: "Enrollment token…" })).toBeNull(); // enrolled already
    fireEvent.click(r.getByRole("button", { name: "Enrollment token…" }));
    fireEvent.click(await r.findByRole("button", { name: "Create the token" }));
    const stepUp = within(await screen.findByRole("dialog", { name: "Confirm it is you" }));
    fireEvent.change(stepUp.getByLabelText("Password"), { target: { value: "pw" } });
    fireEvent.click(stepUp.getByRole("button", { name: "Confirm" }));
    expect((await r.findByLabelText("Install command")).textContent).not.toContain("rpmgr_enr_");
    expect(r.getByLabelText("Enrollment token").textContent).toBe("rpmgr_enr_••••••••••••_9x8y7z");
    expect(tokens.map((x) => [x.gatewayId, x.ttl?.seconds])).toEqual([["gtw_2", 3600n], ["gtw_2", 3600n]]);
    expect(tokens[1]!.requestId).toBe(tokens[0]!.requestId);
    expect(commands.map((c) => c.role)).toEqual([AgentRole.GATEWAY]);
  });
});
