// SPDX-License-Identifier: Apache-2.0

import { cleanup, fireEvent, screen, waitFor, within } from "@testing-library/react";
import { afterEach, describe, expect, it, vi } from "vitest";
import { Code } from "@connectrpc/connect";
import { ConnectorService } from "@/gen/rpmgr/v1/connector_pb";
import { AgentRole, EnrollmentService, type CreateEnrollmentTokenRequest, type GetInstallCommandRequest } from "@/gen/rpmgr/v1/enrollment_pb";
import { GatewayService } from "@/gen/rpmgr/v1/gateway_pb";
import { RouteService } from "@/gen/rpmgr/v1/route_pb";
import { StatusService } from "@/gen/rpmgr/v1/status_pb";
import { Theme, UserService } from "@/gen/rpmgr/v1/user_pb";
import { mask } from "@/pages/enroll";
import { apiError, auth, show } from "@/testing/api";

afterEach(cleanup);

const token = "rpmgr_enr_fakefakefake0123456789_8f2k1a"; // not token-shaped, so the secrets scan passes it
const command = "curl -fsSL https://panel.example.com/install.sh | sudo sh -s -- \\\n  --controller https://panel.example.com --ca-pin sha256:3q2+7w== \\\n  --allow-target 10.0.0.5:5432";

function page() {
  const creates: CreateEnrollmentTokenRequest[] = [];
  const commands: GetInstallCommandRequest[] = [];
  const revoked: string[] = [];
  let steppedUp = false;
  let release: () => void = () => {};
  const connected = new Promise<void>((r) => (release = r));
  const view = show("/connectors", auth({
    getSession: () => ({ userId: "usr_ada", memberships: [{ orgId: "org_1", role: "owner" }] }),
    stepUp: () => ((steppedUp = true), {}),
  }), (router) => {
    router.service(UserService, { getMe: () => ({ user: { id: "usr_ada", theme: Theme.SYSTEM } }) });
    router.service(GatewayService, { listGatewayGroups: () => ({ gatewayGroups: [{ id: "ggr_eu", name: "eu" }] }), listGateways: () => ({}) });
    router.service(RouteService, { listRoutes: () => ({}) });
    router.service(ConnectorService, {
      listConnectors: () => ({ connectors: [{ id: "con_old", name: "old" }] }),
      getConnector: () => ({ connector: { id: "con_new", name: "db-host-1" } }),
      getConnectorStatus: () => ({}),
    });
    router.service(StatusService, {
      async *watchEvents(req) {
        expect(req.orgId).toBe("org_1");
        yield { statusChanged: ["con_old"] }; // a known connector's session changed
        await connected;
        yield { changedResources: ["con_new"] };
        yield { statusChanged: ["con_new"] };
      },
    });
    router.service(EnrollmentService, {
      createEnrollmentToken: (req) => {
        creates.push(req);
        if (!steppedUp) {
          throw apiError(Code.Unauthenticated, "STEP_UP_REQUIRED");
        }
        return { token, enrollmentToken: { id: "enr_1" } };
      },
      getInstallCommand: (req) => (commands.push(req), { command }),
      listEnrollmentTokens: () => ({ enrollmentTokens: [
        { id: "enr_old", maxUses: 1, useCount: 0, labels: { site: "office" } },
        { id: "enr_replace", connectorId: "con_old", maxUses: 1 }, // a re-enrollment token is not listed
      ] }),
      revokeEnrollmentToken: (req) => (revoked.push(req.enrollmentTokenId), {}),
    });
  });
  return { ...view, creates, commands, revoked, release };
}

describe("EnrollDialog", () => {
  it("mints a token after a step-up, keeps it out of the command, and opens the new connector", async () => {
    const write = vi.fn(() => Promise.resolve());
    Object.assign(navigator, { clipboard: { writeText: write } });
    const { creates, commands, history, release } = page();
    fireEvent.click(await screen.findByRole("button", { name: "Enroll a connector" }));
    const dialog = within(await screen.findByRole("dialog", { name: "Enroll a connector" }));
    fireEvent.change(dialog.getByLabelText("Labels"), { target: { value: "site=office" } });
    fireEvent.change(dialog.getByLabelText(/^Targets the connector may reach/), { target: { value: "10.0.0.5:5432\n" } });
    fireEvent.click(dialog.getByRole("button", { name: "Create the token" }));
    const stepUp = within(await screen.findByRole("dialog", { name: "Confirm it is you" }));
    fireEvent.change(stepUp.getByLabelText("Password"), { target: { value: "pw" } });
    fireEvent.click(stepUp.getByRole("button", { name: "Confirm" }));

    const cmd = await dialog.findByLabelText("Install command");
    expect(cmd.textContent).toBe(command);
    expect(cmd.textContent).not.toContain("rpmgr_enr_");
    const tok = dialog.getByLabelText("Enrollment token");
    expect(tok.textContent).toBe(mask(token));
    expect(tok.textContent).not.toContain("0123456789");
    fireEvent.click(dialog.getByRole("button", { name: "Show" }));
    expect(tok.textContent).toBe(token);
    fireEvent.click(dialog.getAllByRole("button", { name: "Copy" })[1]!);
    expect(write).toHaveBeenCalledWith(token);
    expect(dialog.getByText("The token is never part of the command line, and it expires in 1 hour.")).toBeTruthy();

    expect(creates).toHaveLength(2); // refused for the step-up, then made, as one request
    expect(creates[1]!.requestId).toBe(creates[0]!.requestId);
    const c = creates[1]!;
    expect([c.orgId, c.labels, c.ephemeral, c.maxUses, c.ttl?.seconds]).toEqual(["org_1", { site: "office" }, false, 1, 3600n]);
    expect(commands.map((x) => [x.role, x.allowTargets])).toEqual([[AgentRole.CONNECTOR, ["10.0.0.5:5432"]]]);

    release();
    await waitFor(() => expect(history.location.pathname).toBe("/connectors/con_new"));
  });

  it("allows an ephemeral token several uses", async () => {
    const { creates } = page();
    fireEvent.click(await screen.findByRole("button", { name: "Enroll a connector" }));
    const dialog = within(await screen.findByRole("dialog", { name: "Enroll a connector" }));
    fireEvent.click(dialog.getByLabelText(/^Ephemeral/));
    fireEvent.change(dialog.getByLabelText("Connectors it may enroll"), { target: { value: "0" } });
    fireEvent.change(dialog.getByLabelText("The token is valid for"), { target: { value: "86400" } });
    fireEvent.click(dialog.getByRole("button", { name: "Create the token" }));
    const stepUp = within(await screen.findByRole("dialog", { name: "Confirm it is you" }));
    fireEvent.change(stepUp.getByLabelText("Password"), { target: { value: "pw" } });
    fireEvent.click(stepUp.getByRole("button", { name: "Confirm" }));
    await dialog.findByLabelText("Install command");
    expect([creates[1]!.ephemeral, creates[1]!.maxUses, creates[1]!.ttl?.seconds]).toEqual([true, 0, 86400n]);
  });
});

describe("EnrollmentTokens", () => {
  it("lists the tokens that can enroll and revokes one after a confirmation", async () => {
    const { revoked } = page();
    const section = within(await screen.findByRole("region", { name: "Enrollment tokens" }));
    expect(await section.findByText("used 0 of 1")).toBeTruthy();
    expect(section.getAllByRole("listitem")).toHaveLength(1);
    fireEvent.click(section.getByRole("button", { name: "Revoke…" }));
    fireEvent.click(section.getByRole("button", { name: "Revoke it" }));
    await waitFor(() => expect(revoked).toEqual(["enr_old"]));
  });
});

describe("mask", () => {
  it("keeps the kind and the checksum only", () => {
    expect(mask(token)).toBe("rpmgr_enr_••••••••••••_8f2k1a");
  });
});
