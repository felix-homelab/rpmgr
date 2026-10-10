// SPDX-License-Identifier: Apache-2.0

import { cleanup, fireEvent, screen, waitFor, within } from "@testing-library/react";
import { afterEach, describe, expect, it } from "vitest";
import { ConnectorService } from "@/gen/rpmgr/v1/connector_pb";
import {
  GatewayService, PortProtocol,
  type CreatePortPoolRequest, type DeletePortPoolRequest, type DeletePortQuotaRequest, type SetPortQuotaRequest, type UpdatePortPoolRequest,
} from "@/gen/rpmgr/v1/gateway_pb";
import { Theme, UserService } from "@/gen/rpmgr/v1/user_pb";
import { auth, show } from "@/testing/api";

afterEach(cleanup);

function page() {
  const calls = { create: [] as CreatePortPoolRequest[], update: [] as UpdatePortPoolRequest[], remove: [] as DeletePortPoolRequest[],
    quota: [] as SetPortQuotaRequest[], unquota: [] as DeletePortQuotaRequest[] };
  show("/gateways/ggr_eu", auth({ getSession: () => ({ userId: "usr_ada", memberships: [{ orgId: "org_1", role: "owner" }] }) }), (router) => {
    router.service(UserService, { getMe: () => ({ user: { id: "usr_ada", theme: Theme.SYSTEM } }) });
    router.service(ConnectorService, { listConnectors: () => ({}) });
    router.service(GatewayService, {
      listGatewayGroups: () => ({ gatewayGroups: [{ id: "ggr_eu", name: "eu" }] }),
      listGateways: () => ({}),
      listPortPools: (req) => (expect([req.orgId, req.gatewayGroupId]).toEqual(["org_1", "ggr_eu"]),
        { portPools: [{ id: "pool_1", gatewayGroupId: "ggr_eu", protocol: PortProtocol.TCP, portFrom: 20000, portTo: 20999, etag: "3" }] }),
      listPortQuotas: () => ({ portQuotas: [{ id: "quo_1", gatewayGroupId: "ggr_eu", protocol: PortProtocol.UDP, maxPorts: 10, allocatedPorts: 2 }] }),
      createPortPool: (req) => (calls.create.push(req), { portPool: req.portPool }),
      updatePortPool: (req) => (calls.update.push(req), { portPool: req.portPool }),
      deletePortPool: (req) => (calls.remove.push(req), {}),
      setPortQuota: (req) => (calls.quota.push(req), {}),
      deletePortQuota: (req) => (calls.unquota.push(req), {}),
    });
  });
  return calls;
}

async function section() {
  return within(await screen.findByRole("region", { name: "Port pools" }));
}

describe("PortPools", () => {
  it("adds a pool, refusing a range in the wrong order", async () => {
    const calls = page();
    const s = await section();
    fireEvent.click(await s.findByRole("button", { name: "Add a port pool" }));
    const form = within(s.getByRole("form", { name: "New port pool" }));
    fireEvent.change(form.getByLabelText("Protocol"), { target: { value: String(PortProtocol.UDP) } });
    fireEvent.change(form.getByLabelText("First port"), { target: { value: "30999" } });
    fireEvent.change(form.getByLabelText("Last port"), { target: { value: "30000" } });
    fireEvent.click(form.getByRole("button", { name: "Add the pool" }));
    expect((await form.findByRole("alert")).textContent).toBe("Ports are 1 to 65535, the first no larger than the last.");
    fireEvent.change(form.getByLabelText("First port"), { target: { value: "30000" } });
    fireEvent.change(form.getByLabelText("Last port"), { target: { value: "30999" } });
    fireEvent.click(form.getByRole("button", { name: "Add the pool" }));
    await waitFor(() => expect(calls.create).toHaveLength(1));
    const p = calls.create[0]!;
    expect([p.orgId, p.portPool?.gatewayGroupId, p.portPool?.protocol, p.portPool?.portFrom, p.portPool?.portTo]).toEqual(["org_1", "ggr_eu", PortProtocol.UDP, 30000, 30999]);
  });

  it("changes a pool's range and removes a pool after a confirmation", async () => {
    const calls = page();
    const s = await section();
    fireEvent.click(await s.findByRole("button", { name: "Edit…" }));
    const form = within(s.getByRole("form", { name: "Edit port pool" }));
    fireEvent.change(form.getByLabelText("Last port"), { target: { value: "21999" } });
    fireEvent.click(form.getByRole("button", { name: "Save" }));
    await waitFor(() => expect(calls.update).toHaveLength(1));
    expect([calls.update[0]!.portPool?.id, calls.update[0]!.portPool?.portTo, calls.update[0]!.updateMask?.paths, calls.update[0]!.etag])
      .toEqual(["pool_1", 21999, ["port_from", "port_to"], "3"]);
    fireEvent.click(await s.findByRole("button", { name: "Remove…" }));
    expect(s.getByText("Remove the pool TCP 20000–20999?")).toBeTruthy();
    fireEvent.click(s.getByRole("button", { name: "Remove it" }));
    await waitFor(() => expect(calls.remove.map((r) => [r.portPoolId, r.etag])).toEqual([["pool_1", "3"]]));
  });

  it("sets a quota and removes one by emptying it", async () => {
    const calls = page();
    const s = await section();
    const tcp = within(s.getByRole("form", { name: "TCP quota" }));
    fireEvent.change(tcp.getByLabelText("TCP ports at most"), { target: { value: "50" } });
    fireEvent.click(tcp.getByRole("button", { name: "Save" }));
    await waitFor(() => expect(calls.quota.map((q) => [q.orgId, q.gatewayGroupId, q.protocol, q.maxPorts])).toEqual([["org_1", "ggr_eu", PortProtocol.TCP, 50]]));
    const udp = within(s.getByRole("form", { name: "UDP quota" }));
    await waitFor(() => expect((udp.getByLabelText("UDP ports at most") as HTMLInputElement).value).toBe("10"));
    expect(udp.getByText("2 in use")).toBeTruthy();
    fireEvent.change(udp.getByLabelText("UDP ports at most"), { target: { value: "" } });
    fireEvent.click(udp.getByRole("button", { name: "Save" }));
    await waitFor(() => expect(calls.unquota.map((q) => q.portQuotaId)).toEqual(["quo_1"]));
  });
});
