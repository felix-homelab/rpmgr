// SPDX-License-Identifier: Apache-2.0

import { clone, create, equals } from "@bufbuild/protobuf";
import { timestampFromDate } from "@bufbuild/protobuf/wkt";
import { cleanup, fireEvent, screen, waitFor, within } from "@testing-library/react";
import { afterEach, describe, expect, it } from "vitest";
import {
  ConnectorSchema, ConnectorService, DataTransport, type DecommissionConnectorRequest, type UpdateConnectorRequest,
} from "@/gen/rpmgr/v1/connector_pb";
import { GatewayService } from "@/gen/rpmgr/v1/gateway_pb";
import { RouteService } from "@/gen/rpmgr/v1/route_pb";
import { ApplyState, StatusService } from "@/gen/rpmgr/v1/status_pb";
import { Theme, UserService } from "@/gen/rpmgr/v1/user_pb";
import { auth, show } from "@/testing/api";

afterEach(cleanup);

const db = create(ConnectorSchema, {
  id: "con_db", name: "db-host-1", labels: { site: "office" }, enabled: true, transport: DataTransport.AUTO, etag: "4",
  session: { connected: true, version: "0.1.0", remoteAddr: "192.0.2.5:40000", lastSeenTime: timestampFromDate(new Date("2026-10-09T10:00:00Z")) },
});
const lab = create(ConnectorSchema, { id: "con_lab", name: "lab", labels: { site: "home" }, enabled: false, ephemeral: true, session: { connected: false } });

function page(path: string) {
  const updates: UpdateConnectorRequest[] = [];
  const decommissions: DecommissionConnectorRequest[] = [];
  const view = show(path, auth({ getSession: () => ({ userId: "usr_ada", memberships: [{ orgId: "org_1", role: "owner" }] }) }), (router) => {
    router.service(UserService, { getMe: () => ({ user: { id: "usr_ada", theme: Theme.SYSTEM } }) });
    router.service(GatewayService, { listGateways: () => ({ gateways: [{ id: "gtw_1", name: "gw-eu-1" }] }) });
    router.service(StatusService, { async *watchApplyStatus() {} });
    router.service(RouteService, {
      listRoutes: () => ({ routes: [
        { id: "rte_pg", name: "postgres", targets: [{ connectorId: "con_db" }] },
        { id: "rte_web", name: "web", targets: [{ connectorId: "con_lab" }] },
      ] }),
    });
    router.service(ConnectorService, {
      listConnectors: () => ({ connectors: [lab, db] }),
      getConnector: (req) => ({ connector: req.connectorId === "con_db" ? db : lab }),
      getConnectorStatus: () => ({ status: {
        dataSessions: [{ gatewayId: "gtw_1", transport: DataTransport.QUIC, rtt: { seconds: 0n, nanos: 23_400_000 } }],
        notReady: [{ resourceId: "rte_pg", reason: "BLOCKED_BY_LOCAL_POLICY", detail: "10.0.0.5:5432" }],
      } }),
      updateConnector: (req) => (updates.push(req), { connector: req.connector, revision: { dbEpoch: "e", seq: 3n }, applyStatus: { state: ApplyState.APPLIED, agentsTotal: 1, agentsApplied: 1 } }),
      decommissionConnector: (req) => (decommissions.push(req), { connector: db }),
    });
  });
  return { ...view, updates, decommissions };
}

describe("Connectors", () => {
  it("lists the connectors by name, filtered by text and session", async () => {
    const { history } = page("/connectors");
    const table = await screen.findByRole("table");
    await waitFor(() => expect(within(table).getAllByRole("row")).toHaveLength(3));
    expect(within(table).getAllByRole("row").slice(1).map((r) => r.textContent)).toEqual([
      expect.stringMatching(/^db-host-1● connected0\.1\.0.*site=office$/),
      "lab(disabled)(ephemeral)○ offlinesite=home",
    ]);
    fireEvent.change(screen.getByLabelText("Search"), { target: { value: "site=home" } });
    await waitFor(() => expect(within(table).getAllByRole("row")).toHaveLength(2));
    fireEvent.change(screen.getByLabelText("Search"), { target: { value: "" } });
    fireEvent.change(screen.getByLabelText("Session"), { target: { value: "connected" } });
    await waitFor(() => expect(within(table).getAllByRole("row").slice(1).map((r) => r.textContent?.slice(0, 9))).toEqual(["db-host-1"]));
    expect(new URLSearchParams(history.location.search).get("session")).toBe("connected");
  });

  it("shows a connector's sessions, routes and the fix for a blocked target", async () => {
    page("/connectors/con_db");
    expect(await screen.findByRole("heading", { name: "Connector db-host-1" })).toBeTruthy();
    expect(screen.getByText(/^Control session up from 192\.0\.2\.5:40000/)).toBeTruthy();
    const data = within(await screen.findByRole("table"));
    await waitFor(() => expect(data.getAllByRole("row")[1]!.textContent).toMatch(/^gw-eu-1QUIC23 ms/));
    expect(await screen.findByRole("link", { name: "postgres" })).toBeTruthy();
    expect(screen.queryByRole("link", { name: "web" })).toBeNull();
    expect(await screen.findByText("postgres: blocked by the connector's local policy")).toBeTruthy();
    expect(screen.getByText("sudo rpmgr policy allow-target 10.0.0.5:5432")).toBeTruthy();
  });

  it("saves the connector's settings as a whole", async () => {
    const { updates } = page("/connectors/con_db");
    const settings = within(await screen.findByRole("region", { name: "Settings" }));
    fireEvent.change(settings.getByLabelText("Name"), { target: { value: "db-host-2" } });
    fireEvent.change(settings.getByLabelText("Transport"), { target: { value: String(DataTransport.H2) } });
    fireEvent.click(settings.getByRole("button", { name: "Save" }));
    expect(await screen.findByText("Revision 3: applied by all 1 agents.")).toBeTruthy();
    const want = clone(ConnectorSchema, db); // create would return db itself
    want.name = "db-host-2";
    want.transport = DataTransport.H2;
    expect(equals(ConnectorSchema, updates[0]!.connector!, want)).toBe(true);
    expect([updates[0]!.updateMask?.paths, updates[0]!.etag]).toEqual([["name", "labels", "enabled", "transport"], "4"]);
  });

  it("decommissions after a confirmation that names the connector", async () => {
    const { decommissions, history } = page("/connectors/con_db");
    const section = within(await screen.findByRole("region", { name: "Decommission" }));
    fireEvent.click(section.getByRole("button", { name: "Decommission…" }));
    expect(section.getByRole("alert").textContent).toContain("Decommissioning db-host-1 revokes its identity");
    fireEvent.click(section.getByRole("button", { name: "Decommission db-host-1" }));
    await waitFor(() => expect(history.location.pathname).toBe("/connectors"));
    expect(decommissions.map((d) => [d.connectorId, d.etag])).toEqual([["con_db", "4"]]);
  });
});
