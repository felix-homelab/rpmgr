// SPDX-License-Identifier: Apache-2.0

import { clone, create, equals } from "@bufbuild/protobuf";
import { Code, ConnectError } from "@connectrpc/connect";
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
import { marked, unmatched } from "@/testing/required";

afterEach(cleanup);

const db = create(ConnectorSchema, {
  id: "con_db", name: "db-host-1", labels: { site: "office" }, enabled: true, transport: DataTransport.AUTO, etag: "4",
  session: { connected: true, version: "0.1.0", remoteAddr: "192.0.2.5:40000", lastSeenTime: timestampFromDate(new Date("2026-10-09T10:00:00Z")) },
});
const lab = create(ConnectorSchema, { id: "con_lab", name: "lab", labels: { site: "home" }, enabled: false, ephemeral: true, session: { connected: false } });

const routes: { id: string; name: string; targets: { connectorId: string; enabled?: boolean }[] }[] = [
  { id: "rte_pg", name: "postgres", targets: [{ connectorId: "con_db" }] },
  { id: "rte_web", name: "web", targets: [{ connectorId: "con_lab" }] },
];

function page(path: string, connectors = [lab, db], routeList = routes, routesState: "ok" | "loading" | "failed" = "ok", updateFails?: Code) {
  const updates: UpdateConnectorRequest[] = [];
  const decommissions: DecommissionConnectorRequest[] = [];
  const view = show(path, auth({ getSession: () => ({ userId: "usr_ada", memberships: [{ orgId: "org_1", role: "owner" }] }) }), (router) => {
    router.service(UserService, { getMe: () => ({ user: { id: "usr_ada", theme: Theme.SYSTEM } }) });
    router.service(GatewayService, { listGateways: () => ({ gateways: [{ id: "gtw_1", name: "gw-eu-1" }] }) });
    router.service(StatusService, { async *watchApplyStatus() {} });
    router.service(RouteService, {
      listRoutes: () => {
        if (routesState === "failed") {
          throw new ConnectError("unavailable", Code.Unavailable);
        }
        return routesState === "loading" ? new Promise<never>(() => {}) : { routes: routeList };
      },
    });
    router.service(ConnectorService, {
      listConnectors: () => ({ connectors }),
      getConnector: (req) => ({ connector: req.connectorId === "con_db" ? db : lab }),
      getConnectorStatus: () => ({ status: {
        dataSessions: [{ gatewayId: "gtw_1", transport: DataTransport.QUIC, rtt: { seconds: 0n, nanos: 23_400_000 } }],
        notReady: [{ resourceId: "rte_pg", reason: "BLOCKED_BY_LOCAL_POLICY", detail: "10.0.0.5:5432" }],
      } }),
      updateConnector: (req) => {
        updates.push(req);
        if (updateFails) {
          throw new ConnectError("refused", updateFails);
        }
        return { connector: req.connector, revision: { dbEpoch: "e", seq: 3n }, applyStatus: { state: ApplyState.APPLIED, agentsTotal: 1, agentsApplied: 1 } };
      },
      decommissionConnector: (req) => (decommissions.push(req), { connector: db }),
    });
  });
  return { ...view, updates, decommissions };
}

describe("Connectors", () => {
  it("lists the connectors by name, filtered by text and by state, a disabled one as disabled (D81)", async () => {
    const { history } = page("/connectors");
    const table = await screen.findByRole("table");
    await waitFor(() => expect(within(table).getAllByRole("row")).toHaveLength(3));
    expect(within(table).getAllByRole("row").slice(1).map((r) => r.textContent)).toEqual([
      expect.stringMatching(/^db-host-1connected0\.1\.0.*site=office$/), // the badges' icons are drawings, hidden from screen readers
      "labephemeraldisabledsite=home",
    ]);
    fireEvent.change(screen.getByLabelText("Search"), { target: { value: "site=home" } });
    await waitFor(() => expect(within(table).getAllByRole("row")).toHaveLength(2));
    fireEvent.change(screen.getByLabelText("Search"), { target: { value: "" } });
    fireEvent.change(screen.getByLabelText("Session"), { target: { value: "connected" } });
    await waitFor(() => expect(within(table).getAllByRole("row").slice(1).map((r) => r.textContent?.slice(0, 9))).toEqual(["db-host-1"]));
    expect(new URLSearchParams(history.location.search).get("session")).toBe("connected");
    fireEvent.change(screen.getByLabelText("Session"), { target: { value: "disabled" } });
    await waitFor(() => expect(within(table).getAllByRole("row").slice(1).map((r) => r.textContent?.slice(0, 3))).toEqual(["lab"]));
    fireEvent.change(screen.getByLabelText("Session"), { target: { value: "offline" } }); // lab is disabled, not offline
    expect(await screen.findByText("No connector matches.")).toBeTruthy();
  });

  it("offers to enroll the first connector when there is none", async () => {
    const { history } = page("/connectors", []);
    expect(await screen.findByText("No connectors yet.")).toBeTruthy();
    expect(screen.queryByRole("table")).toBeNull();
    const enroll = screen.getAllByRole("button", { name: "Enroll a connector" });
    expect(enroll).toHaveLength(2); // the header's and the empty list's
    fireEvent.click(enroll[1]!);
    await waitFor(() => expect(new URLSearchParams(history.location.search).get("enroll")).toBe("true"));
  });

  it("says when no connector matches the filters, and clears them", async () => {
    const { history } = page("/connectors?q=nothing&session=offline");
    expect(await screen.findByText("No connector matches.")).toBeTruthy();
    expect(screen.queryByRole("table")).toBeNull();
    fireEvent.click(screen.getByRole("button", { name: "Clear the filters" }));
    await waitFor(() => expect(within(screen.getByRole("table")).getAllByRole("row")).toHaveLength(3));
    expect(history.location.search).toBe("");
  });

  it("leads back to the list from a connector's page", async () => {
    page("/connectors/con_db");
    const back = await screen.findByRole("link", { name: "All connectors" });
    expect(back.getAttribute("href")).toBe("/connectors");
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
    expect([marked(screen.getByRole("region", { name: "Settings" })), unmatched(screen.getByRole("region", { name: "Settings" }))]).toEqual([["Name"], []]);
    fireEvent.change(settings.getByLabelText("Name"), { target: { value: "db-host-2" } });
    fireEvent.change(settings.getByLabelText("Transport"), { target: { value: String(DataTransport.H2) } });
    fireEvent.click(settings.getByRole("button", { name: "Save" }));
    expect(await screen.findByText("Revision 3: applied by all 1 agents.")).toBeTruthy();
    const want = clone(ConnectorSchema, db); // create would return db itself
    want.name = "db-host-2";
    want.transport = DataTransport.H2;
    expect(equals(ConnectorSchema, updates[0]!.connector!, want)).toBe(true);
    expect([updates[0]!.updateMask?.paths, updates[0]!.etag]).toEqual([["name", "labels", "transport"], "4"]);
    expect(settings.queryByRole("checkbox")).toBeNull(); // whether it serves has its own switch (U3)
  });

  it("switches a connector off with its switch alone, and follows the change (D81)", async () => {
    const { updates } = page("/connectors/con_db");
    const toggle = await screen.findByRole("switch", { name: "Enabled" });
    expect(toggle.getAttribute("aria-checked")).toBe("true");
    fireEvent.click(toggle);
    expect(await screen.findByText("Revision 3: applied by all 1 agents.")).toBeTruthy();
    expect([updates[0]!.connector?.enabled, updates[0]!.connector?.name, updates[0]!.updateMask?.paths, updates[0]!.etag])
      .toEqual([false, "db-host-1", ["enabled"], "4"]);
  });

  it("says so when the connector changed before the switch was used", async () => {
    page("/connectors/con_lab", [lab, db], routes, "ok", Code.FailedPrecondition);
    const toggle = await screen.findByRole("switch", { name: "Enabled" });
    expect(toggle.getAttribute("aria-checked")).toBe("false");
    fireEvent.click(toggle);
    expect((await screen.findByRole("alert")).textContent).toBe("The connector changed since this page loaded it. The page shows it as it is now; try again.");
  });

  it("decommissions after a confirmation that names the connector", async () => {
    const { decommissions, history } = page("/connectors/con_db");
    const section = within(await screen.findByRole("region", { name: "Decommission" }));
    await screen.findByRole("link", { name: "postgres" }); // the routes have loaded
    fireEvent.click(section.getByRole("button", { name: "Decommission…" }));
    expect(section.getByRole("alert").textContent).toContain("Decommissioning db-host-1 revokes its identity");
    fireEvent.click(section.getByRole("button", { name: "Decommission db-host-1" }));
    await waitFor(() => expect(history.location.pathname).toBe("/connectors"));
    expect(decommissions.map((d) => [d.connectorId, d.etag])).toEqual([["con_db", "4"]]);
  });

  // D78: the routes it leaves with no target go with it; a route with another target stays.
  it("names the routes a decommission deletes, and only those", async () => {
    page("/connectors/con_db", [lab, db], [
      ...routes,
      { id: "rte_dns", name: "dns", targets: [{ connectorId: "con_db" }, { connectorId: "con_db" }] },
      { id: "rte_shared", name: "shared", targets: [{ connectorId: "con_db" }, { connectorId: "con_lab" }] },
      // A disabled target, here also on a disabled connector, still keeps its route.
      { id: "rte_standby", name: "standby", targets: [{ connectorId: "con_db" }, { connectorId: "con_lab", enabled: false }] },
    ]);
    const section = within(await screen.findByRole("region", { name: "Decommission" }));
    await screen.findByRole("link", { name: "shared" }); // the routes have loaded
    fireEvent.click(section.getByRole("button", { name: "Decommission…" }));
    expect(section.getByRole("alert").textContent).toContain(
      "These 2 routes have no other target and are deleted with it, which frees their ports and hostnames: postgres, dns.");
    expect(section.getByRole("alert").textContent).not.toMatch(/shared|standby/);
  });

  // Until the routes are read, it is not known which go with it, so it cannot be decommissioned.
  it("waits for the routes before it decommissions", async () => {
    const { decommissions } = page("/connectors/con_db", [lab, db], routes, "loading");
    const section = within(await screen.findByRole("region", { name: "Decommission" }));
    fireEvent.click(section.getByRole("button", { name: "Decommission…" }));
    const confirm = section.getByRole("button", { name: "Decommission db-host-1" }) as HTMLButtonElement;
    expect(confirm.disabled).toBe(true);
    fireEvent.click(confirm);
    expect(decommissions).toEqual([]);
  });

  it("says so and does not decommission when the routes cannot be read", async () => {
    const { decommissions } = page("/connectors/con_db", [lab, db], routes, "failed");
    const section = within(await screen.findByRole("region", { name: "Decommission" }));
    fireEvent.click(section.getByRole("button", { name: "Decommission…" }));
    await waitFor(() => expect(section.getAllByRole("alert").map((a) => a.textContent)).toContain(
      "The routes could not be read, so it is not known which of them would be deleted with it. Reload the page to try again."));
    expect((section.getByRole("button", { name: "Decommission db-host-1" }) as HTMLButtonElement).disabled).toBe(true);
    expect(decommissions).toEqual([]);
  });

  it("names no route when every route it serves has another target", async () => {
    page("/connectors/con_db", [lab, db], [{ id: "rte_shared", name: "shared", targets: [{ connectorId: "con_db" }, { connectorId: "con_lab" }] }]);
    const section = within(await screen.findByRole("region", { name: "Decommission" }));
    await screen.findByRole("link", { name: "shared" });
    fireEvent.click(section.getByRole("button", { name: "Decommission…" }));
    expect(section.getByRole("alert").textContent).toMatch(/Its route targets are deleted\.$/);
  });
});
