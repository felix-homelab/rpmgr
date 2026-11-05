// SPDX-License-Identifier: Apache-2.0

import { Code } from "@connectrpc/connect";
import { cleanup, fireEvent, screen, waitFor, within } from "@testing-library/react";
import { afterEach, describe, expect, it, vi } from "vitest";
import { ConnectorService, DataTransport } from "@/gen/rpmgr/v1/connector_pb";
import { GatewayService } from "@/gen/rpmgr/v1/gateway_pb";
import { MetricsService, TrafficResolution, type GetRouteTrafficRequest } from "@/gen/rpmgr/v1/metrics_pb";
import { HealthCheckType, RouteService, RouteState, TransportPin, type DeleteRouteRequest, type UpdateRouteRequest } from "@/gen/rpmgr/v1/route_pb";
import { ApplyState } from "@/gen/rpmgr/v1/status_pb";
import { Theme, UserService } from "@/gen/rpmgr/v1/user_pb";
import { policyCommand, shellArg } from "@/routes-data";
import { apiError, auth, show } from "@/testing/api";

afterEach(cleanup);

const postgres = {
  id: "rte_2", name: "postgres", gatewayGroupId: "ggr_eu", enabled: true,
  spec: { case: "tcp" as const, value: { port: 25432 } },
  targets: [
    { id: "tgt_1", connectorId: "con_db", enabled: true, weight: 100, priority: 0, address: { case: "hostPort" as const, value: { host: "10.0.0.5", port: 5432 } } },
    { id: "tgt_2", connectorId: "con_app", enabled: true, weight: 50, priority: 2, address: { case: "unixPath" as const, value: "/run/pg sock" } },
  ],
  status: {
    state: RouteState.DEGRADED, targetsTotal: 2, targetsReady: 1, gatewaysTotal: 2, gatewaysServing: 1,
    notServing: [
      { id: "tgt_1", reason: "BLOCKED_BY_LOCAL_POLICY", detail: "10.0.0.5:5432" },
      { id: "gtw_2", reason: "OFFLINE" },
    ],
    rejections: [{ agentId: "gtw_1", errors: [{ message: "port 25432 in use" }] }],
  },
};

// detail renders the route's page; the route's traffic is recorded in traffic, deleteRoute answers a deletion, updateRoute an update,
// and the gateway group eu has the public hostnames given; with null, the gateway groups cannot be
// read.
function detail(r: object, traffic: GetRouteTrafficRequest[] = [],
  deleteRoute: (req: DeleteRouteRequest) => object = () => { throw apiError(Code.Unimplemented); }, publicHostnames: string[] | null = [],
  updateRoute: (req: UpdateRouteRequest) => object = () => { throw apiError(Code.Unimplemented); }) {
  return show("/routes/rte_2", auth({
    getSession: () => ({ userId: "usr_ada", displayName: "Ada", memberships: [{ orgId: "org_1", role: "owner" }] }),
  }), (router) => {
    router.service(UserService, { getMe: () => ({ user: { id: "usr_ada", theme: Theme.SYSTEM } }) });
    router.service(GatewayService, {
      listGatewayGroups: () => {
        if (publicHostnames === null) {
          throw apiError(Code.Unavailable);
        }
        return { gatewayGroups: [{ id: "ggr_eu", name: "eu", publicHostnames }] };
      },
      listGateways: () => ({ gateways: [{ id: "gtw_1", name: "gw-eu-1" }, { id: "gtw_2", name: "gw-eu-2" }] }),
    });
    router.service(ConnectorService, {
      listConnectors: () => ({ connectors: [{ id: "con_db", name: "db-host-1" }, { id: "con_app", name: "app-host" }] }),
    });
    router.service(MetricsService, {
      getRouteTraffic: (req) => (traffic.push(req), {
        // the bucket that holds from, as the API rounds it down
        buckets: [{ start: { seconds: req.from!.seconds - (req.from!.seconds % (req.resolution === TrafficResolution.DAILY ? 86400n : 3600n)) },
          bytesIn: BigInt(req.resolution) * 1000n, bytesOut: 5n, connections: 2n }],
      }),
    });
    router.service(RouteService, {
      getRoute: (req) => {
        if (req.routeId !== "rte_2") {
          throw apiError(Code.NotFound);
        }
        return { route: r };
      },
      deleteRoute,
      updateRoute,
    });
  });
}

// stats reads the traffic's figures: each term with its value.
const stats = (section: ReturnType<typeof within>) =>
  section.getAllByRole("term").map((dt: HTMLElement) => [dt.textContent, dt.nextElementSibling?.textContent]);

describe("RouteDetail", () => {
  it("shows the desired settings next to the observed state, and the gateways and agents that do not serve", async () => {
    detail(postgres);
    expect(await screen.findByRole("heading", { name: "Route postgres (TCP)" })).toBeTruthy();
    await waitFor(() => expect(screen.getByText("enabled · gateway group eu · :25432")).toBeTruthy());
    // Without a public hostname on its group, the route shows only its port and says where to set one.
    expect(screen.getByText(/has no public hostname/).textContent).toBe(
      "The gateway group has no public hostname, so only the port is shown. Set the names clients reach it by");
    expect(screen.getByRole("link", { name: "Set the names clients reach it by" }).getAttribute("href")).toBe("/gateways/ggr_eu");
    expect(screen.getByText("degraded")).toBeTruthy();
    expect(screen.getByText("served by 1 of 2 gateways")).toBeTruthy();
    expect((await screen.findByText(/^gw-eu-2/)).textContent).toBe("gw-eu-2: offline");
    expect(screen.getByText("gw-eu-1").parentElement?.textContent).toBe("gw-eu-1: port 25432 in use");
    expect(screen.queryByText(/UDP datagrams/)).toBeNull();
  });

  it("shows a TCP route's port at each public hostname of its gateway group, an IPv6 address in brackets", async () => {
    detail(postgres, [], undefined, ["edge.example.com", "2001:db8::7"]);
    await waitFor(() => expect(screen.getByText("enabled · gateway group eu · edge.example.com:25432 · [2001:db8::7]:25432")).toBeTruthy());
    expect(screen.queryByText(/has no public hostname/)).toBeNull();
  });

  it("shows only the port, and no hint, while the gateway groups cannot be read", async () => {
    detail(postgres, [], undefined, null);
    expect(await screen.findByText(/:25432$/)).toBeTruthy();
    await new Promise((r) => setTimeout(r, 50)); // the groups' request has failed by now
    expect(screen.queryByText(/has no public hostname/)).toBeNull();
  });

  it("gives a route without a public port no address and no hint", async () => {
    detail({ ...postgres, spec: { case: "tcp", value: { port: 0 } } });
    await waitFor(() => expect(screen.getByText("enabled · gateway group eu")).toBeTruthy());
    expect(screen.queryByText(/has no public hostname/)).toBeNull();
  });

  it("shows the route's health check and what it found of each target (D133)", async () => {
    detail({
      ...postgres,
      healthCheck: { type: HealthCheckType.HTTP, httpPath: "/healthz", intervalSeconds: 30 },
      targets: [
        ...postgres.targets,
        { id: "tgt_3", connectorId: "con_db", enabled: true, weight: 10, address: { case: "hostPort" as const, value: { host: "10.0.0.6", port: 5432 } } },
        { id: "tgt_4", connectorId: "con_db", enabled: false, weight: 10, address: { case: "hostPort" as const, value: { host: "10.0.0.7", port: 5432 } } },
      ],
      status: { ...postgres.status, healthNotChecked: ["tgt_2"], notServing: [
        { id: "tgt_3", reason: "TARGETS_UNHEALTHY", detail: "status 503, want 200 to 399" },
        ...postgres.status.notServing,
      ] },
    });
    expect(await screen.findByText("HTTP health check of /healthz, every 30 s")).toBeTruthy();
    expect(screen.getByRole("columnheader", { name: "Health" })).toBeTruthy();
    const rows = within(await screen.findByRole("table")).getAllByRole("row");
    const cell = (row: number) => within(rows[row]!).getAllByRole("cell")[4]!;
    await waitFor(() => expect(rows[1]!.textContent).toContain("db-host-1"));
    expect(cell(1).textContent).toBe("—"); // blocked by the policy: the status column says why
    expect(cell(2).textContent).toBe("not checkedIts connector's rpmgr release runs no health checks, so the target counts as healthy. Upgrade the connector.");
    expect(cell(3).textContent).toBe("unhealthyLast check: status 503, want 200 to 399");
    expect(within(rows[3]!).getByText("its health checks fail")).toBeTruthy();
    expect(cell(4).textContent).toBe("—"); // disabled
  });

  it("shows each target's priority next to its weight", async () => {
    detail(postgres);
    const rows = within(await screen.findByRole("table")).getAllByRole("row");
    const heads = within(rows[0]!).getAllByRole("columnheader").map((h) => h.textContent);
    expect(heads.indexOf("Priority")).toBe(heads.indexOf("Weight") + 1);
    await waitFor(() => expect(rows[1]!.textContent).toContain("db-host-1"));
    expect(rows.slice(1).map((r) => within(r).getAllByRole("cell").slice(2, 4).map((c) => c.textContent))).toEqual([["100", "0"], ["50", "2"]]);
  });

  it("shows a target whose first health check has not finished as unknown and serving (D156)", async () => {
    detail({
      ...postgres,
      healthCheck: { type: HealthCheckType.TCP },
      status: { ...postgres.status, state: RouteState.READY, notServing: [
        { id: "tgt_2", reason: "TARGET_UNKNOWN", detail: "" },
      ] },
    });
    const rows = within(await screen.findByRole("table")).getAllByRole("row");
    await waitFor(() => expect(rows[1]!.textContent).toContain("db-host-1"));
    const cells = within(rows[2]!).getAllByRole("cell");
    expect(cells[4]!.textContent).toBe("unknownIts first health check has not finished. It gets traffic once it passed, or while no other target of its priority is healthy.");
    expect(cells[6]!.textContent).toContain("ready"); // not a problem: it serves when no other target does
    expect(within(rows[2]!).queryByText("its health check has not decided yet")).toBeNull();
  });

  it("marks every target healthy that its connector checks and finds no fault in, and shows no column values without a check", async () => {
    const ready = { ...postgres.status, state: RouteState.READY, notServing: [] };
    detail({ ...postgres, healthCheck: { type: HealthCheckType.TCP }, status: ready });
    expect(await screen.findByText("TCP health check")).toBeTruthy();
    const rows = within(await screen.findByRole("table")).getAllByRole("row");
    await waitFor(() => expect(rows[1]!.textContent).toContain("db-host-1"));
    expect(rows.slice(1).map((r) => within(r).getAllByRole("cell")[4]!.textContent)).toEqual(["healthy", "healthy"]);
    cleanup();
    detail({ ...postgres, status: ready });
    expect(await screen.findByText("no health check")).toBeTruthy();
    const plain = within(await screen.findByRole("table")).getAllByRole("row");
    expect(plain.slice(1).map((r) => within(r).getAllByRole("cell")[4]!.textContent)).toEqual(["—", "—"]);
  });

  it("gives a target that a local policy blocks the command for its host", async () => {
    const write = vi.fn(() => Promise.resolve());
    Object.assign(navigator, { clipboard: { writeText: write } });
    detail(postgres);
    const rows = within(await screen.findByRole("table")).getAllByRole("row");
    await waitFor(() => expect(rows[1]!.textContent).toContain("db-host-1"));
    const blocked = within(rows[1]!);
    expect(blocked.getByText("blocked by the connector's local policy")).toBeTruthy();
    expect(blocked.getByText("Run on the host of db-host-1:")).toBeTruthy();
    expect(blocked.getByText("sudo rpmgr policy allow-target 10.0.0.5:5432")).toBeTruthy();
    fireEvent.click(blocked.getByRole("button", { name: "Copy" }));
    expect(write).toHaveBeenCalledWith("sudo rpmgr policy allow-target 10.0.0.5:5432");
    expect(rows[2]!.textContent).toContain("/run/pg sock");
    expect(within(rows[2]!).getByText("ready")).toBeTruthy();
  });

  // withTransports is postgres with the transports its status reports per target.
  const withTransports = (targetTransports: object[], targetsReady = 2) =>
    ({ ...postgres, status: { ...postgres.status, notServing: [{ id: "gtw_2", reason: "OFFLINE" }], targetsReady, targetTransports } });
  const transportCells = async () => {
    await screen.findByRole("heading", { name: "Route postgres (TCP)" });
    await waitFor(() => expect(screen.getAllByRole("row")).toHaveLength(3));
    // the Transport column is the fifth of a target's row
    return screen.getAllByRole("row").slice(1).map((r) => r.querySelectorAll("td")[5]!.textContent);
  };

  it("shows each target the transport its streams take, the raced and the fallback ones told apart", async () => {
    detail(withTransports([
      { targetId: "tgt_1", gateways: [{ gatewayId: "gtw_1", transport: DataTransport.QUIC }, { gatewayId: "gtw_2", transport: DataTransport.QUIC }] },
      { targetId: "tgt_2", gateways: [{ gatewayId: "gtw_1", transport: DataTransport.H2 }, { gatewayId: "gtw_2", transport: DataTransport.H2 }] },
    ]));
    expect(await transportCells()).toEqual(["QUIC", "HTTP/2 (fallback for QUIC)"]);
    // The route header summarises the targets per transport.
    expect(screen.getByText("Transport: QUIC 1 · HTTP/2 1")).toBeTruthy();
    cleanup();
    detail(withTransports([
      { targetId: "tgt_1", gateways: [{ gatewayId: "gtw_1", transport: DataTransport.WSS }] },
      { targetId: "tgt_2", gateways: [{ gatewayId: "gtw_1", transport: DataTransport.H2 }] },
    ]));
    expect(await transportCells()).toEqual(["WSS (fallback)", "HTTP/2 (fallback for QUIC)"]);
  });

  it("says where a pin is set, and never calls a pinned transport a fallback", async () => {
    const on = (pinnedBy: TransportPin, transport: DataTransport) => ({ pinnedBy, gateways: [{ gatewayId: "gtw_1", transport }] });
    detail(withTransports([
      { targetId: "tgt_1", ...on(TransportPin.ROUTE, DataTransport.H2) },
      { targetId: "tgt_2", ...on(TransportPin.CONNECTOR, DataTransport.QUIC) },
    ]));
    expect(await transportCells()).toEqual(["HTTP/2 (pinned on the route)", "QUIC (pinned on the connector)"]);
    cleanup();
    detail(withTransports([
      { targetId: "tgt_1", ...on(TransportPin.INSTANCE, DataTransport.WSS) },
      { targetId: "tgt_2", ...on(TransportPin.ROUTE, DataTransport.WSS) },
    ]));
    expect(await transportCells()).toEqual(["WSS (pinned by the instance default)", "WSS (pinned on the route)"]);
  });

  it("shows a target served over different transports through different gateways one by one", async () => {
    detail(withTransports([
      { targetId: "tgt_1", gateways: [{ gatewayId: "gtw_1", transport: DataTransport.QUIC }, { gatewayId: "gtw_2", transport: DataTransport.QUIC },
        { gatewayId: "gtw_3", transport: DataTransport.H2 }] },
      { targetId: "tgt_2", gateways: [{ gatewayId: "gtw_1", transport: DataTransport.QUIC }, { gatewayId: "gtw_2", transport: DataTransport.H2 }] },
    ]));
    expect(await transportCells()).toEqual(["QUIC on 2 gatewaysHTTP/2 (fallback for QUIC) on gtw_3", "QUIC on gw-eu-1HTTP/2 (fallback for QUIC) on gw-eu-2"]);
    // The gateways of a group are named on hover.
    expect(screen.getByText("QUIC on 2 gateways").getAttribute("title")).toBe("gw-eu-1, gw-eu-2");
    expect(screen.getByText("Transport: QUIC 2 · HTTP/2 2")).toBeTruthy();
  });

  it("shows unknown where a gateway does not report the transport, and nothing for a target that does not serve", async () => {
    // tgt_1 is blocked by the local policy, so it has none. tgt_2 is served through a gateway of an
    // earlier release.
    detail({ ...postgres, status: { ...postgres.status, targetTransports: [
      { targetId: "tgt_1" },
      { targetId: "tgt_2", gateways: [{ gatewayId: "gtw_1" }] },
    ] } });
    expect(await transportCells()).toEqual(["—", "unknown"]);
    expect(screen.getByText("Transport: unknown 1")).toBeTruthy();
    cleanup();
    // A status without transports (a target not served, an offline connector, an older controller):
    // a dash, and no summary in the header.
    detail(withTransports([{ targetId: "tgt_1" }, { targetId: "tgt_2" }]));
    expect(await transportCells()).toEqual(["—", "—"]);
    expect(screen.queryByText(/^Transport:/)).toBeNull();
    cleanup();
    detail(postgres);
    expect(await transportCells()).toEqual(["—", "—"]);
  });

  it("shows UDP routes without a hint about datagram sizes", async () => {
    detail({ ...postgres, spec: { case: "udp", value: { port: 53 } } });
    await screen.findByRole("heading", { name: "Route postgres (UDP)" });
    expect(screen.queryByText(/QUIC datagrams/)).toBeNull();
  });

  it("says when the route does not exist", async () => {
    show("/routes/rte_9", auth({ getSession: () => ({ userId: "usr_ada", memberships: [{ orgId: "org_1", role: "owner" }] }) }), (router) => {
      router.service(UserService, { getMe: () => ({ user: { id: "usr_ada", theme: Theme.SYSTEM } }) });
      router.service(RouteService, { getRoute: () => { throw apiError(Code.NotFound); } });
    });
    expect(await screen.findByText("This route does not exist, or you cannot see it.")).toBeTruthy();
  });

  it("shows the route's traffic of the last 24 hours, or per day of the last 30 days", async () => {
    const traffic: GetRouteTrafficRequest[] = [];
    detail(postgres, traffic);
    const section = within(await screen.findByRole("region", { name: "Traffic" }));
    await section.findByText("1 kB");
    expect(stats(section)).toEqual([["In", "1 kB"], ["Out", "5 B"], ["Connections", "2"], ["Errors", "0"]]);
    expect(section.getByRole("button", { name: "24 hours" }).getAttribute("aria-pressed")).toBe("true");
    fireEvent.click(section.getByRole("button", { name: "30 days" }));
    await section.findByText("2 kB");
    expect(stats(section)).toEqual([["In", "2 kB"], ["Out", "5 B"], ["Connections", "2"], ["Errors", "0"]]);
    const spans = traffic.map((r) => [r.routeId, r.resolution, Number(r.to!.seconds - r.from!.seconds) / 3600]);
    expect(spans).toEqual([["rte_2", TrafficResolution.HOURLY, 24], ["rte_2", TrafficResolution.DAILY, 720]]);
    expect(traffic[0]!.to).toEqual(traffic[1]!.to);
  });

  it("leads back to all routes and to the route's form, and adds targets from the targets card", async () => {
    detail({ ...postgres, targets: [] });
    await screen.findByRole("heading", { name: "Route postgres (TCP)" });
    expect(screen.getByRole("link", { name: "All routes" }).getAttribute("href")).toBe("/routes");
    expect(screen.getByRole("link", { name: "Edit" }).getAttribute("href")).toBe("/routes/rte_2/edit");
    const targets = within(screen.getByRole("region", { name: "Targets" }));
    expect(targets.getByText("The route has no targets.")).toBeTruthy();
    expect(targets.queryByRole("table")).toBeNull();
    fireEvent.click(targets.getByRole("button", { name: "Add a target" }));
    expect(targets.getByRole("form", { name: "New target" })).toBeTruthy();
    expect(targets.queryByRole("button", { name: "Add a target" })).toBeNull(); // one form at a time
  });

  it("deletes the route under its etag after a confirmation that names it, and follows the deletion", async () => {
    const deletes: DeleteRouteRequest[] = [];
    detail({ ...postgres, etag: "4" }, [], (req) => (deletes.push(req),
      { revision: { dbEpoch: "e", seq: 12n }, applyStatus: { state: ApplyState.APPLIED, agentsTotal: 3, agentsApplied: 3 } }));
    await screen.findByRole("heading", { name: "Route postgres (TCP)" });
    fireEvent.click(screen.getByRole("button", { name: "Delete…" }));
    expect(screen.getByText("Delete the route postgres with its hostnames, targets and port? This cannot be undone.")).toBeTruthy();
    expect(screen.queryByRole("link", { name: "Edit" })).toBeNull(); // the question replaces the actions
    fireEvent.click(screen.getByRole("button", { name: "Cancel" }));
    expect(screen.queryByText(/^Delete the route/)).toBeNull();
    expect(deletes).toHaveLength(0);

    fireEvent.click(screen.getByRole("button", { name: "Delete…" }));
    fireEvent.click(screen.getByRole("button", { name: "Delete it" }));
    expect(await screen.findByRole("heading", { name: "Route postgres deleted" })).toBeTruthy();
    expect(deletes.map((d) => [d.routeId, d.etag])).toEqual([["rte_2", "4"]]);
    expect(screen.getByText("Revision 12: applied by all 3 agents.")).toBeTruthy();
    expect(screen.getByRole("link", { name: "All routes" }).getAttribute("href")).toBe("/routes");
    expect(screen.queryByText("This route does not exist, or you cannot see it.")).toBeNull();
  });

  it("puts an http route into maintenance with its own switch, under the etag it read, and changes nothing else", async () => {
    const updates: UpdateRouteRequest[] = [];
    const web = { ...postgres, etag: "4", spec: { case: "http" as const, value: { hostnames: ["app.example.com"], maintenanceMessage: "Back at 18:00." } },
      status: { state: RouteState.READY } };
    detail(web, [], undefined, [], (req) => (updates.push(req),
      { route: req.route, revision: { dbEpoch: "e", seq: 13n }, applyStatus: { state: ApplyState.APPLIED, agentsTotal: 2, agentsApplied: 2 } }));
    const toggle = await screen.findByRole("switch", { name: "Maintenance" });
    expect(toggle.getAttribute("aria-checked")).toBe("false");
    expect(screen.queryByText(/The maintenance page says/)).toBeNull(); // only while in maintenance
    fireEvent.click(toggle);
    await waitFor(() => expect(updates).toHaveLength(1));
    const req = updates[0]!;
    expect([req.updateMask?.paths, req.etag, req.route?.enabled, req.route?.spec.case]).toEqual([["http.maintenance"], "4", true, "http"]);
    expect(req.route?.spec.case === "http" && [req.route.spec.value.maintenance, req.route.spec.value.maintenanceMessage]).toEqual([true, "Back at 18:00."]);
    expect(await screen.findByText("Revision 13: applied by all 2 agents.")).toBeTruthy();
  });

  it("shows a route in maintenance with its message, and gives other route types no maintenance switch", async () => {
    detail({ ...postgres, spec: { case: "http" as const, value: { hostnames: ["app.example.com"], maintenance: true, maintenanceMessage: "Back at 18:00.\nSorry." } },
      status: { state: RouteState.MAINTENANCE } });
    expect(await screen.findByText(/^enabled · in maintenance · gateway group eu/)).toBeTruthy();
    expect(screen.getByText("The maintenance page says: Back at 18:00. Sorry.", { normalizer: (s) => s.replace(/\s+/g, " ") })).toBeTruthy();
    expect(screen.getByRole("switch", { name: "Maintenance" }).getAttribute("aria-checked")).toBe("true");
    expect(screen.getAllByText("maintenance").length).toBeGreaterThan(0); // the observed state
    cleanup();
    detail(postgres);
    await screen.findByRole("switch", { name: "Enabled" });
    expect(screen.queryByRole("switch", { name: "Maintenance" })).toBeNull();
  });

  it("keeps the route and says why when the deletion is refused", async () => {
    let refusal = apiError(Code.FailedPrecondition, "ETAG_MISMATCH");
    detail({ ...postgres, etag: "4" }, [], () => { throw refusal; });
    await screen.findByRole("heading", { name: "Route postgres (TCP)" });
    fireEvent.click(screen.getByRole("button", { name: "Delete…" }));
    fireEvent.click(screen.getByRole("button", { name: "Delete it" }));
    expect((await screen.findByRole("alert")).textContent).toBe("The route changed since this page loaded it. The page shows it as it is now; try again.");
    expect(screen.getByRole("heading", { name: "Route postgres (TCP)" })).toBeTruthy();
    expect(screen.queryByText(/^Delete the route/)).toBeNull();

    refusal = apiError(Code.PermissionDenied, "PERMISSION_MISSING");
    fireEvent.click(screen.getByRole("button", { name: "Delete…" }));
    expect(screen.queryByRole("alert")).toBeNull(); // asking again clears the last error
    fireEvent.click(screen.getByRole("button", { name: "Delete it" }));
    expect((await screen.findByRole("alert")).textContent).toBe("That did not work: api error");
    expect(screen.getByRole("heading", { name: "Route postgres (TCP)" })).toBeTruthy();
  });
});

describe("policyCommand", () => {
  it.each([
    ["10.0.0.5:5432", "sudo rpmgr policy allow-target 10.0.0.5:5432"],
    ["127.0.0.1:345 denied by 127.0.0.1:345", "sudo rpmgr policy remove-deny-target 127.0.0.1:345"],
    ["10.9.0.7:22 denied by 10.9.0.0/16", "sudo rpmgr policy remove-deny-target 10.9.0.0/16"],
    ["/run/app.sock denied by /run/app.sock", "sudo rpmgr policy remove-deny-target /run/app.sock"],
    ["/run/a b.sock denied by /run/a b.sock", "sudo rpmgr policy remove-deny-target '/run/a b.sock'"],
    ["[2001:db8::5]:5432", "sudo rpmgr policy allow-target '[2001:db8::5]:5432'"],
    ["[fd00::9]:443 denied by [fd00::/64]:443", "sudo rpmgr policy remove-deny-target '[fd00::/64]:443'"],
    ["/run/pg sock", "sudo rpmgr policy allow-target '/run/pg sock'"],
    ["/tmp/x';rm -rf /;'", "sudo rpmgr policy allow-target '/tmp/x'\\'';rm -rf /;'\\'''"],
  ])("%s", (target, want) => {
    expect(policyCommand(target)).toBe(want);
  });

  it("has no command for one of rpmgr's own ports", () => {
    expect(policyCommand("127.0.0.1:7381 is one of rpmgr's own ports")).toBeUndefined();
  });

  it("leaves plain words unquoted", () => {
    expect(shellArg("a-b_c.d")).toBe("a-b_c.d");
  });
});
