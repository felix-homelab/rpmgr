// SPDX-License-Identifier: Apache-2.0

import { Code } from "@connectrpc/connect";
import { cleanup, fireEvent, screen, waitFor, within } from "@testing-library/react";
import { afterEach, describe, expect, it, vi } from "vitest";
import { ConnectorService, DataTransport } from "@/gen/rpmgr/v1/connector_pb";
import { GatewayService } from "@/gen/rpmgr/v1/gateway_pb";
import { MetricsService, TrafficResolution, type GetRouteTrafficRequest } from "@/gen/rpmgr/v1/metrics_pb";
import { RouteService, RouteState } from "@/gen/rpmgr/v1/route_pb";
import { Theme, UserService } from "@/gen/rpmgr/v1/user_pb";
import { allowCommand, shellArg } from "@/routes-data";
import { apiError, auth, show } from "@/testing/api";

afterEach(cleanup);

const postgres = {
  id: "rte_2", name: "postgres", gatewayGroupId: "ggr_eu", enabled: true,
  spec: { case: "tcp" as const, value: { port: 25432 } },
  targets: [
    { id: "tgt_1", connectorId: "con_db", enabled: true, weight: 100, address: { case: "hostPort" as const, value: { host: "10.0.0.5", port: 5432 } } },
    { id: "tgt_2", connectorId: "con_app", enabled: true, weight: 50, address: { case: "unixPath" as const, value: "/run/pg sock" } },
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

// detail renders the route's page; the connectors' data sessions use the transports given, and
// the route's traffic is recorded in traffic.
function detail(r: object, transports: Record<string, DataTransport[]> = {}, traffic: GetRouteTrafficRequest[] = []) {
  return show("/routes/rte_2", auth({
    getSession: () => ({ userId: "usr_ada", displayName: "Ada", memberships: [{ orgId: "org_1", role: "owner" }] }),
  }), (router) => {
    router.service(UserService, { getMe: () => ({ user: { id: "usr_ada", theme: Theme.SYSTEM } }) });
    router.service(GatewayService, {
      listGatewayGroups: () => ({ gatewayGroups: [{ id: "ggr_eu", name: "eu" }] }),
      listGateways: () => ({ gateways: [{ id: "gtw_1", name: "gw-eu-1" }, { id: "gtw_2", name: "gw-eu-2" }] }),
    });
    router.service(ConnectorService, {
      listConnectors: () => ({ connectors: [{ id: "con_db", name: "db-host-1" }, { id: "con_app", name: "app-host" }] }),
      getConnectorStatus: (req) => ({ status: { dataSessions: (transports[req.connectorId] ?? []).map((transport) => ({ transport })) } }),
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
    });
  });
}

describe("RouteDetail", () => {
  it("shows the desired settings next to the observed state, and the gateways and agents that do not serve", async () => {
    detail(postgres);
    expect(await screen.findByRole("heading", { name: "Route postgres (TCP)" })).toBeTruthy();
    await waitFor(() => expect(screen.getByText("enabled · gateway group eu · :25432")).toBeTruthy());
    expect(screen.getByText("degraded")).toBeTruthy();
    expect(screen.getByText("served by 1 of 2 gateways")).toBeTruthy();
    expect((await screen.findByText(/^gw-eu-2/)).textContent).toBe("gw-eu-2: offline");
    expect(screen.getByText("gw-eu-1").parentElement?.textContent).toBe("gw-eu-1: port 25432 in use");
    expect(screen.queryByText(/UDP datagrams/)).toBeNull();
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

  it("flags a target served over the HTTP/2 fallback", async () => {
    detail(postgres, { con_app: [DataTransport.H2], con_db: [DataTransport.QUIC, DataTransport.H2] });
    expect(await screen.findByText("served over TLS and HTTP/2, the fallback for QUIC")).toBeTruthy();
    expect(screen.getAllByText(/the fallback for QUIC/)).toHaveLength(1); // con_db has a QUIC session too
    cleanup();
    detail({ ...postgres, transport: DataTransport.H2 }, { con_app: [DataTransport.H2] }); // pinned, not a fallback
    await screen.findByRole("heading", { name: "Route postgres (TCP)" });
    await waitFor(() => expect(screen.getAllByRole("row")).toHaveLength(3));
    expect(screen.queryByText(/the fallback for QUIC/)).toBeNull();
  });

  it("gives UDP routes the MTU hint", async () => {
    detail({ ...postgres, spec: { case: "udp", value: { port: 53 } } });
    expect(await screen.findByText(/^UDP datagrams travel as QUIC datagrams/)).toBeTruthy();
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
    detail(postgres, {}, traffic);
    const section = within(await screen.findByRole("region", { name: "Traffic" }));
    expect(await section.findByText("In 1 kB · out 5 B · 2 connections · 0 errors")).toBeTruthy();
    expect(section.getByRole("button", { name: "24 hours" }).getAttribute("aria-pressed")).toBe("true");
    fireEvent.click(section.getByRole("button", { name: "30 days" }));
    expect(await section.findByText("In 2 kB · out 5 B · 2 connections · 0 errors")).toBeTruthy();
    const spans = traffic.map((r) => [r.routeId, r.resolution, Number(r.to!.seconds - r.from!.seconds) / 3600]);
    expect(spans).toEqual([["rte_2", TrafficResolution.HOURLY, 24], ["rte_2", TrafficResolution.DAILY, 720]]);
    expect(traffic[0]!.to).toEqual(traffic[1]!.to);
  });
});

describe("allowCommand", () => {
  it.each([
    ["10.0.0.5:5432", "sudo rpmgr policy allow-target 10.0.0.5:5432"],
    ["[2001:db8::5]:5432", "sudo rpmgr policy allow-target [2001:db8::5]:5432"],
    ["/run/pg sock", "sudo rpmgr policy allow-target '/run/pg sock'"],
    ["/tmp/x';rm -rf /;'", "sudo rpmgr policy allow-target '/tmp/x'\\'';rm -rf /;'\\'''"],
  ])("%s", (target, want) => {
    expect(allowCommand(target)).toBe(want);
  });

  it("leaves plain words unquoted", () => {
    expect(shellArg("a-b_c.d")).toBe("a-b_c.d");
  });
});
