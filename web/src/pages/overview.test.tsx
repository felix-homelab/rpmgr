// SPDX-License-Identifier: Apache-2.0

import type { MessageInitShape } from "@bufbuild/protobuf";
import { timestampFromDate } from "@bufbuild/protobuf/wkt";
import { Code } from "@connectrpc/connect";
import { cleanup, fireEvent, screen, within } from "@testing-library/react";
import { afterEach, describe, expect, it } from "vitest";
import { MetricsService, type GetOverviewRequest, type GetOverviewResponseSchema } from "@/gen/rpmgr/v1/metrics_pb";
import { RouteService } from "@/gen/rpmgr/v1/route_pb";
import { Theme, UserService } from "@/gen/rpmgr/v1/user_pb";
import { apiError, auth, show } from "@/testing/api";

afterEach(cleanup);

function page(answer: () => MessageInitShape<typeof GetOverviewResponseSchema>) {
  const asked: GetOverviewRequest[] = [];
  const view = show("/", auth({
    getSession: () => ({ userId: "usr_ada", displayName: "Ada", memberships: [{ orgId: "org_1", role: "viewer" }] }),
  }), (router) => {
    router.service(UserService, { getMe: () => ({ user: { id: "usr_ada", theme: Theme.SYSTEM } }) });
    router.service(RouteService, { listRoutes: () => ({ routes: [{ id: "rte_1", name: "web" }, { id: "rte_2", name: "postgres" }] }) });
    router.service(MetricsService, { getOverview: (req) => (asked.push(req), answer()) });
  });
  return { ...view, asked };
}

const at = (iso: string) => timestampFromDate(new Date(iso));

describe("Overview", () => {
  it("summarises the org's last 24 hours and links its busiest routes by name", async () => {
    const { asked } = page(() => ({
      hours: [
        { start: at("2026-10-09T10:00:00Z"), bytesIn: 1_200_000_000n, bytesOut: 300_000n, connections: 40n },
        { start: at("2026-10-09T11:00:00Z"), bytesIn: 0n, bytesOut: 10_000_000n, connections: 2n, errors: 1n },
      ],
      total: { start: at("2026-10-08T12:00:00Z"), bytesIn: 1_200_000_000n, bytesOut: 10_300_000n, connections: 42n, errors: 1n },
      busiestRoutes: [
        { routeId: "rte_2", total: { bytesIn: 1_100_000_000n, bytesOut: 300_000n } },
        { routeId: "rte_9", total: { bytesIn: 5_000n } },
      ],
    }));
    const traffic = within(await screen.findByRole("region", { name: "Traffic, last 24 hours" }));
    expect(await traffic.findByText("In 1.2 GB · out 10.3 MB · 42 connections · 1 error")).toBeTruthy();
    const busiest = within(traffic.getByRole("list", { name: "Busiest routes" })).getAllByRole("listitem");
    await within(busiest[0]!).findByText("postgres");
    expect(busiest.map((li) => li.textContent)).toEqual(["postgresin 1.1 GB · out 300 kB", "rte_9in 5 kB · out 0 B"]);
    expect(within(busiest[0]!).getByRole("link").getAttribute("href")).toBe("/routes/rte_2");
    expect(asked.map((r) => r.orgId)).toEqual(["org_1"]);
    const details = traffic.getByText("Show the values as a table").closest("details")!;
    details.open = true;
    fireEvent(details, new Event("toggle"));
    const rows = within(traffic.getByRole("table")).getAllByRole("row").slice(1).map((r) => within(r).getAllByRole("cell")[1]!.textContent);
    expect(rows).toHaveLength(24);
    expect(rows.slice(21)).toEqual(["0 B", "1.2 GB", "0 B"]); // 09:00, 10:00 and 11:00 UTC
  });

  it("says when no route had traffic", async () => {
    page(() => ({ hours: [], busiestRoutes: [] }));
    const traffic = within(await screen.findByRole("region", { name: "Traffic, last 24 hours" }));
    expect(await traffic.findByText("No route had traffic.")).toBeTruthy();
    expect(traffic.getByText("No traffic in this period.")).toBeTruthy();
    expect(traffic.getByText("In 0 B · out 0 B · 0 connections · 0 errors")).toBeTruthy();
  });

  it("shows why the traffic could not be read", async () => {
    page(() => {
      throw apiError(Code.Unavailable);
    });
    const traffic = within(await screen.findByRole("region", { name: "Traffic, last 24 hours" }));
    expect((await traffic.findByRole("alert")).textContent).toBe("api error");
  });
});
