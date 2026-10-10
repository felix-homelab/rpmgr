// SPDX-License-Identifier: Apache-2.0

import { cleanup, fireEvent, screen, waitFor, within } from "@testing-library/react";
import { afterEach, describe, expect, it } from "vitest";
import { GatewayService } from "@/gen/rpmgr/v1/gateway_pb";
import { RouteService, RouteState, type ListRoutesRequest } from "@/gen/rpmgr/v1/route_pb";
import { Theme, UserService } from "@/gen/rpmgr/v1/user_pb";
import { auth, show } from "@/testing/api";

afterEach(cleanup);

const wiki = {
  id: "rte_1", name: "wiki", gatewayGroupId: "ggr_eu",
  spec: { case: "http" as const, value: { hostnames: ["wiki.example.com"], pathPrefix: "" } },
  status: { state: RouteState.READY, targetsTotal: 2, targetsReady: 2 },
};
const postgres = {
  id: "rte_2", name: "postgres", gatewayGroupId: "ggr_eu",
  spec: { case: "tcp" as const, value: { port: 25432 } },
  status: { state: RouteState.UNAVAILABLE, targetsTotal: 1, targetsReady: 0,
    notServing: [{ id: "tgt_1", reason: "BLOCKED_BY_LOCAL_POLICY", detail: "10.0.0.5:5432" }],
    rejections: [{ agentId: "con_1" }] },
};
const dns = {
  id: "rte_3", name: "dns", gatewayGroupId: "ggr_us",
  spec: { case: "udp" as const, value: { port: 53 } },
  status: { state: RouteState.DISABLED },
};

// routes renders path with the org's routes, served two to a page as the API pages them.
function routes(path: string, all: object[]) {
  const requests: ListRoutesRequest[] = [];
  const view = show(path, auth({
    getSession: () => ({ userId: "usr_ada", displayName: "Ada", memberships: [{ orgId: "org_1", role: "owner" }] }),
  }), (router) => {
    router.service(UserService, { getMe: () => ({ user: { id: "usr_ada", theme: Theme.SYSTEM } }) });
    router.service(GatewayService, {
      listGatewayGroups: () => ({ gatewayGroups: [{ id: "ggr_eu", name: "eu" }, { id: "ggr_us", name: "us" }] }),
    });
    router.service(RouteService, {
      listRoutes: (req) => {
        requests.push(req);
        const from = req.pageToken ? Number(req.pageToken) : 0;
        return { routes: all.slice(from, from + 2), nextPageToken: from + 2 < all.length ? String(from + 2) : "" };
      },
    });
  });
  return { ...view, requests };
}

async function rows() {
  const table = await screen.findByRole("table");
  return within(table).getAllByRole("row").slice(1).map((r) => r.textContent);
}

describe("Routes", () => {
  it("lists every route of every page, sorted by name, with its address, group, targets and state", async () => {
    const { requests } = routes("/routes", [wiki, postgres, dns]);
    await waitFor(async () => expect(await rows()).toHaveLength(3));
    expect(await rows()).toEqual([
      "dns:53UDPus0/0 ready○disabled", // the icons are hidden from screen readers
      "postgres:25432TCPeu0/1 ready1 blocked by local policy▲unavailablerejected by 1 agent",
      "wikiwiki.example.comHTTPeu2/2 ready●ready",
    ]);
    expect(requests.map((r) => [r.orgId, r.pageSize, r.pageToken])).toEqual([["org_1", 500, ""], ["org_1", 500, "2"]]);
    expect(screen.getByText("1–3 of 3")).toBeTruthy();
  });

  it("filters by text, type, state and group, keeping the filters in the URL", async () => {
    const { history } = routes("/routes?type=tcp", [wiki, postgres, dns]);
    await waitFor(async () => expect(await rows()).toEqual([expect.stringMatching(/^postgres/)]));
    fireEvent.change(screen.getByLabelText("Type"), { target: { value: "" } });
    fireEvent.change(screen.getByLabelText("Search"), { target: { value: "EXAMPLE.com" } });
    await waitFor(async () => expect(await rows()).toEqual([expect.stringMatching(/^wiki/)]));
    expect(new URLSearchParams(history.location.search).get("q")).toBe("EXAMPLE.com");
    fireEvent.change(screen.getByLabelText("Search"), { target: { value: "" } });
    fireEvent.change(screen.getByLabelText("Status"), { target: { value: "disabled" } });
    await waitFor(async () => expect(await rows()).toEqual([expect.stringMatching(/^dns/)]));
    fireEvent.change(screen.getByLabelText("Status"), { target: { value: "" } });
    fireEvent.change(screen.getByLabelText("Gateway group"), { target: { value: "ggr_eu" } });
    await waitFor(async () => expect(await rows()).toHaveLength(2));
    expect(new URLSearchParams(history.location.search).get("group")).toBe("ggr_eu");
  });

  it("shows 25 routes a page", async () => {
    const many = Array.from({ length: 30 }, (_, i) => ({ ...wiki, id: `rte_${i}`, name: `r${String(i).padStart(2, "0")}` }));
    const { history } = routes("/routes", many);
    expect(await screen.findByText("1–25 of 30")).toBeTruthy();
    expect(screen.getByRole("button", { name: "Previous" })).toHaveProperty("disabled", true);
    fireEvent.click(screen.getByRole("button", { name: "Next" }));
    expect(await screen.findByText("26–30 of 30")).toBeTruthy();
    expect(new URLSearchParams(history.location.search).get("page")).toBe("2");
    expect((await rows())[0]).toMatch(/^r25/);
    expect(screen.getByRole("button", { name: "Next" })).toHaveProperty("disabled", true);
  });
});
