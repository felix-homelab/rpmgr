// SPDX-License-Identifier: Apache-2.0

import { timestampFromDate } from "@bufbuild/protobuf/wkt";
import { cleanup, screen, within } from "@testing-library/react";
import { afterEach, describe, expect, it } from "vitest";
import { covers } from "@/components/firewall";
import { FirewallState, GatewayService, PortProtocol } from "@/gen/rpmgr/v1/gateway_pb";
import { StatusService } from "@/gen/rpmgr/v1/status_pb";
import { Theme, UserService } from "@/gen/rpmgr/v1/user_pb";
import { auth, show } from "@/testing/api";

afterEach(cleanup);

const reported = timestampFromDate(new Date("2026-10-30T10:00:00Z"));

type Fake = { name: string; connected?: boolean; firewall?: { state?: FirewallState; reason?: string; rules?: string[]; refused?: string[] } };

// group renders the page of the group eu, whose gateways report the given firewall states, and
// whose pools are the TCP range 20000-20999 and the UDP range 30000-30099.
function group(gateways: Fake[]) {
  show("/gateways/ggr_eu", auth({
    getSession: () => ({ userId: "usr_ada", instanceAdmin: false, memberships: [{ orgId: "org_1", role: "admin" }] }),
  }), (router) => {
    router.service(UserService, { getMe: () => ({ user: { id: "usr_ada", theme: Theme.SYSTEM } }) });
    router.service(StatusService, { async *watchApplyStatus() {} });
    router.service(GatewayService, {
      listGatewayGroups: () => ({ gatewayGroups: [{ id: "ggr_eu", name: "eu" }] }),
      listGateways: () => ({ gateways: gateways.map((g, i) => ({ id: `gtw_${i}`, gatewayGroupId: "ggr_eu", name: g.name, slot: i + 1, enabled: true,
        status: { enrolled: true, connected: g.connected ?? true, firewall: g.firewall && { reportTime: reported, ...g.firewall } } })) }),
      listPortPools: () => ({ portPools: [
        { id: "pp_1", gatewayGroupId: "ggr_eu", protocol: PortProtocol.TCP, portFrom: 20000, portTo: 20999 },
        { id: "pp_2", gatewayGroupId: "ggr_eu", protocol: PortProtocol.UDP, portFrom: 30000, portTo: 30099 },
      ] }),
      listPortQuotas: () => ({ portQuotas: [] }),
    });
  });
}

// cells returns the text of the firewall cell of each gateway row.
async function firewallCells() {
  const table = await screen.findByRole("table");
  const col = within(table).getAllByRole("columnheader").findIndex((h) => h.textContent === "Firewall");
  expect(col).toBeGreaterThan(-1);
  return within(table).getAllByRole("row").slice(1).map((r) => within(r).getAllByRole("cell")[col]!.textContent);
}

describe("The firewall of a gateway host", () => {
  it("shows off, applied and failed with the reason and the refused ports", async () => {
    group([
      { name: "gw-off", firewall: { state: FirewallState.OFF, reason: "switched off; ufw is not installed" } },
      { name: "gw-ok", firewall: { state: FirewallState.APPLIED, rules: ["80/tcp", "443/tcp", "443/udp", "20000:20999/tcp"] } },
      { name: "gw-bad", firewall: { state: FirewallState.FAILED, reason: "ufw is inactive; nothing was changed", refused: ["22/tcp"] } },
    ]);
    expect(await firewallCells()).toEqual([
      "Offswitched off; ufw is not installed",
      "Applied4 rules",
      "Failedufw is inactive; nothing was changedRefused, outside the bounds: 22/tcp",
    ]);
  });

  it("shows a gateway that reports nothing as off, and an offline one as a dash", async () => {
    group([{ name: "gw-plain" }, { name: "gw-away", connected: false }, { name: "gw-new", firewall: { state: FirewallState.UNSPECIFIED } }]);
    expect(await firewallCells()).toEqual(["Off", "—", "Not reported"]);
  });

  it("shows a state this release does not know as not reported, not as a state it never had", async () => {
    group([{ name: "gw-future", firewall: { state: 99 as FirewallState } }]);
    expect(await firewallCells()).toEqual(["Not reported"]);
  });

  it("tells for each pool in how many managing gateways its range is open", async () => {
    group([
      // Pools may be adjacent, so the helper holds one merged rule: the pool is open when the rules cover it.
      { name: "gw-1", firewall: { state: FirewallState.APPLIED, rules: ["80/tcp", "20000:20499/tcp", "20500:20999/tcp", "30000:30099/udp"] } },
      { name: "gw-2", firewall: { state: FirewallState.FAILED, reason: "ufw is inactive", rules: ["20000:20499/tcp"] } },
      { name: "gw-3", firewall: { state: FirewallState.OFF } },
      { name: "gw-4" },
    ]);
    const pools = within(await screen.findByRole("region", { name: "Port pools" }));
    const rows = await pools.findAllByRole("listitem");
    expect(rows.map((r) => r.textContent?.replace(/(Edit…|Remove…)/g, ""))).toEqual([
      "TCP 20000–20999Open in the firewall of 1 of 2 gateways",
      "UDP 30000–30099Open in the firewall of 1 of 2 gateways",
    ]);
  });

  it("says nothing of the firewall for pools when no gateway manages one", async () => {
    group([{ name: "gw-1" }, { name: "gw-2", firewall: { state: FirewallState.OFF } }]);
    const pools = within(await screen.findByRole("region", { name: "Port pools" }));
    const rows = await pools.findAllByRole("listitem");
    expect(rows.some((r) => /firewall/.test(r.textContent ?? ""))).toBe(false);
  });
});

describe("covers", () => {
  it("reads the rules as ufw names them", () => {
    expect(covers(["80/tcp"], "tcp", 80, 80)).toBe(true);
    expect(covers(["80/tcp"], "udp", 80, 80)).toBe(false);
    expect(covers(["20000:20999/tcp"], "tcp", 20000, 20999)).toBe(true);
    expect(covers(["20000:20999/tcp"], "tcp", 20000, 21000)).toBe(false);
    expect(covers(["20001:20999/tcp"], "tcp", 20000, 20999)).toBe(false);
  });
  it("joins rules that touch or overlap, in any order, and not those with a gap", () => {
    expect(covers(["20500:20999/tcp", "20000:20499/tcp"], "tcp", 20000, 20999)).toBe(true);
    expect(covers(["20000:20600/tcp", "20500:20999/tcp"], "tcp", 20000, 20999)).toBe(true);
    expect(covers(["20000:20498/tcp", "20500:20999/tcp"], "tcp", 20000, 20999)).toBe(false);
  });
  it("ignores what is no rule of the helper", () => {
    expect(covers([], "tcp", 1, 1)).toBe(false);
    expect(covers(["Anywhere", "20000-20999/tcp", "::/0", "x:y/tcp", ""], "tcp", 20000, 20999)).toBe(false);
  });
});
