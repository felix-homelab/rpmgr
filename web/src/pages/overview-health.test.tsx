// SPDX-License-Identifier: Apache-2.0

import { timestampFromMs } from "@bufbuild/protobuf/wkt";
import { cleanup, screen, waitFor, within } from "@testing-library/react";
import { afterEach, describe, expect, it } from "vitest";
import { CertificateService, CertificateStatus } from "@/gen/rpmgr/v1/certificate_pb";
import { ConnectorService } from "@/gen/rpmgr/v1/connector_pb";
import { DomainService, DomainStatus } from "@/gen/rpmgr/v1/domain_pb";
import { GatewayService } from "@/gen/rpmgr/v1/gateway_pb";
import { RouteService, RouteState } from "@/gen/rpmgr/v1/route_pb";
import { TokenService } from "@/gen/rpmgr/v1/token_pb";
import { Theme, UserService } from "@/gen/rpmgr/v1/user_pb";
import { auth, show } from "@/testing/api";

afterEach(cleanup);

const day = 86400_000;
const inDays = (n: number) => timestampFromMs(Date.now() + n * day);

interface Fleet {
  connectors?: object[];
  gateways?: object[];
  routes?: object[];
  certificates?: object[];
  domains?: object[];
  tokens?: object[];
}

function page(f: Fleet) {
  return show("/", auth({
    getSession: () => ({ userId: "usr_ada", displayName: "Ada", memberships: [{ orgId: "org_1", role: "viewer" }] }),
  }), (router) => {
    router.service(UserService, { getMe: () => ({ user: { id: "usr_ada", theme: Theme.SYSTEM } }) });
    router.service(ConnectorService, { listConnectors: () => ({ connectors: f.connectors ?? [] }) });
    router.service(GatewayService, { listGateways: () => ({ gateways: f.gateways ?? [] }) });
    router.service(RouteService, { listRoutes: () => ({ routes: f.routes ?? [] }) });
    router.service(CertificateService, { listCertificates: () => ({ certificates: f.certificates ?? [] }) });
    router.service(DomainService, { listDomains: () => ({ domains: f.domains ?? [] }) });
    router.service(TokenService, { listAPITokens: () => ({ apiTokens: f.tokens ?? [] }) });
  });
}

// card returns the health card of the given title, once its data has arrived.
async function card(title: string) {
  const region = await screen.findByRole("region", { name: title });
  return within(region);
}

const items = (c: ReturnType<typeof within>) => c.getAllByRole("listitem").map((li: HTMLElement) => li.textContent);

describe("Health", () => {
  it("lists the agents without a control session, with when they were last seen", async () => {
    page({
      gateways: [
        { id: "gtw_1", gatewayGroupId: "ggr_eu", name: "gw-eu-1", status: { enrolled: true, connected: true } },
        { id: "gtw_2", gatewayGroupId: "ggr_eu", name: "gw-eu-2", status: { enrolled: true, connected: false, lastSeenTime: timestampFromMs(Date.UTC(2026, 9, 8, 12)) } },
        { id: "gtw_3", gatewayGroupId: "ggr_us", name: "gw-us-1", status: { enrolled: false } },
      ],
      connectors: [
        { id: "con_1", name: "db-host", session: { connected: true } },
        { id: "con_2", name: "laptop" },
        { id: "con_3", name: "old", decommissionTime: inDays(-1) },
      ],
    });
    const agents = await card("Agents");
    await waitFor(() => expect(agents.getByText("Gateways: 1 of 3 connected · connectors: 1 of 2 connected")).toBeTruthy());
    expect(items(agents)).toEqual([expect.stringMatching(/^gw-eu-2last seen Oct 8, 2026/), "gw-us-1not enrolled yet", "laptopnever connected"]);
    expect(agents.getByRole("link", { name: "gw-us-1" }).getAttribute("href")).toBe("/gateways/ggr_us");
    expect(agents.getByRole("link", { name: "laptop" }).getAttribute("href")).toBe("/connectors/con_2");
  });

  it("lists routes that do not serve fully or that agents rejected, but not disabled ones", async () => {
    page({
      routes: [
        { id: "rte_1", name: "web", status: { state: RouteState.READY } },
        { id: "rte_2", name: "postgres", status: { state: RouteState.DEGRADED } },
        { id: "rte_3", name: "old", status: { state: RouteState.DISABLED } },
        { id: "rte_4", name: "new", status: { state: RouteState.PENDING } },
        { id: "rte_5", name: "api", status: { state: RouteState.READY, rejections: [{ agentId: "gtw_1" }, { agentId: "gtw_2" }] } },
      ],
    });
    const routes = await card("Routes");
    await waitFor(() => expect(routes.getAllByRole("listitem")).toHaveLength(3));
    expect(items(routes)).toEqual(["postgres◐degraded", "new⧗pending", "api●readyrejected by 2 agents"]);
  });

  it("points out failed certificates and those that expire within 21 days", async () => {
    page({
      certificates: [
        { id: "crt_1", sans: ["www.example.com"], status: CertificateStatus.ACTIVE, notAfter: inDays(60) },
        { id: "crt_2", sans: ["api.example.com"], status: CertificateStatus.ACTIVE, notAfter: inDays(20) },
        { id: "crt_3", sans: ["shop.example.com"], status: CertificateStatus.FAILED, lastError: "rate limited" },
        { id: "crt_4", sans: ["late.example.com"], status: CertificateStatus.ACTIVE, notAfter: inDays(22) },
      ],
    });
    const certs = await card("Certificates");
    await waitFor(() => expect(certs.getAllByRole("listitem")).toHaveLength(2));
    expect(items(certs)).toEqual([expect.stringMatching(/^api\.example\.comexpires /), "shop.example.comfailed: rate limited"]);
  });

  it("lists unverified domains and the user's API tokens that expire soon or have expired", async () => {
    page({
      domains: [
        { id: "dom_1", fqdn: "example.com", status: DomainStatus.VERIFIED },
        { id: "dom_2", fqdn: "example.net", wildcard: true, status: DomainStatus.PENDING },
        { id: "dom_3", fqdn: "example.org", status: DomainStatus.FAILED },
      ],
      tokens: [
        { id: "tok_1", name: "ci", expireTime: inDays(3) },
        { id: "tok_2", name: "backup", expireTime: inDays(-2) },
        { id: "tok_3", name: "long", expireTime: inDays(90) },
      ],
    });
    const domains = await card("Domains");
    await waitFor(() => expect(domains.getAllByRole("listitem")).toHaveLength(2));
    expect(items(domains)).toEqual(["*.example.net⧗ pending", "example.org✕ failed"]);
    const tokens = await card("Your API tokens");
    await waitFor(() => expect(tokens.getAllByRole("listitem")).toHaveLength(2));
    expect(items(tokens)).toEqual([expect.stringMatching(/^ciexpires /), expect.stringMatching(/^backupexpired /)]);
  });

  it("says when nothing needs attention", async () => {
    page({
      gateways: [{ id: "gtw_1", gatewayGroupId: "ggr_eu", name: "gw-eu-1", status: { enrolled: true, connected: true } }],
      routes: [{ id: "rte_1", name: "web", status: { state: RouteState.READY } }, { id: "rte_2", name: "old", status: { state: RouteState.DISABLED } }],
    });
    expect(await (await card("Agents")).findByText("Every agent holds a control session.")).toBeTruthy();
    expect(await (await card("Routes")).findByText("All 2 routes serve fully, or are disabled.")).toBeTruthy();
    expect((await card("Certificates")).getByText("No certificate failed or expires within 21 days.")).toBeTruthy();
    expect((await card("Domains")).getByText("Every domain is verified.")).toBeTruthy();
    expect((await card("Your API tokens")).getByText("None of your API tokens expires within 21 days.")).toBeTruthy();
  });
});
