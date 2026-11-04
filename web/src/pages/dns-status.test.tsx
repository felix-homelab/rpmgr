// SPDX-License-Identifier: Apache-2.0

import { Code } from "@connectrpc/connect";
import { cleanup, fireEvent, screen, waitFor, within } from "@testing-library/react";
import { afterEach, describe, expect, it } from "vitest";
import { DnsNameService, DnsRecordState, DnsZoneService, ZoneProviderStatus, ZoneSyncState, type CreateDnsNameRequest, type DeleteDnsNameRequest } from "@/gen/rpmgr/v1/dns_pb";
import { GatewayService } from "@/gen/rpmgr/v1/gateway_pb";
import { RouteService } from "@/gen/rpmgr/v1/route_pb";
import { Theme, UserService } from "@/gen/rpmgr/v1/user_pb";
import { apiError, auth, show } from "@/testing/api";

afterEach(cleanup);

const route = (dnsStatus: object[]) => ({
  id: "rte_1", name: "wiki", gatewayGroupId: "ggr_eu", enabled: true, spec: { case: "http" as const, value: {} }, targets: [], status: { state: 2 }, dnsStatus,
});

function detail(dnsStatus: object[]) {
  show("/routes/rte_1", auth({ getSession: () => ({ userId: "usr_ada", memberships: [{ orgId: "org_1", role: "owner" }] }) }), (router) => {
    router.service(UserService, { getMe: () => ({ user: { id: "usr_ada", theme: Theme.SYSTEM } }) });
    router.service(GatewayService, { listGatewayGroups: () => ({ gatewayGroups: [{ id: "ggr_eu", name: "eu" }] }), listGateways: () => ({ gateways: [] }) });
    router.service(RouteService, { getRoute: () => ({ route: route(dnsStatus) }) });
  });
}

describe("Route detail: the DNS line (U4)", () => {
  it("shows each hostname's status and the records published for it", async () => {
    detail([{ hostname: "wiki.example.com", status: "published", records: ["CNAME eu.gw.example.net"] }]);
    const card = within(await screen.findByRole("region", { name: "DNS" }));
    expect(card.getByText("wiki.example.com")).toBeTruthy();
    expect(card.getByText("published")).toBeTruthy();
    expect(card.getByText("CNAME eu.gw.example.net")).toBeTruthy();
    expect(card.queryByText(/Adopt it/)).toBeNull();
  });

  it("says what to do about a conflict and links to the zones", async () => {
    detail([{ hostname: "grafana.example.com", status: "conflict" }]);
    const card = within(await screen.findByRole("region", { name: "DNS" }));
    expect(card.getByText("conflict")).toBeTruthy();
    expect(card.getByText(/A record that rpmgr does not own occupies this name\. Adopt it on the zone page, or remove it at the provider\./)).toBeTruthy();
    expect(card.getByRole("link", { name: "Open the zones." }).getAttribute("href")).toBe("/dns");
  });

  it("says what to do about an ambiguous name and links to the DNS names", async () => {
    detail([{ hostname: "app.example.com", status: "ambiguous" }]);
    const card = within(await screen.findByRole("region", { name: "DNS" }));
    expect(card.getByText(/Two gateway groups claim this name and no DNS name decides\. Create a DNS name for it/)).toBeTruthy();
    expect(card.getByRole("link", { name: "Open the DNS names." }).getAttribute("href")).toBe("/dns-names");
  });

  it("gives the reason a name is not managed, and the provider's reason for an error", async () => {
    detail([
      { hostname: "a.example.com", status: "not_managed", reason: "no_target" },
      { hostname: "b.example.com", status: "not_managed", reason: "not_verified" },
      { hostname: "c.example.com", status: "not_managed" },
      { hostname: "d.example.com", status: "error", reason: "the token was refused" },
      { hostname: "e.example.com", status: "held" },
      { hostname: "f.example.com", status: "rate_limited" },
      { hostname: "g.example.com", status: "pending" },
      { hostname: "h.example.com", status: "something-new" },
    ]);
    const card = within(await screen.findByRole("region", { name: "DNS" }));
    expect(card.getByText(/The gateway group has no DNS target/)).toBeTruthy();
    expect(card.getByRole("link", { name: "Open the gateway groups." })).toBeTruthy();
    expect(card.getByText(/No verified domain of the org covers this name/)).toBeTruthy();
    expect(card.getByText("the token was refused")).toBeTruthy();
    expect(card.getByText(/The provider refused the change/)).toBeTruthy();
    expect(card.getByText(/The zone is held, or a gate holds this name/)).toBeTruthy();
    expect(card.getByText(/The provider limits requests/)).toBeTruthy();
    expect(card.getByText(/waits for the next DNS pass/)).toBeTruthy();
    // A status the UI does not know is shown as it is.
    expect(card.getByText("something-new")).toBeTruthy();
    // A name that is not managed for no known reason has no hint.
    expect(within(card.getByText("c.example.com").closest("li")!).queryByText(/\./, { selector: "span.text-muted-foreground" })).toBeNull();
  });

  it("shows no DNS card for a route without DNS status", async () => {
    detail([]);
    await screen.findByRole("heading", { name: /wiki/ });
    expect(screen.queryByRole("region", { name: "DNS" })).toBeNull();
  });
});

const groups = [{ id: "ggr_eu", name: "eu" }, { id: "ggr_us", name: "us" }];
const names = [
  { id: "dnn_1", fqdn: "status.example.com", gatewayGroupId: "ggr_eu", ttl: 0, etag: "1" },
  { id: "dnn_2", fqdn: "*.apps.example.com", gatewayGroupId: "ggr_us", ttl: 120, etag: "4" },
];

function namesPage(role = "owner", refuse?: Error) {
  const calls = { create: [] as CreateDnsNameRequest[], remove: [] as DeleteDnsNameRequest[] };
  show("/dns-names", auth({ getSession: () => ({ userId: "usr_ada", memberships: [{ orgId: "org_1", role }] }) }), (router) => {
    router.service(UserService, { getMe: () => ({ user: { id: "usr_ada", theme: Theme.SYSTEM } }) });
    router.service(GatewayService, { listGatewayGroups: () => ({ gatewayGroups: groups }), listGateways: () => ({ gateways: [] }) });
    router.service(DnsNameService, {
      listDnsNames: () => ({ dnsNames: names }),
      createDnsName: (req) => {
        if (refuse) {
          throw refuse;
        }
        calls.create.push(req);
        return { dnsName: req.dnsName };
      },
      deleteDnsName: (req) => (calls.remove.push(req), {}),
    });
  });
  return calls;
}

describe("DNS names", () => {
  it("lists the names with their group, TTL and a mark on wildcards", async () => {
    namesPage();
    const status = within((await screen.findByText("status.example.com")).closest("li")!);
    expect(status.getByText("points at eu")).toBeTruthy();
    expect(status.getByText("TTL of the zone")).toBeTruthy();
    expect(status.queryByText("wildcard")).toBeNull();
    const wild = within(screen.getByText("*.apps.example.com").closest("li")!);
    expect(wild.getByText("wildcard")).toBeTruthy();
    expect(wild.getByText("points at us")).toBeTruthy();
    expect(wild.getByText("TTL 120 s")).toBeTruthy();
  });

  it("creates a name for a group, in lower case and without the final dot, and a wildcard", async () => {
    const calls = namesPage();
    fireEvent.click(await screen.findByRole("button", { name: "Add a name" }));
    const form = within(await screen.findByRole("form", { name: "Add a DNS name" }));
    fireEvent.change(form.getByLabelText("Name"), { target: { value: "*.Dev.Example.com." } });
    fireEvent.change(form.getByLabelText("Gateway group"), { target: { value: "ggr_us" } });
    fireEvent.change(form.getByLabelText("TTL in seconds"), { target: { value: "300" } });
    fireEvent.click(form.getByRole("button", { name: "Add it" }));
    await waitFor(() => expect(calls.create).toHaveLength(1));
    const c = calls.create[0]!;
    expect([c.orgId, c.dnsName?.fqdn, c.dnsName?.gatewayGroupId, c.dnsName?.ttl]).toEqual(["org_1", "*.dev.example.com", "ggr_us", 300]);
    expect(c.requestId).toMatch(/^[0-9a-f-]{36}$/);
  });

  it("refuses a bad name, a missing group and a bad TTL before sending anything", async () => {
    const calls = namesPage();
    fireEvent.click(await screen.findByRole("button", { name: "Add a name" }));
    const form = within(await screen.findByRole("form", { name: "Add a DNS name" }));
    fireEvent.click(form.getByRole("button", { name: "Add it" }));
    expect(await form.findByText("Enter a name.")).toBeTruthy();
    expect(form.getByText("Choose the gateway group the name points at.")).toBeTruthy();
    fireEvent.change(form.getByLabelText("Name"), { target: { value: "a.*.example.com" } });
    fireEvent.change(form.getByLabelText("Gateway group"), { target: { value: "ggr_eu" } });
    fireEvent.change(form.getByLabelText("TTL in seconds"), { target: { value: "-5" } });
    fireEvent.click(form.getByRole("button", { name: "Add it" }));
    expect(await form.findByText("Use * only as the whole first label, as in *.example.com.")).toBeTruthy();
    expect(form.getByText("Use a whole number of seconds, or leave it empty.")).toBeTruthy();
    expect(calls.create).toHaveLength(0);
  });

  it("shows the API's refusal, such as a name outside the verified domains", async () => {
    namesPage("owner", apiError(Code.FailedPrecondition));
    fireEvent.click(await screen.findByRole("button", { name: "Add a name" }));
    const form = within(await screen.findByRole("form", { name: "Add a DNS name" }));
    fireEvent.change(form.getByLabelText("Name"), { target: { value: "x.other.example" } });
    fireEvent.change(form.getByLabelText("Gateway group"), { target: { value: "ggr_eu" } });
    fireEvent.click(form.getByRole("button", { name: "Add it" }));
    expect(await form.findByRole("alert")).toBeTruthy();
  });

  it("deletes a name after a confirmation that names it", async () => {
    const calls = namesPage();
    const row = within((await screen.findByText("*.apps.example.com")).closest("li")!);
    fireEvent.click(row.getByRole("button", { name: "Delete…" }));
    expect(row.getByText("Delete *.apps.example.com? The records published for it go with it.")).toBeTruthy();
    expect(calls.remove).toHaveLength(0);
    fireEvent.click(row.getByRole("button", { name: "Delete it" }));
    await waitFor(() => expect(calls.remove.map((r) => [r.dnsNameId, r.etag])).toEqual([["dnn_2", "4"]]));
  });

  it("shows a Viewer the names and no way to change them", async () => {
    namesPage("viewer");
    await screen.findByText("status.example.com");
    expect(screen.queryByRole("button", { name: "Add a name" })).toBeNull();
    expect(screen.queryByRole("button", { name: "Delete…" })).toBeNull();
  });
});

function overview(role: string, opts: { routes?: object[]; zones?: object[]; records?: object[]; zonesRefused?: boolean } = {}) {
  const asked = { zones: 0, records: 0 };
  show("/", auth({ getSession: () => ({ userId: "usr_ada", memberships: [{ orgId: "org_1", role }] }) }), (router) => {
    router.service(UserService, { getMe: () => ({ user: { id: "usr_ada", theme: Theme.SYSTEM } }) });
    router.service(RouteService, { listRoutes: () => ({ routes: opts.routes ?? [] }) });
    router.service(DnsZoneService, {
      listZones: () => {
        asked.zones++;
        if (opts.zonesRefused) {
          throw apiError(Code.Unimplemented);
        }
        return { dnsZones: opts.zones ?? [] };
      },
      listZoneRecords: () => (asked.records++, { records: opts.records ?? [] }),
    });
  });
  return asked;
}

const area = async () => within(await screen.findByRole("region", { name: "DNS" }));

describe("Overview: DNS needs attention", () => {
  const problems = [
    route([
      { hostname: "grafana.example.com", status: "conflict" },
      { hostname: "app.example.com", status: "ambiguous" },
      { hostname: "ok.example.com", status: "published" },
      { hostname: "held.example.com", status: "held" },
    ]),
  ];

  it("lists conflicts and ambiguous names with their hints for any member", async () => {
    const asked = overview("viewer", { routes: problems });
    const dns = await area();
    await dns.findByText("grafana.example.com");
    expect(dns.getByText("has a DNS conflict")).toBeTruthy();
    expect(dns.getByText(/Adopt it on the zone page/)).toBeTruthy();
    expect(dns.getByText("is claimed by two gateway groups")).toBeTruthy();
    expect(dns.getByText(/Create a DNS name for it/)).toBeTruthy();
    // A published name and a held one are not problems of a route.
    expect(dns.queryByText("ok.example.com")).toBeNull();
    expect(dns.queryByText("held.example.com")).toBeNull();
    // The zones are for Owners and Admins.
    expect(asked.zones).toBe(0);
  });

  it("lists held zones, rate limits, refused tokens and drifted records for an Owner", async () => {
    const asked = overview("owner", {
      zones: [
        { id: "dnz_1", name: "example.com", syncState: ZoneSyncState.HELD, providerStatus: ZoneProviderStatus.OK },
        { id: "dnz_2", name: "example.net", syncState: ZoneSyncState.ACTIVE, providerStatus: ZoneProviderStatus.RATE_LIMITED },
        { id: "dnz_3", name: "example.org", syncState: ZoneSyncState.ACTIVE, providerStatus: ZoneProviderStatus.PERMISSION_DENIED },
      ],
      records: [{ id: "dnr_1", name: "app.example.com", type: "A", state: DnsRecordState.DRIFTED, reason: "changed twice" }, { id: "dnr_2", name: "ok.example.com", state: DnsRecordState.SYNCED }],
    });
    const dns = await area();
    await dns.findByText("is held");
    expect(dns.getByText(/Review the zone's plan and approve it/)).toBeTruthy();
    expect(dns.getByText("is rate limited by the provider")).toBeTruthy();
    expect(dns.getByText("is refused by the provider")).toBeTruthy();
    expect(dns.getByText(/Give the token the zone's DNS edit permission/)).toBeTruthy();
    expect((await dns.findAllByText("keeps being changed at the provider")).length).toBeGreaterThan(0);
    expect(dns.getAllByText(/changed twice/).length).toBeGreaterThan(0);
    expect(dns.queryByText("ok.example.com")).toBeNull();
    expect(asked.zones).toBeGreaterThan(0);
  });

  it("says nothing needs attention, and is not troubled by an instance that serves no DNS", async () => {
    overview("owner", { zonesRefused: true });
    const dns = await area();
    expect(await dns.findByText("No hostname has a DNS conflict, and no zone needs attention.")).toBeTruthy();
    expect(dns.queryByRole("alert")).toBeNull();
  });
});
