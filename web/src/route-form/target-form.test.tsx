// SPDX-License-Identifier: Apache-2.0

import { clone, create, equals } from "@bufbuild/protobuf";
import { Code, ConnectError } from "@connectrpc/connect";
import { cleanup, fireEvent, screen, waitFor, within } from "@testing-library/react";
import { afterEach, describe, expect, it } from "vitest";
import { ConnectorService } from "@/gen/rpmgr/v1/connector_pb";
import { GatewayService } from "@/gen/rpmgr/v1/gateway_pb";
import {
  ProxyProtocol, RouteService, RouteState, RouteTargetSchema, UpstreamProtocol, UpstreamTLSSettingsSchema, UpstreamVerification,
  type CreateRouteTargetRequest, type DeleteRouteTargetRequest, type ProbeTargetCertificateRequest, type UpdateRouteTargetRequest,
} from "@/gen/rpmgr/v1/route_pb";
import { ApplyState, StatusService } from "@/gen/rpmgr/v1/status_pb";
import { Theme, UserService } from "@/gen/rpmgr/v1/user_pb";
import { PINNED, targetMask, UNVERIFIED } from "@/route-form/target-form";
import { auth, show } from "@/testing/api";
import { marked, unmatched } from "@/testing/required";

afterEach(cleanup);

const target = create(RouteTargetSchema, {
  id: "tgt_1", connectorId: "con_db", enabled: true, weight: 100, priority: 2, etag: "3", upstreamProtocol: UpstreamProtocol.HTTP,
  address: { case: "hostPort", value: { host: "10.0.0.5", port: 8080 } },
});
const applied = { revision: { dbEpoch: "e", seq: 11n }, applyStatus: { state: ApplyState.APPLIED, agentsTotal: 1, agentsApplied: 1 } };

// detail renders the detail of a route of type case with targets, by default the target above;
// ProbeTargetCertificate answers with probe, if given.
function detail(spec: { case: "http" | "tcp" | "udp" | "tcpUdp" | "tlsPassthrough"; value: object }, targets = [target], probe?: () => object) {
  const probes: ProbeTargetCertificateRequest[] = [];
  const creates: CreateRouteTargetRequest[] = [];
  const updates: UpdateRouteTargetRequest[] = [];
  const deletes: DeleteRouteTargetRequest[] = [];
  const route = { id: "rte_1", name: "app", gatewayGroupId: "ggr_eu", enabled: true, etag: "7", spec, targets,
    status: { state: RouteState.READY, targetsTotal: 1, targetsReady: 1 } };
  show("/routes/rte_1", auth({ getSession: () => ({ userId: "usr_ada", memberships: [{ orgId: "org_1", role: "owner" }] }) }), (router) => {
    router.service(UserService, { getMe: () => ({ user: { id: "usr_ada", theme: Theme.SYSTEM } }) });
    router.service(GatewayService, { listGatewayGroups: () => ({}), listGateways: () => ({}) });
    router.service(ConnectorService, {
      listConnectors: () => ({ connectors: [{ id: "con_db", name: "db-host-1" }, { id: "con_app", name: "app-host" }] }),
      getConnectorStatus: () => ({}),
    });
    router.service(StatusService, { async *watchApplyStatus() {} });
    router.service(RouteService, {
      getRoute: () => ({ route }),
      createRouteTarget: (req) => (creates.push(req), { target: req.target, ...applied }),
      updateRouteTarget: (req) => (updates.push(req), { target: req.target, ...applied }),
      deleteRouteTarget: (req) => (deletes.push(req), applied),
      probeTargetCertificate: (req) => (probes.push(req), probe ? probe() : {}),
    });
  });
  return { creates, updates, deletes, probes };
}

async function form(name: string) {
  return within(await screen.findByRole("form", { name }));
}

describe("targets", () => {
  it("adds a target to a TCP route, with a PROXY header", async () => {
    const { creates } = detail({ case: "tcp", value: { port: 25432 } });
    fireEvent.click(await screen.findByRole("button", { name: "Add a target" }));
    const f = await form("New target");
    await f.findByRole("option", { name: "app-host" });
    fireEvent.click(f.getByRole("button", { name: "Add the target" }));
    expect(await f.findByText("Choose the connector that reaches the target.")).toBeTruthy();
    expect(creates).toEqual([]);
    fireEvent.change(f.getByLabelText("Connector"), { target: { value: "con_app" } });
    fireEvent.change(f.getByLabelText("Host"), { target: { value: " 10.0.0.6 " } });
    fireEvent.change(f.getByLabelText("Port"), { target: { value: "5432" } });
    fireEvent.change(f.getByLabelText("PROXY protocol"), { target: { value: String(ProxyProtocol.V2) } });
    fireEvent.click(f.getByRole("button", { name: "Add the target" }));
    expect(await screen.findByText("Revision 11: applied by all 1 agents.")).toBeTruthy();
    const t = creates[0]!.target!;
    expect([creates[0]!.routeId, t.connectorId, t.address, t.upstreamProtocol, t.proxyProtocol, t.weight, t.enabled])
      .toEqual(["rte_1", "con_app", { case: "hostPort", value: expect.objectContaining({ host: "10.0.0.6", port: 5432 }) }, UpstreamProtocol.TCP, ProxyProtocol.V2, 100, true]);
    expect(creates[0]!.requestId).toMatch(/^[0-9a-f-]{36}$/);
  });

  it("asks for the protocol to the target only on HTTP routes (#509)", async () => {
    detail({ case: "http", value: { hostnames: ["app.example.com"] } });
    fireEvent.click(await screen.findByRole("button", { name: "Add a target" }));
    const options = within((await form("New target")).getByLabelText("Protocol to the target")).getAllByRole("option");
    expect(options.map((o) => o.textContent)).toEqual(["HTTP", "HTTPS, verified", "HTTPS, pinned key", "HTTPS, unverified", "HTTP/2 without TLS (h2c)"]);
    for (const spec of [{ case: "tcp", value: { port: 25432 } }, { case: "tlsPassthrough", value: { hostnames: ["db.example.com"] } }] as const) {
      cleanup();
      detail(spec);
      fireEvent.click(await screen.findByRole("button", { name: "Add a target" }));
      expect((await form("New target")).queryByLabelText("Protocol to the target")).toBeNull();
    }
  });

  it("adds a target to a UDP route without naming a protocol, and sends its datagrams as they come", async () => {
    const { creates } = detail({ case: "udp", value: { port: 5353 } });
    fireEvent.click(await screen.findByRole("button", { name: "Add a target" }));
    const f = await form("New target");
    expect(f.queryByLabelText("Protocol to the target")).toBeNull();
    expect(f.queryByLabelText("PROXY protocol")).toBeNull();
    expect(f.queryByText("TCP")).toBeNull();
    await f.findByRole("option", { name: "app-host" });
    fireEvent.change(f.getByLabelText("Connector"), { target: { value: "con_app" } });
    fireEvent.change(f.getByLabelText("Host"), { target: { value: "10.0.0.7" } });
    fireEvent.change(f.getByLabelText("Port"), { target: { value: "53" } });
    fireEvent.click(f.getByRole("button", { name: "Add the target" }));
    expect(await screen.findByText("Revision 11: applied by all 1 agents.")).toBeTruthy();
    expect([creates[0]!.target!.upstreamProtocol, creates[0]!.target!.proxyProtocol]).toEqual([UpstreamProtocol.TCP, ProxyProtocol.UNSPECIFIED]);
  });

  it("offers a PROXY header on a TCP and UDP route, for its TCP connections only (D86)", async () => {
    const { creates } = detail({ case: "tcpUdp", value: { port: 5353 } });
    fireEvent.click(await screen.findByRole("button", { name: "Add a target" }));
    const f = await form("New target");
    expect(f.queryByLabelText("Protocol to the target")).toBeNull();
    const proxy = f.getByLabelText("PROXY protocol");
    expect(within(proxy).getAllByRole("option").map((o) => o.textContent)).toEqual(["None", "Version 1", "Version 2"]);
    const hint = f.getByText("TCP connections only; UDP datagrams get no header.");
    expect(proxy.getAttribute("aria-describedby")).toBe(hint.id);
    await f.findByRole("option", { name: "app-host" });
    fireEvent.change(f.getByLabelText("Connector"), { target: { value: "con_app" } });
    fireEvent.change(f.getByLabelText("Host"), { target: { value: "10.0.0.7" } });
    fireEvent.change(f.getByLabelText("Port"), { target: { value: "53" } });
    fireEvent.change(proxy, { target: { value: String(ProxyProtocol.V1) } });
    fireEvent.click(f.getByRole("button", { name: "Add the target" }));
    expect(await screen.findByText("Revision 11: applied by all 1 agents.")).toBeTruthy();
    expect([creates[0]!.target!.upstreamProtocol, creates[0]!.target!.proxyProtocol]).toEqual([UpstreamProtocol.TCP, ProxyProtocol.V1]);
  });

  it("shows the TCP-only note on a TCP and UDP route alone", async () => {
    detail({ case: "tcp", value: { port: 25432 } });
    fireEvent.click(await screen.findByRole("button", { name: "Add a target" }));
    const f = await form("New target");
    expect(f.getByLabelText("PROXY protocol").getAttribute("aria-describedby")).toBeNull();
    expect(f.queryByText("TCP connections only; UDP datagrams get no header.")).toBeNull();
  });

  it("explains that priority ranks targets across connectors (D90)", async () => {
    detail({ case: "tcp", value: { port: 25432 } });
    fireEvent.click(await screen.findByRole("button", { name: "Add a target" }));
    const f = await form("New target");
    const hint = f.getByText("Lower is preferred. A higher priority, on any connector, is a failover; one priority is shared by weight.");
    expect(f.getByLabelText(/^Priority/).getAttribute("aria-describedby")).toContain(hint.id);
  });

  it("sends a target back unchanged when nothing was edited", async () => {
    const { updates } = detail({ case: "http", value: { hostnames: ["app.example.com"] } });
    fireEvent.click(await screen.findByRole("button", { name: "Edit…" }));
    const f = await form("Edit target");
    expect((f.getByLabelText("Connector") as HTMLSelectElement).disabled).toBe(true);
    fireEvent.click(f.getByRole("button", { name: "Save" }));
    await waitFor(() => expect(updates).toHaveLength(1));
    expect(equals(RouteTargetSchema, updates[0]!.target!, target)).toBe(true);
    expect([updates[0]!.updateMask?.paths, updates[0]!.etag]).toEqual([targetMask, "3"]);
  });

  it("verifies an HTTPS upstream, and moves a target to a socket", async () => {
    const { updates } = detail({ case: "http", value: { hostnames: ["app.example.com"] } });
    fireEvent.click(await screen.findByRole("button", { name: "Edit…" }));
    const f = await form("Edit target");
    expect(f.queryByLabelText(/TLS server name/)).toBeNull();
    fireEvent.change(f.getByLabelText("Protocol to the target"), { target: { value: String(UpstreamProtocol.HTTPS) } });
    fireEvent.change(await f.findByLabelText(/TLS server name/), { target: { value: "app.internal" } });
    fireEvent.change(f.getByLabelText("Address"), { target: { value: "unixPath" } });
    fireEvent.change(await f.findByLabelText("Socket path"), { target: { value: "/run/app.sock" } });
    fireEvent.click(f.getByRole("button", { name: "Save" }));
    await waitFor(() => expect(updates).toHaveLength(1));
    const t = updates[0]!.target!;
    expect([t.connectorId, t.upstreamProtocol, t.tls?.serverName, t.address]).toEqual(["con_db", UpstreamProtocol.HTTPS, "app.internal", { case: "unixPath", value: "/run/app.sock" }]);
  });

  it("warns before HTTPS, unverified, and sends it with a server name but no CA bundle or pin", async () => {
    const { updates } = detail({ case: "http", value: { hostnames: ["app.example.com"] } });
    fireEvent.click(await screen.findByRole("button", { name: "Edit…" }));
    const f = await form("Edit target");
    const protocol = f.getByLabelText("Protocol to the target");
    expect(f.queryByText(/will not check the target's certificate/)).toBeNull();
    fireEvent.change(protocol, { target: { value: String(UpstreamProtocol.HTTPS) } });
    fireEvent.change(await f.findByLabelText(/CA bundle ID/), { target: { value: "cab_1" } });
    fireEvent.change(f.getByLabelText(/Public key pin/), { target: { value: "ab".repeat(32) } });
    fireEvent.change(protocol, { target: { value: UNVERIFIED } });
    const warning = await f.findByText(/will not check the target's certificate/);
    expect(protocol.getAttribute("aria-describedby")).toBe(warning.parentElement!.id);
    expect([f.queryByLabelText(/CA bundle ID/), f.queryByLabelText(/Public key pin/)]).toEqual([null, null]);
    const serverName = f.getByLabelText("TLS server name");
    expect(document.getElementById(serverName.getAttribute("aria-describedby")!.split(" ")[0]!)?.textContent).toBe("Sent to the target; empty: the host's name.");
    fireEvent.change(serverName, { target: { value: " nas.local " } });
    fireEvent.click(f.getByRole("button", { name: "Save" }));
    await waitFor(() => expect(updates).toHaveLength(1));
    const t = updates[0]!.target!;
    expect([t.upstreamProtocol, t.tls?.verification, t.tls?.serverName, t.tls?.caBundleId, t.tls?.spkiSha256])
      .toEqual([UpstreamProtocol.HTTPS, UpstreamVerification.UNVERIFIED, "nas.local", "", ""]);
  });

  it("shows an unverified target as such, and keeps it so", async () => {
    const unverified = clone(RouteTargetSchema, target);
    unverified.upstreamProtocol = UpstreamProtocol.HTTPS;
    unverified.tls = create(UpstreamTLSSettingsSchema, { serverName: "nas.local", verification: UpstreamVerification.UNVERIFIED });
    const { updates } = detail({ case: "http", value: { hostnames: ["app.example.com"] } }, [unverified]);
    const row = (await screen.findByText("10.0.0.5:8080")).closest("tr")!;
    expect(within(row).getByText("unverified").getAttribute("title")).toBe("HTTPS without checking the target's certificate");
    fireEvent.click(within(row).getByRole("button", { name: "Edit…" }));
    const f = await form("Edit target");
    expect((f.getByLabelText("Protocol to the target") as HTMLSelectElement).value).toBe(UNVERIFIED);
    expect(f.getByText(/will not check the target's certificate/)).toBeTruthy();
    fireEvent.click(f.getByRole("button", { name: "Save" }));
    await waitFor(() => expect(updates).toHaveLength(1));
    expect(equals(RouteTargetSchema, updates[0]!.target!, unverified)).toBe(true);
  });

  it("pins the key of the certificate the target shows, once the user trusts it", async () => {
    const pin = "ab".repeat(32);
    const { updates, probes } = detail({ case: "http", value: { hostnames: ["app.example.com"] } }, [target], () => ({
      certificate: { spkiSha256: pin, subject: "CN=pve.local", issuer: "CN=pve.local", dnsNames: ["pve.local"], ipAddresses: ["10.0.0.5"],
        selfSigned: true, notAfter: { seconds: 1893456000n } },
    }));
    fireEvent.click(await screen.findByRole("button", { name: "Edit…" }));
    const f = await form("Edit target");
    fireEvent.change(f.getByLabelText("Protocol to the target"), { target: { value: PINNED } });
    const key = await f.findByLabelText("Pinned public key, SHA-256 in hex");
    expect(key.hasAttribute("required")).toBe(true);
    expect([f.queryByLabelText(/CA bundle ID/), f.queryByText(/will not check the target's certificate/)]).toEqual([null, null]);
    fireEvent.change(f.getByLabelText("TLS server name"), { target: { value: "pve.local" } });
    fireEvent.click(f.getByRole("button", { name: "Trust the certificate it shows now" }));
    const shown = within(await f.findByRole("region", { name: "The certificate the target shows" }));
    expect(shown.getByText("pve.local, 10.0.0.5")).toBeTruthy();
    expect(shown.getByText("Self-signed")).toBeTruthy();
    expect(shown.getByText(pin)).toBeTruthy();
    expect(probes.map((p) => [p.connectorId, p.address, p.serverName]))
      .toEqual([["con_db", { case: "hostPort", value: expect.objectContaining({ host: "10.0.0.5", port: 8080 }) }, "pve.local"]]);
    fireEvent.click(shown.getByRole("button", { name: "Trust this key" }));
    await waitFor(() => expect((key as HTMLInputElement).value).toBe(pin));
    expect(f.queryByRole("region", { name: "The certificate the target shows" })).toBeNull();
    fireEvent.click(f.getByRole("button", { name: "Save" }));
    await waitFor(() => expect(updates).toHaveLength(1));
    const t = updates[0]!.target!;
    expect([t.upstreamProtocol, t.tls?.verification, t.tls?.spkiSha256, t.tls?.caBundleId, t.tls?.serverName])
      .toEqual([UpstreamProtocol.HTTPS, UpstreamVerification.PINNED_KEY, pin, "", "pve.local"]);
  });

  it("drops a certificate it read once the form names another target, so another target's key is never pinned", async () => {
    const pin = "cd".repeat(32);
    const { probes } = detail({ case: "http", value: { hostnames: ["app.example.com"] } }, [target], () => ({
      certificate: { spkiSha256: pin, subject: "CN=pve.local", issuer: "CN=pve.local", dnsNames: ["pve.local"], selfSigned: true },
    }));
    fireEvent.click(await screen.findByRole("button", { name: "Edit…" }));
    const f = await form("Edit target");
    fireEvent.change(f.getByLabelText("Protocol to the target"), { target: { value: PINNED } });
    const key = await f.findByLabelText("Pinned public key, SHA-256 in hex");
    for (const [label, value] of [["Host", "10.0.0.6"], ["Port", "8443"], ["TLS server name", "other.local"]] as const) {
      fireEvent.click(f.getByRole("button", { name: "Trust the certificate it shows now" }));
      await f.findByRole("region", { name: "The certificate the target shows" });
      fireEvent.change(f.getByLabelText(label), { target: { value } });
      await waitFor(() => expect(f.queryByRole("region", { name: "The certificate the target shows" })).toBeNull());
    }
    expect(probes).toHaveLength(3);
    expect((key as HTMLInputElement).value).toBe("");
  });

  it("says why no certificate was read, and asks for a connector and an address first", async () => {
    const { probes } = detail({ case: "http", value: { hostnames: ["app.example.com"] } }, [target], () => {
      throw new ConnectError("apisvc: the connector read no certificate: the connector's local policy does not allow 10.0.0.5:8080", Code.FailedPrecondition);
    });
    fireEvent.click(await screen.findByRole("button", { name: "Add a target" }));
    const f = await form("New target");
    fireEvent.change(f.getByLabelText("Protocol to the target"), { target: { value: PINNED } });
    fireEvent.click(await f.findByRole("button", { name: "Trust the certificate it shows now" }));
    expect((await f.findByRole("alert")).textContent).toBe("Choose the connector and enter the target's address first.");
    expect(probes).toEqual([]);
    await f.findByRole("option", { name: "app-host" });
    fireEvent.change(f.getByLabelText("Connector"), { target: { value: "con_app" } });
    fireEvent.change(f.getByLabelText("Host"), { target: { value: "10.0.0.5" } });
    fireEvent.change(f.getByLabelText("Port"), { target: { value: "8080" } });
    fireEvent.click(f.getByRole("button", { name: "Trust the certificate it shows now" }));
    await waitFor(() => expect(f.getByRole("alert").textContent).toBe(
      "The connector could not read the target's certificate: apisvc: the connector read no certificate: the connector's local policy does not allow 10.0.0.5:8080"));
    expect(probes.map((p) => p.connectorId)).toEqual(["con_app"]);
  });

  it("removes a target after a confirmation that names it", async () => {
    const { deletes } = detail({ case: "tcp", value: { port: 25432 } });
    fireEvent.click(await screen.findByRole("button", { name: "Remove…" }));
    expect(screen.getByText("Remove the target 10.0.0.5:8080?")).toBeTruthy();
    fireEvent.click(screen.getByRole("button", { name: "Remove it" }));
    expect(await screen.findByText("Revision 11: applied by all 1 agents.")).toBeTruthy();
    expect(deletes.map((d) => [d.routeTargetId, d.etag])).toEqual([["tgt_1", "3"]]);
  });

  it("marks what a target needs: a connector when it is added, then a host and port or a socket", async () => {
    detail({ case: "http", value: { hostnames: ["app.example.com"] } });
    fireEvent.click(await screen.findByRole("button", { name: "Add a target" }));
    const added = await screen.findByRole("form", { name: "New target" });
    expect(marked(added)).toEqual(["Connector", "Host", "Port", "Weight", "Priority"]);
    expect(unmatched(added)).toEqual([]);
    fireEvent.change(within(added).getByLabelText("Address"), { target: { value: "unixPath" } });
    await waitFor(() => expect(marked(added)).toEqual(["Connector", "Socket path", "Weight", "Priority"]));
    // An HTTPS target on a socket has no host to name, so it needs a server name, without the hint
    // that an empty one is the host's.
    fireEvent.change(within(added).getByLabelText("Protocol to the target"), { target: { value: String(UpstreamProtocol.HTTPS) } });
    await waitFor(() => expect(marked(added)).toContain("TLS server name"));
    expect(within(added).queryByText("Empty: the host's name.")).toBeNull();
    expect(unmatched(added)).toEqual([]);
    fireEvent.change(within(added).getByLabelText("Address"), { target: { value: "hostPort" } });
    await waitFor(() => expect(marked(added)).toEqual(["Connector", "Host", "Port", "Weight", "Priority"]));
    const serverName = within(added).getByLabelText("TLS server name");
    expect(document.getElementById(serverName.getAttribute("aria-describedby")!.split(" ")[0]!)?.textContent).toBe("Empty: the host's name.");
  });

  it("does not mark the connector of a target being edited, which cannot change", async () => {
    detail({ case: "http", value: { hostnames: ["app.example.com"] } });
    fireEvent.click(await screen.findByRole("button", { name: "Edit…" }));
    const edited = await screen.findByRole("form", { name: "Edit target" });
    expect(marked(edited)).toEqual(["Host", "Port", "Weight", "Priority"]);
    expect(unmatched(edited)).toEqual([]);
  });
});
