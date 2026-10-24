// SPDX-License-Identifier: Apache-2.0

import { clone, create, equals } from "@bufbuild/protobuf";
import { timestampFromDate } from "@bufbuild/protobuf/wkt";
import { Code, ConnectError } from "@connectrpc/connect";
import { FieldDescriptorProto_Type } from "@bufbuild/protobuf/wkt";
import { cleanup, fireEvent, screen, waitFor } from "@testing-library/react";
import { afterEach, describe, expect, it } from "vitest";
import { ViolationsSchema } from "@/gen/buf/validate/validate_pb";
import { CertificateService, CertificateSource } from "@/gen/rpmgr/v1/certificate_pb";
import { ConnectorService, DataTransport } from "@/gen/rpmgr/v1/connector_pb";
import { GatewayService } from "@/gen/rpmgr/v1/gateway_pb";
import { ConnectAuthMode, ListenerMode, Port80Mode, RouteSchema, RouteService, RouteState, TLSMode, type Route, type UpdateRouteRequest } from "@/gen/rpmgr/v1/route_pb";
import { ApplyState, StatusService } from "@/gen/rpmgr/v1/status_pb";
import { Theme, UserService } from "@/gen/rpmgr/v1/user_pb";
import { auth, show } from "@/testing/api";

afterEach(cleanup);

// Routes of every type with every field set, output-only ones included, which no save may lose
// (docs/09-web-ui.md, U1).
const common = {
  id: "rte_1", name: "wiki", gatewayGroupId: "ggr_eu", enabled: true, labels: { team: "ops", env: "prod" }, description: "the wiki",
  policyIds: ["pol_1", "pol_2"], transport: DataTransport.QUIC, etag: "7",
  createTime: timestampFromDate(new Date("2026-10-01T00:00:00Z")), updateTime: timestampFromDate(new Date("2026-10-02T00:00:00Z")),
  targets: [{ id: "tgt_1", connectorId: "con_1", weight: 100, enabled: true, address: { case: "hostPort" as const, value: { host: "10.0.0.5", port: 80 } } }],
  status: { state: RouteState.READY, targetsTotal: 1, targetsReady: 1 },
};
const routes: Record<string, Route> = {
  http: create(RouteSchema, { ...common, spec: { case: "http", value: {
    hostnames: ["wiki.example.com", "w.example.com"], pathPrefix: "/docs", tlsMode: TLSMode.TLS_MODE_CERTIFICATE, certificateId: "crt_1",
    port80: Port80Mode.SERVE, hstsMaxAgeSeconds: 3600, hostHeader: "internal", requestHeadersSet: { "X-A": "1" },
    responseHeadersSet: { "X-B": "a: b" }, websocket: false, maxBodyBytes: 1024n, maintenance: true, maintenanceMessage: "Back at 18:00.\nSorry." } } }),
  tcp: create(RouteSchema, { ...common, spec: { case: "tcp", value: { port: 25432, idleTimeoutSeconds: 600 } } }),
  tcpConnect: create(RouteSchema, { ...common, spec: { case: "tcp", value: { port: 20001, idleTimeoutSeconds: 600, listenerMode: ListenerMode.HTTP_CONNECT,
    connect: { authorities: ["bastion", "ssh.internal"], authMode: ConnectAuthMode.NONE } } } }),
  udp: create(RouteSchema, { ...common, spec: { case: "udp", value: { port: 53, flowIdleTimeoutSeconds: 30 } } }),
  tcpUdp: create(RouteSchema, { ...common, spec: { case: "tcpUdp", value: { port: 5353, idleTimeoutSeconds: 600, flowIdleTimeoutSeconds: 30 } } }),
  tlsPassthrough: create(RouteSchema, { ...common, spec: { case: "tlsPassthrough", value: { hostnames: ["db.example.com"] } } }),
};

// edit renders the edit page of route; UpdateRoute answers with answer, and ListCertificates with
// certs, if given: without, the certificates cannot be read.
function edit(route: Route, answer: (req: UpdateRouteRequest) => object = (req) => ({ route: req.route, revision: { dbEpoch: "e", seq: 9n }, applyStatus: { state: ApplyState.APPLIED, agentsTotal: 1, agentsApplied: 1 } }),
  certs?: object[]) {
  const updates: UpdateRouteRequest[] = [];
  show("/routes/rte_1/edit", auth({ getSession: () => ({ userId: "usr_ada", memberships: [{ orgId: "org_1", role: "owner" }] }) }), (router) => {
    router.service(UserService, { getMe: () => ({ user: { id: "usr_ada", theme: Theme.SYSTEM } }) });
    router.service(GatewayService, { listGateways: () => ({}) });
    router.service(ConnectorService, { listConnectors: () => ({}) });
    router.service(StatusService, { async *watchApplyStatus() {} });
    if (certs) {
      router.service(CertificateService, { listCertificates: () => ({ certificates: certs }) });
    }
    router.service(RouteService, { getRoute: () => ({ route }), updateRoute: (req) => (updates.push(req), answer(req)) });
  });
  return updates;
}

const save = () => fireEvent.click(screen.getByRole("button", { name: "Save" }));

describe("RouteEdit", () => {
  it.each(Object.entries(routes))("sends a %s route back unchanged when nothing was edited", async (_, route) => {
    const updates = edit(route);
    await screen.findByLabelText("Name");
    save();
    expect(await screen.findByText("Revision 9: applied by all 1 agents.")).toBeTruthy();
    expect(updates).toHaveLength(1);
    expect(equals(RouteSchema, updates[0]!.route!, route)).toBe(true);
    expect(updates[0]!.etag).toBe("7");
    expect(updates[0]!.updateMask?.paths.slice(0, 4)).toEqual(["name", "description", "labels", "transport"]);
  });

  it("changes only the fields edited", async () => {
    const updates = edit(routes.http!);
    fireEvent.change(await screen.findByLabelText("Name"), { target: { value: "docs" } });
    fireEvent.change(screen.getByLabelText("Hostnames"), { target: { value: "docs.example.com\n\n  d.example.com  " } });
    fireEvent.change(screen.getByLabelText("Labels"), { target: { value: "team=web" } });
    fireEvent.change(screen.getByLabelText("WebSocket"), { target: { value: "" } });
    fireEvent.change(screen.getByLabelText("Request headers to set"), { target: { value: "X-A: 2\nX-C: x: y" } });
    save();
    await waitFor(() => expect(updates).toHaveLength(1));
    const want = clone(RouteSchema, routes.http!); // create would return the route itself
    want.name = "docs";
    want.labels = { team: "web" };
    if (want.spec.case === "http") {
      want.spec.value.hostnames = ["docs.example.com", "d.example.com"];
      want.spec.value.websocket = undefined;
      want.spec.value.requestHeadersSet = { "X-A": "2", "X-C": "x: y" };
    }
    expect(equals(RouteSchema, updates[0]!.route!, want)).toBe(true);
    expect(updates[0]!.updateMask?.paths).toContain("http.websocket");
  });

  it("takes an http route out of maintenance and changes the page's message (D88)", async () => {
    const updates = edit(routes.http!);
    const maintenance = await screen.findByLabelText("Maintenance");
    expect((maintenance as HTMLSelectElement).value).toBe("true");
    fireEvent.change(maintenance, { target: { value: "false" } });
    fireEvent.change(screen.getByLabelText("Maintenance message (plain text, at most 500 characters)"), { target: { value: "Back\nsoon" } });
    save();
    await waitFor(() => expect(updates).toHaveLength(1));
    const spec = updates[0]!.route?.spec;
    expect(spec?.case === "http" && [spec.value.maintenance, spec.value.maintenanceMessage, spec.value.hostnames]).toEqual([false, "Back\nsoon", ["wiki.example.com", "w.example.com"]]);
    expect(updates[0]!.updateMask?.paths).toEqual(expect.arrayContaining(["http.maintenance", "http.maintenance_message"]));
  });

  it.each([["above 500 characters", "x".repeat(501)], ["with a tab", "back\tsoon"], ["with a C1 control", "back \u009b31msoon"]])(
    "refuses a maintenance message %s before sending", async (_, bad) => {
      const updates = edit(routes.http!);
      const message = await screen.findByLabelText("Maintenance message (plain text, at most 500 characters)");
      fireEvent.change(message, { target: { value: bad } });
      save();
      await waitFor(() => expect(message.getAttribute("aria-invalid")).toBe("true"));
      expect(updates).toEqual([]);
    });

  it("moves a TCP and UDP route to a new port and clears its UDP flow idle timeout", async () => {
    const updates = edit(routes.tcpUdp!);
    fireEvent.change(await screen.findByLabelText("Public port"), { target: { value: "5354" } });
    expect((screen.getByLabelText("TCP idle timeout (seconds)") as HTMLInputElement).value).toBe("600");
    fireEvent.change(screen.getByLabelText("UDP flow idle timeout (seconds)"), { target: { value: "" } });
    save();
    await waitFor(() => expect(updates).toHaveLength(1));
    const spec = updates[0]!.route?.spec;
    expect(spec?.case === "tcpUdp" && [spec.value.port, spec.value.idleTimeoutSeconds, spec.value.flowIdleTimeoutSeconds]).toEqual([5354, 600, undefined]);
    expect(updates[0]!.updateMask?.paths).toEqual(expect.arrayContaining(["tcp_udp.port", "tcp_udp.flow_idle_timeout_seconds"]));
  });

  it("edits a CONNECT route's names and mode, warns of passwords in the clear, and shows the server's warning", async () => {
    const updates = edit(routes.tcpConnect!, (req) => ({ route: req.route, revision: { dbEpoch: "e", seq: 9n },
      applyStatus: { state: ApplyState.APPLIED, agentsTotal: 1, agentsApplied: 1 }, warnings: ["passwords cross the network in the clear"] }));
    const names = await screen.findByLabelText("CONNECT names");
    expect((names as HTMLTextAreaElement).value).toBe("bastion\nssh.internal");
    expect(screen.queryByLabelText("Listener hostname (HTTPS proxy)")).toBeNull();
    fireEvent.change(names, { target: { value: "jump\n bastion " } });
    fireEvent.change(screen.getByLabelText("Proxy credentials"), { target: { value: String(ConnectAuthMode.PLAIN_BASIC) } });
    expect(await screen.findByText(/anyone on the network between them and the gateway can read and use it/)).toBeTruthy();
    save();
    await waitFor(() => expect(updates).toHaveLength(1));
    const spec = updates[0]!.route?.spec;
    expect(spec?.case === "tcp" && [spec.value.listenerMode, spec.value.connect?.authorities, spec.value.connect?.authMode]).toEqual(
      [ListenerMode.HTTP_CONNECT, ["jump", "bastion"], ConnectAuthMode.PLAIN_BASIC]);
    expect(updates[0]!.updateMask?.paths.filter((p) => p === "tcp.connect")).toHaveLength(1);
    expect(await screen.findByText("Warning: passwords cross the network in the clear.")).toBeTruthy();
  });

  it("asks a TLS CONNECT listener for its hostname and certificate, and a CONNECT route for its names", async () => {
    const updates = edit(routes.tcpConnect!);
    fireEvent.change(await screen.findByLabelText("Proxy credentials"), { target: { value: String(ConnectAuthMode.TLS_BASIC) } });
    const host = await screen.findByLabelText(/Listener hostname/);
    expect(host.getAttribute("required")).not.toBeNull();
    expect(screen.getByLabelText(/Listener certificate/)).toBeTruthy();
    save();
    expect(await screen.findByText("Choose the uploaded certificate the route uses.")).toBeTruthy();
    fireEvent.change(screen.getByLabelText("Proxy credentials"), { target: { value: String(ConnectAuthMode.NONE) } });
    fireEvent.change(screen.getByLabelText("CONNECT names"), { target: { value: "" } });
    save();
    await waitFor(() => expect(screen.getByLabelText("CONNECT names").getAttribute("aria-invalid")).toBe("true"));
    expect(updates).toEqual([]);
  });

  it("checks the API's rules before sending", async () => {
    const updates = edit(routes.tcp!);
    fireEvent.change(await screen.findByLabelText("Name"), { target: { value: "Bad_Name" } });
    save();
    expect((await screen.findByRole("alert")).textContent).toMatch(/does not match regex pattern/);
    fireEvent.change(screen.getByLabelText("Name"), { target: { value: "ok" } });
    fireEvent.change(screen.getByLabelText("Public port"), { target: { value: "8o" } });
    save();
    expect(await screen.findByText("Enter a whole number.")).toBeTruthy();
    await waitFor(() => expect(screen.queryByText(/does not match regex pattern/)).toBeNull());
    expect(updates).toEqual([]);
  });

  it("shows the server's violations on their fields", async () => {
    edit(routes.http!, () => {
      const el = (name: string, n: number, t: FieldDescriptorProto_Type) => ({ fieldName: name, fieldNumber: n, fieldType: t });
      const v = create(ViolationsSchema, { violations: [
        { field: { elements: [el("route", 1, FieldDescriptorProto_Type.MESSAGE), el("http", 10, FieldDescriptorProto_Type.MESSAGE), { ...el("hostnames", 1, FieldDescriptorProto_Type.STRING), subscript: { case: "index", value: 0n } }] },
          message: "the domain is not verified" },
      ] });
      throw new ConnectError("invalid", Code.InvalidArgument, undefined, [{ desc: ViolationsSchema, value: v }]);
    });
    await screen.findByLabelText("Name");
    save();
    const hostnames = screen.getByLabelText("Hostnames");
    await waitFor(() => expect(hostnames.getAttribute("aria-invalid")).toBe("true"));
    expect(screen.getByText("the domain is not verified")).toBeTruthy();
  });

  it("keeps a route's certificate chosen, also when it no longer covers the hostnames or is not listed", async () => {
    const ok = { id: "crt_1", source: CertificateSource.UPLOADED, sans: ["*.example.com"], notAfter: timestampFromDate(new Date("2027-03-01T12:00:00Z")) };
    const updates = edit(routes.http!, undefined, [ok, { id: "crt_2", source: CertificateSource.UPLOADED, sans: ["example.org"] }]);
    const picker = await screen.findByLabelText<HTMLSelectElement>("Uploaded certificate");
    await waitFor(() => expect([...picker.options].map((o) => o.value)).toEqual(["", "crt_1"]));
    expect([picker.value, picker.selectedOptions[0]!.textContent]).toEqual(["crt_1", expect.stringMatching(/^\*\.example\.com · crt_1 · expires /)]);
    fireEvent.change(screen.getByLabelText("Hostnames"), { target: { value: "example.org" } });
    await waitFor(() => expect([...picker.options].map((o) => o.value)).toEqual(["", "crt_2", "crt_1"]));
    expect([picker.value, picker.selectedOptions[0]!.textContent]).toEqual(["crt_1", expect.stringMatching(/^\*\.example\.com · crt_1 · expires .* \(does not cover every hostname\)$/)]);
    save();
    await waitFor(() => expect(updates).toHaveLength(1));
    expect(updates[0]!.route?.spec).toMatchObject({ case: "http", value: { certificateId: "crt_1", hostnames: ["example.org"] } });
    // A certificate the list lacks, or while it cannot be read, shows by its ID.
    cleanup();
    edit(routes.http!);
    const unread = await screen.findByLabelText<HTMLSelectElement>("Uploaded certificate");
    expect([unread.value, unread.selectedOptions[0]!.textContent]).toEqual(["crt_1", "crt_1"]);
  });
});
