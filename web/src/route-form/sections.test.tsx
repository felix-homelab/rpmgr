// SPDX-License-Identifier: Apache-2.0

import { create } from "@bufbuild/protobuf";
import { FieldDescriptorProto_Type } from "@bufbuild/protobuf/wkt";
import { Code, ConnectError } from "@connectrpc/connect";
import { cleanup, fireEvent, screen, waitFor, within } from "@testing-library/react";
import { afterEach, describe, expect, it } from "vitest";
import { ViolationsSchema } from "@/gen/buf/validate/validate_pb";
import { ConnectorService } from "@/gen/rpmgr/v1/connector_pb";
import { GatewayService } from "@/gen/rpmgr/v1/gateway_pb";
import { ConnectAuthMode, HealthCheckType, ListenerMode, RouteSchema, RouteService, TLSMode, type Route } from "@/gen/rpmgr/v1/route_pb";
import { StatusService } from "@/gen/rpmgr/v1/status_pb";
import { Theme, UserService } from "@/gen/rpmgr/v1/user_pb";
import { routeFields } from "@/route-form/fields";
import { anchor, routeSections, sectionIds, sectionOf } from "@/route-form/sections";
import { auth, show } from "@/testing/api";

afterEach(cleanup);

const base = { id: "rte_1", name: "wiki", gatewayGroupId: "ggr_eu", etag: "7" };
const routes: Record<string, Route> = {
  http: create(RouteSchema, { ...base, spec: { case: "http", value: { hostnames: ["wiki.example.com"], tlsMode: TLSMode.TLS_MODE_ACME, hstsMaxAgeSeconds: 0 } } }),
  tlsPassthrough: create(RouteSchema, { ...base, spec: { case: "tlsPassthrough", value: { hostnames: ["db.example.com"] } } }),
  tcp: create(RouteSchema, { ...base, spec: { case: "tcp", value: { port: 25432 } } }),
  connect: create(RouteSchema, { ...base, spec: { case: "tcp", value: { port: 20001, listenerMode: ListenerMode.HTTP_CONNECT,
    connect: { authorities: ["bastion"], authMode: ConnectAuthMode.TLS_BASIC, hostname: "proxy.example.com", certificateId: "crt_1" } } } }),
  udp: create(RouteSchema, { ...base, spec: { case: "udp", value: { port: 53 } } }),
  tcpUdp: create(RouteSchema, { ...base, spec: { case: "tcpUdp", value: { port: 5353 } } }),
};

// The sections each type has, and the fields of each section, in the page's order.
const want: Record<string, Record<string, string[]>> = {
  http: {
    general: ["name", "description", "labels"],
    matching: ["hostnames", "pathPrefix", "headerMatches"],
    tls: ["tlsMode", "certificateId", "port80", "hsts"],
    requests: ["hostHeader", "requestHeaders", "responseHeaders", "websocket", "maxBody"],
    upstream: ["transport", "upstreamHeaderTimeout", "upstreamIdleTimeout", "maxConnections", "requestsPerSecond", "bandwidth"],
    health: ["healthCheck", "healthPort", "healthPath", "healthStatus", "healthInterval", "healthTimeout", "healthUnhealthy", "healthHealthy"],
    maintenance: ["maintenance", "maintenanceMessage"],
  },
  tlsPassthrough: { general: [], matching: ["hostnames"], upstream: [], health: [] },
  tcp: { general: [], upstream: ["transport", "idleTimeout", "maxConnections", "requestsPerSecond", "bandwidth"], health: [],
    connect: ["listenerMode", "authorities", "connectAuth", "connectHostname", "connectCertificate", "port"] },
  udp: { general: [], matching: ["port"], upstream: ["transport", "flowIdleTimeout", "maxConnections", "requestsPerSecond", "bandwidth"], health: [] },
  tcpUdp: { general: [], matching: ["port"], upstream: ["transport", "tcpIdleTimeout", "udpFlowIdleTimeout", "maxConnections", "requestsPerSecond", "bandwidth"],
    health: [] },
};

describe("routeSections", () => {
  it.each(Object.entries(want))("gives a %s route only its sections, in order, with their fields in order", (type, sections) => {
    const got = routeSections(routes[type]!);
    expect(got.map((s) => s.id)).toEqual(Object.keys(sections));
    for (const [id, keys] of Object.entries(sections).filter(([, keys]) => keys.length > 0)) {
      expect(got.find((s) => s.id === id)!.fields.map((f) => f.key), id).toEqual(keys);
    }
  });

  it.each(Object.keys(routes))("places every field of a %s route in exactly one section the order names", (type) => {
    const r = routes[type]!;
    const fields = routeFields(r).map((f) => f.key);
    expect(fields.filter((k) => sectionOf(r, k) === undefined)).toEqual([]);
    expect(routeSections(r).flatMap((s) => s.fields.map((f) => f.key)).sort()).toEqual([...fields].sort());
  });

  it("knows no section of a key no field has, and puts a new route's gateway group in General", () => {
    expect(sectionOf(routes.http!, "nothing")).toBeUndefined();
    expect(sectionOf(routes.http!, "group")).toBe("general");
    // The port stands with the CONNECT listener on a TCP route, and with the hostnames otherwise.
    expect(sectionOf(routes.tcp!, "port")).toBe("connect");
    expect(sectionOf(routes.udp!, "port")).toBe("matching");
  });

  it("gives every section a distinct anchor", () => {
    expect(new Set(sectionIds.map(anchor)).size).toBe(sectionIds.length);
  });
});

// edit renders the edit page of route; UpdateRoute answers with answer.
function edit(route: Route, answer: () => object = () => ({ route })) {
  show("/routes/rte_1/edit", auth({ getSession: () => ({ userId: "usr_ada", memberships: [{ orgId: "org_1", role: "owner" }] }) }), (router) => {
    router.service(UserService, { getMe: () => ({ user: { id: "usr_ada", theme: Theme.SYSTEM } }) });
    router.service(GatewayService, { listGateways: () => ({}), listGatewayGroups: () => ({ gatewayGroups: [{ id: "ggr_eu", name: "eu" }] }) });
    router.service(ConnectorService, { listConnectors: () => ({}) });
    router.service(StatusService, { async *watchApplyStatus() {} });
    router.service(RouteService, { getRoute: () => ({ route }), updateRoute: answer, createRoute: answer });
  });
}

const list = () => screen.getByRole("navigation", { name: "Sections of the form" });
const links = () => within(list()).getAllByRole("link").map((a) => a.textContent);
const headings = () => screen.getAllByRole("heading", { level: 2 }).map((h) => h.textContent);
const marked = () => within(list()).getAllByRole("link").filter((a) => a.textContent?.includes("(has an error)")).map((a) => a.textContent);

describe("the route form's sections", () => {
  it.each([
    ["HTTP", routes.http!, ["General", "Hostnames & matching", "TLS", "Requests & headers", "Upstream", "Health check", "Maintenance"]],
    ["TLS passthrough", routes.tlsPassthrough!, ["General", "Hostnames & matching", "Upstream", "Health check"]],
    ["TCP", routes.tcp!, ["General", "Upstream", "Health check", "CONNECT listener"]],
    ["CONNECT", routes.connect!, ["General", "Upstream", "Health check", "CONNECT listener"]],
    ["UDP", routes.udp!, ["General", "Hostnames & matching", "Upstream", "Health check"]],
  ])("shows a %s route's sections, each linked from the list to its heading", async (_, route, titles) => {
    edit(route);
    await screen.findByLabelText("Name");
    expect(headings()).toEqual(titles);
    expect(links()).toEqual(titles);
    for (const a of within(list()).getAllByRole("link")) {
      const target = document.getElementById(a.getAttribute("href")!.replace(/^#/, ""));
      expect(target?.tagName, a.textContent!).toBe("H2");
      expect(target?.textContent).toBe(a.textContent);
    }
    expect(marked()).toEqual([]);
  });

  it("shows a CONNECT route's listener fields in its section, and a plain TCP route's listener and port only", async () => {
    edit(routes.connect!);
    await screen.findByLabelText("Name");
    const section = (title: string) => screen.getByRole("heading", { name: title }).closest("section")!;
    const connect = within(section("CONNECT listener"));
    for (const label of ["Listener", "CONNECT names", "Proxy credentials", "Listener hostname (HTTPS proxy)", "Listener certificate", "Public port"]) {
      expect(connect.getByLabelText(label, { exact: true })).toBeTruthy();
    }
    expect(within(section("Upstream")).getByLabelText("Idle timeout (seconds)")).toBeTruthy();
    cleanup();
    edit(routes.tcp!);
    await screen.findByLabelText("Name");
    const controls = section("CONNECT listener").querySelectorAll<HTMLInputElement | HTMLSelectElement>("input, select, textarea");
    expect([...controls].map((c) => c.labels?.[0]?.textContent)).toEqual(["Listener", "Public port"]);
  });

  it("marks the sections with errors and moves the focus to the first such field in the page's order", async () => {
    edit(routes.http!);
    await screen.findByLabelText("Name");
    // HSTS comes before the header matches among the fields, but after them on the page.
    fireEvent.change(screen.getByLabelText("HSTS max-age (seconds)"), { target: { value: "soon" } });
    fireEvent.change(screen.getByLabelText("Serve only requests with these headers"), { target: { value: "X Env: a" } });
    fireEvent.click(screen.getByRole("button", { name: "Save" }));
    await waitFor(() => expect(marked()).toEqual(["Hostnames & matching (has an error)", "TLS (has an error)"]));
    await waitFor(() => expect(document.activeElement).toBe(screen.getByLabelText("Serve only requests with these headers")));
    // Once the first is right, a failed save moves to the next, and its section alone stays marked.
    fireEvent.change(screen.getByLabelText("Serve only requests with these headers"), { target: { value: "X-Env: a" } });
    fireEvent.click(screen.getByRole("button", { name: "Save" }));
    await waitFor(() => expect(marked()).toEqual(["TLS (has an error)"]));
    await waitFor(() => expect(document.activeElement).toBe(screen.getByLabelText("HSTS max-age (seconds)")));
  });

  it("moves the focus to a field the server refuses, and a failed preview does too", async () => {
    edit(routes.http!, () => {
      const el = (name: string, n: number, t: FieldDescriptorProto_Type) => ({ fieldName: name, fieldNumber: n, fieldType: t });
      const v = create(ViolationsSchema, { violations: [
        { field: { elements: [el("route", 1, FieldDescriptorProto_Type.MESSAGE), el("http", 10, FieldDescriptorProto_Type.MESSAGE),
          { ...el("hostnames", 1, FieldDescriptorProto_Type.STRING), subscript: { case: "index", value: 0n } }] }, message: "the domain is not verified" },
      ] });
      throw new ConnectError("invalid", Code.InvalidArgument, undefined, [{ desc: ViolationsSchema, value: v }]);
    });
    await screen.findByLabelText("Name");
    fireEvent.click(screen.getByRole("button", { name: "Save" }));
    await waitFor(() => expect(document.activeElement).toBe(screen.getByLabelText("Hostnames")));
    expect(marked()).toEqual(["Hostnames & matching (has an error)"]);
    // The form's own check refuses a preview before it is sent.
    fireEvent.change(screen.getByLabelText("Health check", { exact: true }), { target: { value: String(HealthCheckType.TCP) } });
    fireEvent.change(screen.getByLabelText("Check interval (seconds)"), { target: { value: "x" } });
    fireEvent.click(screen.getByRole("button", { name: "Preview" }));
    await waitFor(() => expect(document.activeElement).toBe(screen.getByLabelText("Check interval (seconds)")));
    expect(marked()).toEqual(["Health check (has an error)"]);
  });

  it("puts the new route's gateway group in General, marks it and moves to it when none is chosen", async () => {
    show("/routes/new", auth({ getSession: () => ({ userId: "usr_ada", memberships: [{ orgId: "org_1", role: "owner" }] }) }), (router) => {
      router.service(UserService, { getMe: () => ({ user: { id: "usr_ada", theme: Theme.SYSTEM } }) });
      router.service(GatewayService, { listGateways: () => ({}), listGatewayGroups: () => ({ gatewayGroups: [{ id: "ggr_eu", name: "eu" }] }) });
      router.service(ConnectorService, { listConnectors: () => ({}) });
    });
    fireEvent.change(await screen.findByLabelText("Name"), { target: { value: "wiki" } });
    fireEvent.change(screen.getByLabelText("Hostnames"), { target: { value: "wiki.example.com" } });
    const general = screen.getByRole("heading", { name: "General" }).closest("section")!;
    expect(within(general).getByLabelText("Gateway group")).toBeTruthy();
    fireEvent.click(screen.getByRole("button", { name: "Create the route" }));
    await waitFor(() => expect(document.activeElement).toBe(screen.getByLabelText("Gateway group")));
    expect(marked()).toEqual(["General (has an error)"]);
    // The form's controls stay at its end, after the last section.
    const form = screen.getByRole("button", { name: "Create the route" }).closest("form")!;
    const sections = form.querySelectorAll("section");
    expect(sections[sections.length - 1]!.compareDocumentPosition(screen.getByRole("button", { name: "Preview" })) & Node.DOCUMENT_POSITION_FOLLOWING).toBeTruthy();
  });
});
