// SPDX-License-Identifier: Apache-2.0

import { timestampFromDate } from "@bufbuild/protobuf/wkt";
import { Code, ConnectError } from "@connectrpc/connect";
import { cleanup, fireEvent, screen, waitFor, within } from "@testing-library/react";
import { afterEach, describe, expect, it } from "vitest";
import { CertificateService, CertificateSource } from "@/gen/rpmgr/v1/certificate_pb";
import { ConnectorService } from "@/gen/rpmgr/v1/connector_pb";
import { GatewayService } from "@/gen/rpmgr/v1/gateway_pb";
import { Port80Mode, RouteService, TLSMode, type CreateRouteRequest, type PreviewRouteRequest } from "@/gen/rpmgr/v1/route_pb";
import { SettingsService } from "@/gen/rpmgr/v1/settings_pb";
import { ApplyState, StatusService } from "@/gen/rpmgr/v1/status_pb";
import { Theme, UserService } from "@/gen/rpmgr/v1/user_pb";
import { auth, show } from "@/testing/api";
import { marked, unmatched } from "@/testing/required";

afterEach(cleanup);

// chooseGroup chooses the gateway group "eu" once it is listed.
async function chooseGroup() {
  await screen.findByRole("option", { name: "eu" });
  fireEvent.change(screen.getByLabelText("Gateway group"), { target: { value: "ggr_eu" } });
}

const expiry = timestampFromDate(new Date("2027-03-01T12:00:00Z"));
// The org's certificates: uploaded ones for a wildcard, for wiki and for another domain, and one
// from ACME for wiki, which a route never chooses.
const certificates = [
  { id: "crt_wild", source: CertificateSource.UPLOADED, sans: ["*.example.com"], notAfter: expiry },
  { id: "crt_wiki", source: CertificateSource.UPLOADED, sans: ["w.example.com", "wiki.example.com"], notAfter: expiry },
  { id: "crt_org", source: CertificateSource.UPLOADED, sans: ["example.org"], notAfter: expiry },
  { id: "crt_acme", source: CertificateSource.ACME, sans: ["wiki.example.com"], notAfter: expiry },
];

// page renders path with the gateway groups "eu" and "us" and the certificates certs; CreateRoute
// answers with create, and GetOrgSettings with orgSettings, if given: without, the org's settings
// cannot be read.
function page(path: string, create?: (req: CreateRouteRequest) => object, orgSettings?: () => object | Promise<object>, certs: object[] = certificates) {
  const creates: CreateRouteRequest[] = [];
  const previews: PreviewRouteRequest[] = [];
  const view = show(path, auth({ getSession: () => ({ userId: "usr_ada", memberships: [{ orgId: "org_1", role: "owner" }] }) }), (router) => {
    router.service(UserService, { getMe: () => ({ user: { id: "usr_ada", theme: Theme.SYSTEM } }) });
    router.service(GatewayService, {
      listGatewayGroups: () => ({ gatewayGroups: [{ id: "ggr_eu", name: "eu", publicHostnames: ["edge.example.net"] }, { id: "ggr_us", name: "us" }] }),
      listGateways: () => ({ gateways: [{ id: "gtw_1", name: "gw-eu-1" }] }),
    });
    router.service(ConnectorService, { listConnectors: () => ({ connectors: [{ id: "con_1", name: "db-host-1" }] }) });
    router.service(CertificateService, { listCertificates: () => ({ certificates: certs }) });
    router.service(StatusService, { async *watchApplyStatus() {} });
    if (orgSettings) {
      router.service(SettingsService, { getOrgSettings: orgSettings });
    }
    router.service(RouteService, {
      listRoutes: () => ({}),
      getRoute: () => ({ route: { id: "rte_1", name: "wiki", gatewayGroupId: "ggr_eu", etag: "7", spec: { case: "tcp", value: { port: 25432 } } } }),
      createRoute: (req) => (creates.push(req), create ? create(req) : {
        route: { ...req.route, id: "rte_new" }, revision: { dbEpoch: "e", seq: 5n }, applyStatus: { state: ApplyState.APPLIED, agentsTotal: 1, agentsApplied: 1 },
      }),
      previewRoute: (req) => (previews.push(req), {
        route: req.route, gatewayIds: ["gtw_1"], connectorIds: req.updateMask ? ["con_1"] : [],
        problems: req.route?.name === "bad" ? [{ message: "port 25432 in use on gw-eu-1" }] : [],
      }),
    });
  });
  return { ...view, creates, previews };
}

describe("RouteNew", () => {
  it("shows a hint only where a field's kind has one, and describes each field by what is there", async () => {
    page("/routes/new");
    await screen.findByLabelText("Labels");
    expect(screen.queryByText(/^routeForm\./)).toBeNull(); // never a key instead of text (U11)
    const hint = (label: string) => document.getElementById(screen.getByLabelText(label).getAttribute("aria-describedby")!)?.textContent;
    expect(hint("Labels")).toBe("One per line, as key=value.");
    expect([hint("Request headers to set"), hint("Response headers to set")]).toEqual(Array(2).fill("One per line, as Name: value. An empty value removes the header."));
    expect(hint("Hostnames")).toBe("One per line.");
    const hsts = screen.getByLabelText("HSTS max-age (seconds)");
    expect(hsts.getAttribute("aria-describedby")).toBeNull(); // a number field has no hint
    await chooseGroup();
    fireEvent.change(hsts, { target: { value: "soon" } });
    fireEvent.click(screen.getByRole("button", { name: "Create the route" }));
    await waitFor(() => expect(hsts.getAttribute("aria-describedby")).not.toBeNull());
    expect(document.getElementById(hsts.getAttribute("aria-describedby")!)?.textContent).toBe("Enter a whole number.");
  });

  it("creates an HTTP route with ACME and a port-80 redirect, then follows it to the agents", async () => {
    const { creates } = page("/routes/new");
    await chooseGroup();
    fireEvent.change(screen.getByLabelText("Name"), { target: { value: "wiki" } });
    fireEvent.change(screen.getByLabelText("Hostnames"), { target: { value: "wiki.example.com" } });
    fireEvent.click(screen.getByRole("button", { name: "Create the route" }));
    expect(await screen.findByText("Revision 5: applied by all 1 agents.")).toBeTruthy();
    expect(screen.getByRole("link", { name: "Open wiki to add its targets" }).getAttribute("href")).toBe("/routes/rte_new");
    const r = creates[0]!;
    expect([r.orgId, r.route?.name, r.route?.gatewayGroupId, r.route?.enabled]).toEqual(["org_1", "wiki", "ggr_eu", true]);
    expect(r.route?.spec.case === "http" && [r.route.spec.value.hostnames, r.route.spec.value.tlsMode, r.route.spec.value.port80])
      .toEqual([["wiki.example.com"], TLSMode.TLS_MODE_ACME, Port80Mode.REDIRECT]);
    expect(r.requestId).toMatch(/^[0-9a-f-]{36}$/);
  });

  it("creates a TCP route on a free port of the pools", async () => {
    const { creates } = page("/routes/new");
    fireEvent.click(await screen.findByLabelText("TCP"));
    await chooseGroup();
    fireEvent.change(screen.getByLabelText("Name"), { target: { value: "pg" } });
    expect((screen.getByLabelText("Public port") as HTMLInputElement).value).toBe("0");
    fireEvent.click(screen.getByRole("button", { name: "Create the route" }));
    await waitFor(() => expect(creates).toHaveLength(1));
    expect(creates[0]!.route?.spec).toMatchObject({ case: "tcp", value: { port: 0 } });
  });

  it("creates a TCP and UDP route with both idle timeouts, empty for their defaults", async () => {
    const { creates } = page("/routes/new");
    fireEvent.click(await screen.findByLabelText("TCP and UDP"));
    await chooseGroup();
    fireEvent.change(screen.getByLabelText("Name"), { target: { value: "dns" } });
    fireEvent.change(screen.getByLabelText("Public port"), { target: { value: "53" } });
    fireEvent.change(screen.getByLabelText("UDP flow idle timeout (seconds)"), { target: { value: "30" } });
    expect((screen.getByLabelText("TCP idle timeout (seconds)") as HTMLInputElement).value).toBe("");
    fireEvent.click(screen.getByRole("button", { name: "Create the route" }));
    await waitFor(() => expect(creates).toHaveLength(1));
    const spec = creates[0]!.route?.spec;
    expect(spec?.case === "tcpUdp" && [spec.value.port, spec.value.idleTimeoutSeconds, spec.value.flowIdleTimeoutSeconds]).toEqual([53, undefined, 30]);
  });

  it("sends no certificate ID once the route is back on ACME", async () => {
    const { creates } = page("/routes/new");
    await chooseGroup();
    fireEvent.change(screen.getByLabelText("Name"), { target: { value: "wiki" } });
    fireEvent.change(screen.getByLabelText("Hostnames"), { target: { value: "wiki.example.com" } });
    fireEvent.change(screen.getByLabelText("TLS certificate"), { target: { value: String(TLSMode.TLS_MODE_CERTIFICATE) } });
    await screen.findByRole("option", { name: /crt_wiki/ });
    fireEvent.change(screen.getByLabelText("Uploaded certificate"), { target: { value: "crt_wiki" } });
    fireEvent.change(screen.getByLabelText("TLS certificate"), { target: { value: String(TLSMode.TLS_MODE_ACME) } });
    expect(screen.queryByLabelText("Uploaded certificate")).toBeNull(); // shown with an uploaded certificate only
    fireEvent.click(screen.getByRole("button", { name: "Create the route" }));
    await waitFor(() => expect(creates).toHaveLength(1));
    expect(creates[0]!.route?.spec).toMatchObject({ case: "http", value: { tlsMode: TLSMode.TLS_MODE_ACME, certificateId: "" } });
  });

  it("preselects the org's default gateway group", async () => {
    const { creates } = page("/routes/new", undefined, () => ({ settings: { defaultGatewayGroupId: "ggr_us" } }));
    const group = await screen.findByLabelText<HTMLSelectElement>("Gateway group");
    await waitFor(() => expect(group.value).toBe("ggr_us"));
    fireEvent.change(screen.getByLabelText("Name"), { target: { value: "wiki" } });
    fireEvent.change(screen.getByLabelText("Hostnames"), { target: { value: "wiki.example.com" } });
    fireEvent.click(screen.getByRole("button", { name: "Create the route" }));
    await waitFor(() => expect(creates).toHaveLength(1));
    expect(creates[0]!.route?.gatewayGroupId).toBe("ggr_us");
    // A route of another type starts from the default as well.
    fireEvent.click(screen.getByLabelText("TCP"));
    expect(screen.getByLabelText<HTMLSelectElement>("Gateway group").value).toBe("ggr_us");
  });

  it("keeps a gateway group chosen before the org's default is read", async () => {
    let answer = () => {};
    const asked = new Promise<void>((r) => (answer = r));
    let read = false;
    page("/routes/new", undefined, async () => {
      await asked;
      read = true;
      return { settings: { defaultGatewayGroupId: "ggr_us" } };
    });
    await chooseGroup();
    answer();
    await waitFor(() => expect(read).toBe(true));
    await new Promise((r) => setTimeout(r, 50)); // the form has the default by now
    expect(screen.getByLabelText<HTMLSelectElement>("Gateway group").value).toBe("ggr_eu");
    fireEvent.click(screen.getByLabelText("TCP")); // a new form takes the default
    expect(screen.getByLabelText<HTMLSelectElement>("Gateway group").value).toBe("ggr_us");
  });

  it("preselects no gateway group when the default is not one of the org's or the settings cannot be read", async () => {
    let read = false;
    page("/routes/new", undefined, () => ((read = true), { settings: { defaultGatewayGroupId: "ggr_gone" } }));
    await screen.findByRole("option", { name: "us" });
    await waitFor(() => expect(read).toBe(true));
    await new Promise((r) => setTimeout(r, 50)); // the form has the default by now
    expect(screen.getByLabelText<HTMLSelectElement>("Gateway group").value).toBe("");
    cleanup();
    page("/routes/new"); // GetOrgSettings fails
    await screen.findByRole("option", { name: "us" });
    expect(screen.getByLabelText<HTMLSelectElement>("Gateway group").value).toBe("");
  });

  it("needs a gateway group, and shows the server's refusal", async () => {
    const { creates } = page("/routes/new", () => { throw new ConnectError("apisvc: the org's port quota is used up", Code.ResourceExhausted); });
    fireEvent.change(await screen.findByLabelText("Name"), { target: { value: "wiki" } });
    fireEvent.change(screen.getByLabelText("Hostnames"), { target: { value: "wiki.example.com" } });
    fireEvent.click(screen.getByRole("button", { name: "Create the route" }));
    expect((await screen.findByRole("alert")).textContent).toBe("Choose the gateway group that serves the route.");
    expect(creates).toEqual([]);
    await chooseGroup();
    fireEvent.click(screen.getByRole("button", { name: "Create the route" }));
    expect(await screen.findByText("apisvc: the org's port quota is used up")).toBeTruthy();
  });

  it("previews a new route without creating it", async () => {
    const { creates, previews } = page("/routes/new");
    await chooseGroup();
    fireEvent.change(screen.getByLabelText("Name"), { target: { value: "bad" } });
    fireEvent.change(screen.getByLabelText("Hostnames"), { target: { value: "wiki.example.com" } });
    fireEvent.click(screen.getByRole("button", { name: "Preview" }));
    const panel = within(await screen.findByRole("region", { name: "Preview" }));
    expect(panel.getByText("Reached at wiki.example.com")).toBeTruthy();
    expect(panel.getByText("Gateways that would serve it: gw-eu-1")).toBeTruthy();
    expect(panel.getByRole("alert").textContent).toBe("port 25432 in use on gw-eu-1");
    expect(previews.map((p) => [p.orgId, p.route?.name, p.updateMask])).toEqual([["org_1", "bad", undefined]]);
    expect(creates).toEqual([]);
  });

  it("previews a change of a route with its mask and etag", async () => {
    const { previews } = page("/routes/rte_1/edit");
    fireEvent.change(await screen.findByLabelText("Public port"), { target: { value: "25433" } });
    fireEvent.click(screen.getByRole("button", { name: "Preview" }));
    const panel = within(await screen.findByRole("region", { name: "Preview" }));
    expect(panel.getByText("Connectors its streams would go to: db-host-1")).toBeTruthy();
    expect(await panel.findByText("Reached at edge.example.net:25433")).toBeTruthy(); // at the group's public hostname (D79)
    expect(previews[0]!.etag).toBe("7");
    expect(previews[0]!.updateMask?.paths).toContain("tcp.port");
    expect(previews[0]!.route?.spec).toMatchObject({ case: "tcp", value: { port: 25433 } });
  });

  it("marks the fields a route needs, an uploaded certificate's ID only while the route uses one", async () => {
    page("/routes/new");
    await screen.findByLabelText("Labels");
    const always = ["Gateway group", "Name", "Hostnames"];
    const numbers = ["HSTS max-age (seconds)", "Largest request body (bytes, 0 for no limit)"];
    expect(marked()).toEqual([...always, ...numbers]);
    expect(unmatched()).toEqual([]);
    fireEvent.change(screen.getByLabelText("TLS certificate"), { target: { value: String(TLSMode.TLS_MODE_CERTIFICATE) } });
    await waitFor(() => expect(marked()).toEqual([...always, "Uploaded certificate", ...numbers]));
    expect(unmatched()).toEqual([]);
    fireEvent.change(screen.getByLabelText("TLS certificate"), { target: { value: String(TLSMode.TLS_MODE_ACME) } });
    await waitFor(() => expect(marked()).toEqual([...always, ...numbers]));
    // A TCP route needs its port, which may be 0 for any free one, and no hostnames.
    fireEvent.click(screen.getByLabelText("TCP"));
    await waitFor(() => expect(marked()).toEqual(["Gateway group", "Name", "Public port"]));
    expect(unmatched()).toEqual([]);
  });

  it("marks the same fields when a route is edited, without the gateway group it keeps", async () => {
    page("/routes/rte_1/edit");
    await screen.findByLabelText("Public port");
    expect(marked()).toEqual(["Name", "Public port"]);
    expect(unmatched()).toEqual([]);
  });

  // fill fills in a new HTTP route's group, name and hostnames.
  async function fill(hostnames = "wiki.example.com") {
    await chooseGroup();
    fireEvent.change(screen.getByLabelText("Name"), { target: { value: "wiki" } });
    fireEvent.change(screen.getByLabelText("Hostnames"), { target: { value: hostnames } });
  }

  // errorOf is the error the field labelled label shows.
  const errorOf = (label: string) => screen.getByLabelText(label).getAttribute("aria-describedby")?.split(" ")
    .map((id) => document.getElementById(id)).find((e) => e?.getAttribute("role") === "alert")?.textContent;

  it.each([
    ["Labels", "team=web\nweb", "Line 2: write a label as key=value."],
    ["Labels", "team: web", "Line 1: write a label as key=value."],
    ["Labels", "Team=web", "Line 1: “Team” is not a label key. A key has 1 to 63 lowercase letters, digits, dots, dashes and underscores, and starts and ends with a letter or digit."],
    ["Labels", "=web", "Line 1: “” is not a label key. A key has 1 to 63 lowercase letters, digits, dots, dashes and underscores, and starts and ends with a letter or digit."],
    ["Labels", "team=a\n\n team = b", "Line 3: team is on line 1 already."],
    ["Request headers to set", "X-Team=web", "Line 1: write a header as Name: value."],
    ["Response headers to set", "X Team: web", "Line 1: “X Team” is not a header name. A name has letters, digits and the characters !#$%&'*+-.^_`|~ only."],
    ["Request headers to set", "X-Team: a\nx-team: b", "Line 2: x-team is on line 1 already."], // a header's name has no case
  ])("checks each line of %s, and names the first that is wrong: %j", async (label, value, message) => {
    const { creates } = page("/routes/new");
    await fill();
    fireEvent.change(screen.getByLabelText(label), { target: { value } });
    fireEvent.click(screen.getByRole("button", { name: "Create the route" }));
    await waitFor(() => expect(errorOf(label)).toBe(message));
    expect(screen.getByLabelText(label).getAttribute("aria-invalid")).toBe("true");
    expect(creates).toEqual([]);
  });

  it("sends labels and headers whose values hold the separator, and a header's empty value", async () => {
    const { creates } = page("/routes/new");
    await fill();
    fireEvent.change(screen.getByLabelText("Labels"), { target: { value: "team=a=b\n\nenv=" } });
    fireEvent.change(screen.getByLabelText("Request headers to set"), { target: { value: "X-Url: http://x:8080\nX-Drop:" } });
    fireEvent.click(screen.getByRole("button", { name: "Create the route" }));
    await waitFor(() => expect(creates).toHaveLength(1));
    const r = creates[0]!.route!;
    expect([r.labels, r.spec.case === "http" && r.spec.value.requestHeadersSet]).toEqual([{ team: "a=b", env: "" }, { "X-Url": "http://x:8080", "X-Drop": "" }]);
  });

  it("offers the uploaded certificates that cover every hostname, and sends the one chosen", async () => {
    const { creates } = page("/routes/new");
    await fill("");
    fireEvent.change(screen.getByLabelText("TLS certificate"), { target: { value: String(TLSMode.TLS_MODE_CERTIFICATE) } });
    const picker = await screen.findByLabelText<HTMLSelectElement>("Uploaded certificate");
    const offered = () => [...picker.options].map((o) => o.value);
    await waitFor(() => expect(offered()).toEqual(["", "crt_wild", "crt_wiki", "crt_org"])); // without hostnames, every uploaded one
    expect(picker.options[2]!.textContent).toMatch(/^w\.example\.com, wiki\.example\.com · crt_wiki · expires \S/);
    expect(document.getElementById(picker.getAttribute("aria-describedby")!)?.textContent)
      .toBe("The org's uploaded certificates that cover every hostname. Upload one under Domains & certificates.");
    for (const [hostnames, want] of [
      [" Wiki.Example.COM. ", ["", "crt_wild", "crt_wiki"]], // as the server compares them
      ["w.example.com\nwiki.example.com", ["", "crt_wild", "crt_wiki"]],
      ["docs.example.com", ["", "crt_wild"]],
      ["a.b.example.com", [""]], // a wildcard covers one label
      ["example.com", [""]], // and not its parent
      ["wiki.example.com\nexample.org", [""]], // none covers both
      ["*.example.com", ["", "crt_wild"]], // a wildcard by the same wildcard only
    ] as const) {
      fireEvent.change(screen.getByLabelText("Hostnames"), { target: { value: hostnames } });
      await waitFor(() => expect(offered()).toEqual(want));
    }
    expect(picker.options[0]!.textContent).toBe("Choose a certificate");
    fireEvent.change(screen.getByLabelText("Hostnames"), { target: { value: "wiki.example.com\nexample.org" } });
    await waitFor(() => expect(picker.options[0]!.textContent).toBe("No uploaded certificate covers these hostnames"));
    fireEvent.change(screen.getByLabelText("Hostnames"), { target: { value: "wiki.example.com" } });
    fireEvent.change(picker, { target: { value: "crt_wiki" } });
    fireEvent.click(screen.getByRole("button", { name: "Create the route" }));
    await waitFor(() => expect(creates).toHaveLength(1));
    expect(creates[0]!.route?.spec).toMatchObject({ case: "http", value: { tlsMode: TLSMode.TLS_MODE_CERTIFICATE, certificateId: "crt_wiki" } });
  });

  it.each([
    ["no certificate", []],
    ["only certificates from ACME", [certificates[3]!]],
  ])("says so when the org has %s to upload, and needs one before it creates the route", async (_, certs) => {
    const { creates } = page("/routes/new", undefined, undefined, certs);
    await fill();
    fireEvent.change(screen.getByLabelText("TLS certificate"), { target: { value: String(TLSMode.TLS_MODE_CERTIFICATE) } });
    const picker = await screen.findByLabelText<HTMLSelectElement>("Uploaded certificate");
    await waitFor(() => expect(picker.options[0]!.textContent).toBe("The org has no uploaded certificate"));
    expect(picker.options).toHaveLength(1);
    fireEvent.click(screen.getByRole("button", { name: "Create the route" }));
    await waitFor(() => expect(errorOf("Uploaded certificate")).toBe("Choose the uploaded certificate the route uses."));
    expect(creates).toEqual([]);
  });
});
