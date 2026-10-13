// SPDX-License-Identifier: Apache-2.0

import { Code, ConnectError } from "@connectrpc/connect";
import { cleanup, fireEvent, screen, waitFor, within } from "@testing-library/react";
import { afterEach, describe, expect, it } from "vitest";
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

// page renders path with the gateway groups "eu" and "us"; CreateRoute answers with create, and
// GetOrgSettings with orgSettings, if given: without, the org's settings cannot be read.
function page(path: string, create?: (req: CreateRouteRequest) => object, orgSettings?: () => object | Promise<object>) {
  const creates: CreateRouteRequest[] = [];
  const previews: PreviewRouteRequest[] = [];
  const view = show(path, auth({ getSession: () => ({ userId: "usr_ada", memberships: [{ orgId: "org_1", role: "owner" }] }) }), (router) => {
    router.service(UserService, { getMe: () => ({ user: { id: "usr_ada", theme: Theme.SYSTEM } }) });
    router.service(GatewayService, {
      listGatewayGroups: () => ({ gatewayGroups: [{ id: "ggr_eu", name: "eu", publicHostnames: ["edge.example.net"] }, { id: "ggr_us", name: "us" }] }),
      listGateways: () => ({ gateways: [{ id: "gtw_1", name: "gw-eu-1" }] }),
    });
    router.service(ConnectorService, { listConnectors: () => ({ connectors: [{ id: "con_1", name: "db-host-1" }] }) });
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
    const labels = await screen.findByLabelText("Labels");
    expect(screen.queryByText(/^routeForm\./)).toBeNull(); // never a key instead of text (U11)
    expect(document.getElementById(labels.getAttribute("aria-describedby")!)?.textContent).toBe("One per line, as key=value or Name: value.");
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

  it("sends no certificate ID once the route is back on ACME", async () => {
    const { creates } = page("/routes/new");
    await chooseGroup();
    fireEvent.change(screen.getByLabelText("Name"), { target: { value: "wiki" } });
    fireEvent.change(screen.getByLabelText("Hostnames"), { target: { value: "wiki.example.com" } });
    fireEvent.change(screen.getByLabelText("TLS certificate"), { target: { value: String(TLSMode.TLS_MODE_CERTIFICATE) } });
    fireEvent.change(screen.getByLabelText("Uploaded certificate ID"), { target: { value: "crt_1" } });
    fireEvent.change(screen.getByLabelText("TLS certificate"), { target: { value: String(TLSMode.TLS_MODE_ACME) } });
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
    await waitFor(() => expect(marked()).toEqual([...always, "Uploaded certificate ID", ...numbers]));
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
});
