// SPDX-License-Identifier: Apache-2.0

import { clone, create, equals } from "@bufbuild/protobuf";
import { Code } from "@connectrpc/connect";
import { cleanup, fireEvent, screen, waitFor, within } from "@testing-library/react";
import { afterEach, describe, expect, it } from "vitest";
import {
  GatewayGroupSchema, GatewayService, type CreateGatewayGroupRequest, type UpdateGatewayGroupRequest,
} from "@/gen/rpmgr/v1/gateway_pb";
import { ManifestService, type ExportManifestsRequest } from "@/gen/rpmgr/v1/manifest_pb";
import { Theme, UserService } from "@/gen/rpmgr/v1/user_pb";
import { apiError, auth, show } from "@/testing/api";
import { marked, unmatched } from "@/testing/required";

afterEach(cleanup);

const eu = create(GatewayGroupSchema, { id: "ggr_eu", name: "eu", region: "Frankfurt", publicHostnames: ["eu.example.com"], trustedProxyCidrs: ["10.0.0.0/8"], etag: "2" });
const us = create(GatewayGroupSchema, { id: "ggr_us", name: "us", region: "Virginia" });

// page renders path with the groups; UpdateGatewayGroup fails with refuse, if given.
function page(path: string, groups = [us, eu], refuse?: Error) {
  const creates: CreateGatewayGroupRequest[] = [];
  const updates: UpdateGatewayGroupRequest[] = [];
  const exports: ExportManifestsRequest[] = [];
  const view = show(path, auth({ getSession: () => ({ userId: "usr_ada", memberships: [{ orgId: "org_1", role: "owner" }] }) }), (router) => {
    router.service(UserService, { getMe: () => ({ user: { id: "usr_ada", theme: Theme.SYSTEM } }) });
    router.service(GatewayService, {
      listGatewayGroups: () => ({ gatewayGroups: groups }),
      listGateways: () => ({ gateways: [
        { id: "gtw_2", gatewayGroupId: "ggr_eu", name: "gw-eu-2", slot: 2, enabled: false, tunnelEndpoints: ["198.51.100.2:443"], status: { enrolled: true, connected: false } },
        { id: "gtw_1", gatewayGroupId: "ggr_eu", name: "gw-eu-1", slot: 1, enabled: true, tunnelEndpoints: ["198.51.100.1:443"], status: { enrolled: true, connected: true, version: "0.1.0" } },
        { id: "gtw_3", gatewayGroupId: "ggr_eu", name: "gw-eu-3", slot: 3, enabled: true, status: { enrolled: false } },
      ] }),
      createGatewayGroup: (req) => (creates.push(req), { gatewayGroup: { id: "ggr_new", name: req.gatewayGroup?.name } }),
      updateGatewayGroup: (req) => {
        updates.push(req);
        if (refuse) {
          throw refuse;
        }
        return { gatewayGroup: req.gatewayGroup };
      },
    });
    router.service(ManifestService, { exportManifests: (req) => (exports.push(req), { yaml: "kind: GatewayGroup\n", count: 1 }) });
  });
  return { ...view, creates, updates, exports };
}

describe("Gateways", () => {
  it("lists the groups by name with their gateways", async () => {
    page("/gateways");
    const table = await screen.findByRole("table");
    await waitFor(() => expect(within(table).getAllByRole("row").slice(1).map((r) => r.textContent)).toEqual([
      "euFrankfurteu.example.com1 of 3 connected",
      "usVirginia0 of 0 connected",
    ]));
  });

  it("offers the first group when there is none, and hides the offer while it is made", async () => {
    page("/gateways", []);
    expect(await screen.findByText("The org has no gateway group yet.")).toBeTruthy();
    expect(screen.queryByRole("table")).toBeNull();
    const add = screen.getAllByRole("button", { name: "New gateway group" });
    expect(add).toHaveLength(2); // the header's and the empty list's
    fireEvent.click(add[1]!);
    expect(await screen.findByRole("form", { name: "New gateway group" })).toBeTruthy();
    expect(screen.queryByText("The org has no gateway group yet.")).toBeNull();
  });

  it("leads back to the groups from a group's page", async () => {
    page("/gateways/ggr_eu");
    expect((await screen.findByRole("link", { name: "All gateway groups" })).getAttribute("href")).toBe("/gateways");
  });

  it("creates a group and opens it", async () => {
    const { creates, history } = page("/gateways");
    fireEvent.click(await screen.findByRole("button", { name: "New gateway group" }));
    const form = within(await screen.findByRole("form", { name: "New gateway group" }));
    expect([marked(screen.getByRole("form", { name: "New gateway group" })), unmatched(screen.getByRole("form", { name: "New gateway group" }))]).toEqual([["Name"], []]);
    fireEvent.change(form.getByLabelText("Name"), { target: { value: "ap" } });
    fireEvent.change(form.getByLabelText("Region"), { target: { value: "Tokyo" } });
    fireEvent.change(form.getByLabelText("Public hostnames"), { target: { value: "ap.example.com\n\n" } });
    fireEvent.click(form.getByRole("button", { name: "Create the group" }));
    await waitFor(() => expect(history.location.pathname).toBe("/gateways/ggr_new"));
    const c = creates[0]!;
    expect([c.orgId, c.gatewayGroup?.name, c.gatewayGroup?.region, c.gatewayGroup?.publicHostnames, c.gatewayGroup?.trustedProxyCidrs])
      .toEqual(["org_1", "ap", "Tokyo", ["ap.example.com"], []]);
    expect(c.requestId).toMatch(/^[0-9a-f-]{36}$/);
  });

  it("shows a group's gateways by slot, and saves its settings as a whole", async () => {
    const { updates } = page("/gateways/ggr_eu");
    expect(await screen.findByRole("heading", { name: "Gateway group eu" })).toBeTruthy();
    const members = within(screen.getByRole("region", { name: "Gateways" }));
    await waitFor(() => expect(members.getAllByRole("row").slice(1).map((r) => r.textContent)).toEqual([
      "gw-eu-11198.51.100.1:443connected0.1.0Edit…DrainDecommission…", // the badges' icons are drawings, hidden from screen readers
      "gw-eu-22198.51.100.2:443offlinedrainedEdit…ResumeDecommission…",
      "gw-eu-33not enrolledEdit…DrainEnrollment token…Decommission…",
    ]));
    const form = within(screen.getByRole("form", { name: "Settings" }));
    fireEvent.change(form.getByLabelText("Trusted proxies"), { target: { value: "10.0.0.0/8\n192.168.0.0/16" } });
    fireEvent.click(form.getByRole("button", { name: "Save" }));
    expect(await form.findByText("Saved.")).toBeTruthy();
    const want = clone(GatewayGroupSchema, eu);
    want.trustedProxyCidrs = ["10.0.0.0/8", "192.168.0.0/16"];
    expect(equals(GatewayGroupSchema, updates[0]!.gatewayGroup!, want)).toBe(true);
    expect([updates[0]!.updateMask?.paths, updates[0]!.etag]).toEqual([["name", "region", "public_hostnames", "trusted_proxy_cidrs"], "2"]);
  });

  it.each([
    ["ggr_eu", "eu", "gw-eu-3", ["ggr_eu", "gtw_1", "gtw_2", "gtw_3"]],
    ["ggr_us", "us", "The group has no gateway yet.", ["ggr_us"]],
  ])("asks for the YAML of group %s and its own gateways, by ID", async (id, name, shown, ids) => {
    const { exports } = page(`/gateways/${id}`);
    await screen.findByText(shown);
    fireEvent.click(screen.getByRole("button", { name: "YAML" }));
    await screen.findByRole("dialog", { name: `${name} as YAML` });
    await waitFor(() => expect(exports.map((r) => [r.orgId, r.kinds, r.resourceIds])).toEqual([["org_1", [], ids]]));
  });

  it.each([
    ["changed since it was read", apiError(Code.FailedPrecondition, "ETAG_MISMATCH"),
      "The gateway group changed since this page loaded it. Reload the page to see it as it is now, then try again."],
    ["refused for another reason", apiError(Code.FailedPrecondition, "RESTORE_REVIEW"), "That did not work: api error"],
  ])("says so when a group's settings are not saved because the group %s", async (_, refuse, text) => {
    const { updates } = page("/gateways/ggr_eu", [us, eu], refuse);
    const form = within(await screen.findByRole("form", { name: "Settings" }));
    fireEvent.change(form.getByLabelText("Region"), { target: { value: "Paris" } });
    fireEvent.click(form.getByRole("button", { name: "Save" }));
    expect((await form.findByRole("alert")).textContent).toBe(text);
    expect(updates.map((u) => u.etag)).toEqual(["2"]);
  });
});
