// SPDX-License-Identifier: Apache-2.0

import { create } from "@bufbuild/protobuf";
import { Code, ConnectError } from "@connectrpc/connect";
import { cleanup, fireEvent, screen, waitFor, within } from "@testing-library/react";
import { afterEach, describe, expect, it } from "vitest";
import {
  GatewayGroupSchema, GatewayPageKind, GatewayService, type DeleteGatewayPageRequest, type SetGatewayPageRequest,
} from "@/gen/rpmgr/v1/gateway_pb";
import { Theme, UserService } from "@/gen/rpmgr/v1/user_pb";
import { auth, show } from "@/testing/api";

afterEach(cleanup);

const eu = create(GatewayGroupSchema, { id: "ggr_eu", name: "eu", etag: "2" });
const own = { gatewayGroupId: "ggr_eu", kind: GatewayPageKind.MAINTENANCE, html: "<h1>Back soon</h1><script>alert(1)</script>" };

function page(refuse?: Error) {
  const sets: SetGatewayPageRequest[] = [];
  const deletes: DeleteGatewayPageRequest[] = [];
  show("/gateways/ggr_eu", auth({ getSession: () => ({ userId: "usr_ada", memberships: [{ orgId: "org_1", role: "owner" }] }) }), (router) => {
    router.service(UserService, { getMe: () => ({ user: { id: "usr_ada", theme: Theme.SYSTEM } }) });
    router.service(GatewayService, {
      listGatewayGroups: () => ({ gatewayGroups: [eu] }),
      listGateways: () => ({}),
      listGatewayPages: () => ({ gatewayPages: [own] }),
      setGatewayPage: (req) => {
        sets.push(req);
        if (refuse) {
          throw refuse;
        }
        return { gatewayPage: req.gatewayPage, revision: { dbEpoch: "e", seq: 7n } };
      },
      deleteGatewayPage: (req) => (deletes.push(req), { revision: { dbEpoch: "e", seq: 8n } }),
      previewGatewayPage: (req) => ({ url: `/gateway-page-preview/token-${req.kind}` }),
    });
  });
  return { sets, deletes };
}

async function row(name: string) {
  const card = within(await screen.findByRole("region", { name: "Pages" }));
  return within(await card.findByRole("listitem", { name }));
}

function file(name: string, body: string) {
  return new File([body], name, { type: "text/html" });
}

describe("GatewayPages", () => {
  it("shows each page as built in or own, with its placeholders", async () => {
    page();
    const notFound = await row("Not found (404)");
    expect(notFound.getByText("Built in")).toBeTruthy();
    expect(notFound.getAllByRole("code").map((c) => c.textContent)).toEqual(["{{hostname}}", "{{status}}", "{{request_id}}"]);
    const maintenance = await row("Maintenance");
    await waitFor(() => expect(maintenance.getByText("Own")).toBeTruthy());
    expect(maintenance.getAllByRole("code").map((c) => c.textContent)).toContain("{{message}}");
  });

  it("previews a page as the controller renders it, in a frame that runs no script", async () => {
    page();
    const maintenance = await row("Maintenance");
    fireEvent.click(await maintenance.findByRole("button", { name: "Preview" }));
    const frame = (await maintenance.findByTitle("Preview of the page Maintenance")) as HTMLIFrameElement;
    expect(frame.getAttribute("sandbox")).toBe("");
    expect(frame.getAttribute("src")).toBe(`/gateway-page-preview/token-${GatewayPageKind.MAINTENANCE}`);
    expect(frame.hasAttribute("srcdoc")).toBe(false); // never the page's HTML under the UI's own origin
    fireEvent.click(maintenance.getByRole("button", { name: "Hide the preview" }));
    expect(maintenance.queryByTitle("Preview of the page Maintenance")).toBeNull();
    // A built-in page has a preview too.
    const notFound = await row("Not found (404)");
    fireEvent.click(notFound.getByRole("button", { name: "Preview" }));
    expect(((await notFound.findByTitle("Preview of the page Not found (404)")) as HTMLIFrameElement).getAttribute("src"))
      .toBe(`/gateway-page-preview/token-${GatewayPageKind.NOT_FOUND}`);
  });

  it("uploads a page's HTML, and refuses a file above the limit before it uploads", async () => {
    const calls = page();
    const notFound = await row("Not found (404)");
    const input = notFound.getByLabelText("Upload HTML…") as HTMLInputElement;
    fireEvent.change(input, { target: { files: [file("big.html", "a".repeat(64 * 1024 + 1))] } });
    expect((await notFound.findByRole("alert")).textContent).toBe("The file has 65537 bytes; a page has at most 65536.");
    expect(calls.sets).toHaveLength(0);
    fireEvent.change(input, { target: { files: [file("404.html", "<p>{{hostname}} is not here</p>")] } });
    await waitFor(() => expect(calls.sets).toHaveLength(1));
    expect([calls.sets[0]!.gatewayPage?.gatewayGroupId, calls.sets[0]!.gatewayPage?.kind, calls.sets[0]!.gatewayPage?.html])
      .toEqual(["ggr_eu", GatewayPageKind.NOT_FOUND, "<p>{{hostname}} is not here</p>"]);
  });

  it("shows why the server refused a page", async () => {
    page(new ConnectError("apisvc: a page is UTF-8", Code.InvalidArgument));
    const unavailable = await row("Unavailable (502, 503, 504)");
    fireEvent.change(unavailable.getByLabelText("Upload HTML…"), { target: { files: [file("x.html", "<p>x</p>")] } });
    expect((await unavailable.findByRole("alert")).textContent).toBe("apisvc: a page is UTF-8");
  });

  it("goes back to the built-in page after a confirmation", async () => {
    const calls = page();
    const maintenance = await row("Maintenance");
    fireEvent.click(await maintenance.findByRole("button", { name: "Reset…" }));
    expect(maintenance.getByText("Go back to the built-in page Maintenance?")).toBeTruthy();
    fireEvent.click(maintenance.getByRole("button", { name: "Use the built-in page" }));
    await waitFor(() => expect(calls.deletes.map((d) => [d.gatewayGroupId, d.kind])).toEqual([["ggr_eu", GatewayPageKind.MAINTENANCE]]));
  });
});
