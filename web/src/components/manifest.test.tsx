// SPDX-License-Identifier: Apache-2.0

import { Code } from "@connectrpc/connect";
import { cleanup, fireEvent, screen, waitFor, within } from "@testing-library/react";
import { afterEach, describe, expect, it, vi } from "vitest";
import { ManifestService, type ExportManifestsRequest } from "@/gen/rpmgr/v1/manifest_pb";
import { RouteService } from "@/gen/rpmgr/v1/route_pb";
import { Theme, UserService } from "@/gen/rpmgr/v1/user_pb";
import { cspNonce } from "@/lib/csp";
import { apiError, auth, show } from "@/testing/api";

afterEach(() => {
  cleanup();
  vi.restoreAllMocks();
  document.head.querySelectorAll('meta[property="csp-nonce"]').forEach((m) => m.remove());
});

const yaml = "kind: Route\nmetadata:\n  name: web\nspec:\n  http:\n    hostnames: [web.example.com]\n";

function page(path: string, fail = false) {
  const asked: ExportManifestsRequest[] = [];
  show(path, auth({
    getSession: () => ({ userId: "usr_ada", displayName: "Ada", memberships: [{ orgId: "org_1", role: "viewer" }] }),
  }), (router) => {
    router.service(UserService, { getMe: () => ({ user: { id: "usr_ada", theme: Theme.SYSTEM } }) });
    router.service(RouteService, {
      listRoutes: () => ({ routes: [{ id: "rte_1", name: "web", spec: { case: "http", value: { hostnames: ["web.example.com"] } } }] }),
      getRoute: () => ({ route: { id: "rte_1", name: "web", spec: { case: "http", value: { hostnames: ["web.example.com"] } } } }),
    });
    router.service(ManifestService, {
      exportManifests: (req) => {
        asked.push(req);
        if (fail) {
          throw apiError(Code.NotFound);
        }
        return { yaml, count: 1 };
      },
    });
  });
  return asked;
}

describe("ManifestButton", () => {
  it("exports a kind as YAML, read-only, to copy and download", async () => {
    const write = vi.fn(() => Promise.resolve());
    Object.assign(navigator, { clipboard: { writeText: write } });
    const url = vi.spyOn(URL, "createObjectURL").mockReturnValue("blob:x");
    vi.spyOn(URL, "revokeObjectURL").mockImplementation(() => {});
    const click = vi.spyOn(HTMLAnchorElement.prototype, "click").mockImplementation(function (this: HTMLAnchorElement) {
      expect([this.href, this.download]).toEqual(["blob:x", "routes.yaml"]);
    });
    const asked = page("/routes");
    fireEvent.click(await screen.findByRole("button", { name: "Export YAML" }));
    const dialog = within(await screen.findByRole("dialog", { name: "Routes as YAML" }));
    expect(await dialog.findByText("1 resource. Editing and importing YAML come with Phase 2.")).toBeTruthy();
    const editor = await dialog.findByRole("textbox", { name: "Routes as YAML" });
    expect(editor.getAttribute("aria-readonly")).toBe("true");
    expect(editor.textContent).toBe(yaml.replaceAll("\n", ""));
    expect(asked.map((r) => [r.orgId, r.kinds, r.resourceIds])).toEqual([["org_1", ["Route"], []]]);

    fireEvent.click(dialog.getByRole("button", { name: "Copy" }));
    await waitFor(() => expect(write).toHaveBeenCalledWith(yaml));
    expect(await dialog.findByRole("button", { name: "Copied" })).toBeTruthy();
    fireEvent.click(dialog.getByRole("button", { name: "Download" }));
    expect(click).toHaveBeenCalledTimes(1);
    const blob = url.mock.calls[0]![0] as Blob;
    expect([blob.type, await blob.text()]).toEqual(["application/yaml", yaml]);

    fireEvent.click(dialog.getByRole("button", { name: "Close" }));
    expect(screen.queryByRole("dialog")).toBeNull();
  });

  it("shows one route's YAML from its detail", async () => {
    const asked = page("/routes/rte_1");
    fireEvent.click(await screen.findByRole("button", { name: "YAML" }));
    const dialog = within(await screen.findByRole("dialog", { name: "web as YAML" }));
    await dialog.findByRole("textbox", { name: "web as YAML" });
    expect(asked.map((r) => [r.kinds, r.resourceIds])).toEqual([[[], ["rte_1"]]]);
  });

  it("says why the YAML could not be read, and offers nothing to copy", async () => {
    page("/routes", true);
    fireEvent.click(await screen.findByRole("button", { name: "Export YAML" }));
    const dialog = within(await screen.findByRole("dialog", { name: "Routes as YAML" }));
    expect((await dialog.findByRole("alert")).textContent).toBe("api error");
    expect((dialog.getByRole("button", { name: "Copy" }) as HTMLButtonElement).disabled).toBe(true);
    expect((dialog.getByRole("button", { name: "Download" }) as HTMLButtonElement).disabled).toBe(true);
  });
});

describe("cspNonce", () => {
  function meta(nonce: string) {
    const m = document.createElement("meta");
    m.setAttribute("property", "csp-nonce");
    m.nonce = nonce;
    document.head.append(m);
  }

  it("reads the page's nonce from its property", () => {
    expect(cspNonce()).toBeUndefined();
    meta("bm9uY2Vub25jZQ==");
    expect(cspNonce()).toBe("bm9uY2Vub25jZQ==");
  });

  it("takes the build's placeholder for none", () => {
    meta("RPMGR_CSP_NONCE");
    expect(cspNonce()).toBeUndefined();
  });
});
