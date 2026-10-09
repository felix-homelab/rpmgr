// SPDX-License-Identifier: Apache-2.0

import { cleanup, fireEvent, screen, waitFor, within } from "@testing-library/react";
import { afterEach, describe, expect, it } from "vitest";
import { matches, type Command } from "@/components/command-palette";
import { ConnectorService } from "@/gen/rpmgr/v1/connector_pb";
import { GatewayService } from "@/gen/rpmgr/v1/gateway_pb";
import { RouteService } from "@/gen/rpmgr/v1/route_pb";
import { Theme, UserService } from "@/gen/rpmgr/v1/user_pb";
import { auth, show } from "@/testing/api";

afterEach(cleanup);

function page() {
  return show("/", auth({
    getSession: () => ({ userId: "usr_ada", displayName: "Ada", memberships: [{ orgId: "org_1", role: "owner" }] }),
  }), (router) => {
    router.service(UserService, { getMe: () => ({ user: { id: "usr_ada", theme: Theme.SYSTEM } }) });
    router.service(RouteService, { listRoutes: () => ({ routes: [{ id: "rte_2", name: "postgres" }, { id: "rte_7", name: "web-postgres-admin" }] }) });
    router.service(ConnectorService, { listConnectors: () => ({ connectors: [{ id: "con_db", name: "db-host" }] }) });
    router.service(GatewayService, {
      listGatewayGroups: () => ({ gatewayGroups: [{ id: "ggr_eu", name: "eu" }] }),
      listGateways: () => ({ gateways: [{ id: "gtw_1", gatewayGroupId: "ggr_eu", name: "gw-eu-1" }] }),
    });
  });
}

// open opens the palette with its shortcut and returns its search box and its matches.
async function open(key: { ctrlKey?: boolean; metaKey?: boolean } = { ctrlKey: true }) {
  await screen.findByRole("button", { name: /^Go to…/ }); // the signed-in layout is there
  fireEvent.keyDown(window, { key: "k", ...key });
  const dialog = within(await screen.findByRole("dialog", { name: "Go to" }));
  return { dialog, box: dialog.getByRole("combobox", { name: "Page, resource or action" }) };
}

const options = (d: ReturnType<typeof within>) => d.queryAllByRole("option").map((o: HTMLElement) => o.textContent);

describe("matches", () => {
  const cmd = (label: string, id?: string): Command => ({ kind: id ? "Route" : "Page", label, id, run: () => {} });
  const all = [cmd("Routes"), cmd("web-postgres", "rte_7"), cmd("postgres", "rte_2"), cmd("db", "rte_9")];

  it("offers what is not a resource without a query", () => {
    expect(matches(all, "  ").map((c) => c.label)).toEqual(["Routes"]);
  });

  it("puts labels that start with the query first, then those that hold it, then IDs", () => {
    expect(matches(all, "POST").map((c) => c.label)).toEqual(["postgres", "web-postgres"]);
    expect(matches(all, "rte_").map((c) => c.label)).toEqual(["web-postgres", "postgres", "db"]);
    expect(matches(all, "rte_9").map((c) => c.label)).toEqual(["db"]);
    expect(matches(all, "nothing")).toEqual([]);
  });
});

describe("CommandPalette", () => {
  it("opens on Ctrl+K and jumps to a route by name with the keyboard", async () => {
    const { history } = page();
    const { dialog, box } = await open();
    expect(options(dialog)).toContain("Create a routeAction");
    fireEvent.change(box, { target: { value: "postgres" } });
    await waitFor(() => expect(options(dialog)).toEqual(["postgresRoute · rte_2", "web-postgres-adminRoute · rte_7"]));
    const [first, second] = dialog.getAllByRole("option");
    expect(first!.getAttribute("aria-selected")).toBe("true");
    expect(box.getAttribute("aria-activedescendant")).toBe(first!.id);
    fireEvent.keyDown(box, { key: "ArrowDown" });
    expect(second!.getAttribute("aria-selected")).toBe("true");
    fireEvent.keyDown(box, { key: "ArrowDown" }); // wraps
    expect(box.getAttribute("aria-activedescendant")).toBe(first!.id);
    fireEvent.keyDown(box, { key: "ArrowUp" });
    fireEvent.keyDown(box, { key: "Enter" });
    await waitFor(() => expect(history.location.pathname).toBe("/routes/rte_7"));
    expect(screen.queryByRole("dialog", { name: "Go to" })).toBeNull();
  });

  it("finds connectors, gateway groups and gateways by ID, and opens on ⌘K", async () => {
    const { history } = page();
    const { dialog, box } = await open({ metaKey: true });
    fireEvent.change(box, { target: { value: "gtw_1" } });
    await waitFor(() => expect(options(dialog)).toEqual(["gw-eu-1Gateway · gtw_1"]));
    fireEvent.click(dialog.getByRole("option"));
    await waitFor(() => expect(history.location.pathname).toBe("/gateways/ggr_eu"));
    const again = await open();
    fireEvent.change(again.box, { target: { value: "db" } });
    await waitFor(() => expect(options(again.dialog)).toEqual(["db-hostConnector · con_db"]));
  });

  it("opens the enroll dialog as an action", async () => {
    const { history } = page();
    const { dialog, box } = await open();
    fireEvent.change(box, { target: { value: "enroll" } });
    expect(options(dialog)).toEqual(["Enroll a connectorAction"]);
    fireEvent.keyDown(box, { key: "Enter" });
    expect(await screen.findByRole("dialog", { name: "Enroll a connector" })).toBeTruthy();
    expect(history.location.search).toContain("enroll=true");
  });

  it("says when nothing matches, and closes on Escape", async () => {
    page();
    const { dialog, box } = await open();
    fireEvent.change(box, { target: { value: "zzz" } });
    expect(dialog.getByText("Nothing matches.")).toBeTruthy();
    fireEvent.keyDown(box, { key: "Enter" }); // runs nothing
    fireEvent(screen.getByRole("dialog", { name: "Go to" }), new Event("cancel"));
    await waitFor(() => expect(screen.queryByRole("dialog", { name: "Go to" })).toBeNull());
  });
});
