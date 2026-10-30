// SPDX-License-Identifier: Apache-2.0

import { create } from "@bufbuild/protobuf";
import { timestampFromDate } from "@bufbuild/protobuf/wkt";
import { Code, ConnectError } from "@connectrpc/connect";
import { cleanup, fireEvent, screen, waitFor } from "@testing-library/react";
import { afterEach, describe, expect, it, vi } from "vitest";
import { ConnectorSchema, ConnectorService, DataTransport } from "@/gen/rpmgr/v1/connector_pb";
import { GatewayService } from "@/gen/rpmgr/v1/gateway_pb";
import { LogService, type StreamLogsRequest } from "@/gen/rpmgr/v1/log_pb";
import { RouteService } from "@/gen/rpmgr/v1/route_pb";
import { StatusService } from "@/gen/rpmgr/v1/status_pb";
import { Theme, UserService } from "@/gen/rpmgr/v1/user_pb";
import { auth, show } from "@/testing/api";

afterEach(() => {
  cleanup();
  vi.restoreAllMocks();
});

const db = create(ConnectorSchema, { id: "con_db", name: "db-host-1", enabled: true, transport: DataTransport.AUTO, session: { connected: true } });
const local = create(ConnectorSchema, { id: "con_local", name: "local", enabled: true, builtIn: true, session: { connected: true } });
const at = timestampFromDate(new Date("2026-10-25T09:00:00Z"));

// page shows a connector's page for a member of role; StreamLogs answers with stream.
function page(path: string, role: string, stream: (req: StreamLogsRequest) => AsyncIterable<object>) {
  const requests: StreamLogsRequest[] = [];
  show(path, auth({ getSession: () => ({ userId: "usr_ada", memberships: [{ orgId: "org_1", role }] }) }), (router) => {
    router.service(UserService, { getMe: () => ({ user: { id: "usr_ada", theme: Theme.SYSTEM } }) });
    router.service(GatewayService, { listGateways: () => ({}) });
    router.service(StatusService, { async *watchApplyStatus() {} });
    router.service(RouteService, { listRoutes: () => ({ routes: [] }) });
    router.service(ConnectorService, {
      listConnectors: () => ({ connectors: [db, local] }),
      getConnector: (req) => ({ connector: [db, local].find((c) => c.id === req.connectorId) }),
      getConnectorStatus: () => ({ status: {} }),
    });
    router.service(LogService, { streamLogs: (req) => (requests.push(req), stream(req)) });
  });
  return requests;
}

describe("LiveLog", () => {
  it("follows a connector's log with its level, filter and raise, and marks dropped and cut lines", async () => {
    const requests = page("/connectors/con_db", "owner", async function* () {
      yield { line: { time: at, level: "info", text: "msg=ready" } };
      yield { line: { time: at, level: "debug", text: "msg=dialing", droppedBefore: 3, truncated: true } };
    });
    fireEvent.change(await screen.findByLabelText("Level"), { target: { value: "debug" } });
    fireEvent.change(screen.getByLabelText("Only lines containing"), { target: { value: "dial" } });
    fireEvent.click(screen.getByLabelText("Raise to debug while open (audited)"));
    fireEvent.click(screen.getByRole("button", { name: "Start" }));
    const log = await screen.findByRole("log", { name: "Live log lines" });
    await waitFor(() => expect(log.textContent).toContain("msg=dialing"));
    expect([...log.children].map((c) => c.textContent)).toEqual([
      "2026-10-25T09:00:00.000Z INFO  msg=ready",
      "… 3 lines dropped: the agent logged faster than lines could be sent",
      "2026-10-25T09:00:00.000Z DEBUG msg=dialing …(cut)",
    ]);
    expect(requests[0]).toMatchObject({ agentId: "con_db", level: "debug", filter: "dial", raiseToDebug: true });
    // The stream ended at its deadline: the panel says so and goes on with a new one.
    expect(await screen.findByText("The live log ended at its time limit. Continue opens a new one.")).toBeTruthy();
    fireEvent.click(screen.getByRole("button", { name: "Continue" }));
    await waitFor(() => expect(requests).toHaveLength(2));
  });

  it("does not show a line twice when Continue opens a new stream with the backlog again", async () => {
    let opened = 0;
    const requests = page("/connectors/con_db", "owner", async function* () {
      opened++;
      yield { line: { time: at, level: "info", text: "msg=earlier", backlog: true } };
      yield { line: { time: at, level: "info", text: `msg=live-${opened}` } };
    });
    fireEvent.click(await screen.findByRole("button", { name: "Start" }));
    fireEvent.click(await screen.findByRole("button", { name: "Continue" }));
    await waitFor(() => expect(requests).toHaveLength(2));
    const log = await screen.findByRole("log", { name: "Live log lines" });
    await waitFor(() => expect(log.textContent).toContain("msg=live-2"));
    expect([...log.children].filter((c) => c.textContent?.includes("msg=earlier"))).toHaveLength(1);
    expect(log.textContent).not.toContain("msg=live-1");
  });

  it.each([[Code.Unavailable, "The agent is offline, or its rpmgr release has no live logs."],
    [Code.ResourceExhausted, "Too many live logs are open, for you or for this agent. Close one and try again."]])(
    "says why a stream failed (%s)", async (code, text) => {
      page("/connectors/con_db", "admin", async function* () {
        yield* [];
        throw new ConnectError("refused", code);
      });
      fireEvent.click(await screen.findByRole("button", { name: "Start" }));
      expect(await screen.findByText(text)).toBeTruthy();
    });

  it("pauses scrolling while lines keep arriving, and stops a stream without an error", async () => {
    page("/connectors/con_db", "owner", async function* () {
      yield { line: { time: at, level: "info", text: "msg=ready" } };
      await new Promise(() => {}); // the agent stays quiet until the viewer stops
    });
    fireEvent.click(await screen.findByRole("button", { name: "Start" }));
    const log = await screen.findByRole("log", { name: "Live log lines" });
    await waitFor(() => expect(log.textContent).toContain("msg=ready"));
    fireEvent.click(screen.getByRole("button", { name: "Pause" }));
    expect(screen.getByRole("button", { name: "Resume scrolling" }).getAttribute("aria-pressed")).toBe("true");
    fireEvent.click(screen.getByRole("button", { name: "Stop" }));
    expect(await screen.findByRole("button", { name: "Continue" })).toBeTruthy();
    expect(screen.queryByText("The live log ended at its time limit. Continue opens a new one.")).toBeNull();
    expect(log.textContent).toContain("msg=ready");
  });

  it("shows markup in a line as text", async () => {
    page("/connectors/con_db", "owner", async function* () {
      yield { line: { time: at, level: "info", text: "msg=<script>alert(1)</script><img src=x onerror=alert(2)>" } };
    });
    fireEvent.click(await screen.findByRole("button", { name: "Start" }));
    const log = await screen.findByRole("log", { name: "Live log lines" });
    await waitFor(() => expect(log.textContent).toContain("<script>alert(1)</script>"));
    expect(log.querySelector("script, img")).toBeNull();
  });

  it("ends its stream when the page goes away", async () => {
    page("/connectors/con_db", "owner", async function* () {
      yield { line: { time: at, level: "info", text: "msg=ready" } };
      await new Promise(() => {}); // the agent stays quiet
    });
    fireEvent.click(await screen.findByRole("button", { name: "Start" }));
    const log = await screen.findByRole("log", { name: "Live log lines" });
    await waitFor(() => expect(log.textContent).toContain("msg=ready"));
    const abort = vi.spyOn(AbortController.prototype, "abort");
    cleanup();
    expect(abort).toHaveBeenCalled();
  });

  it("is not shown to an Operator or a Viewer, and explains the built-in connector", async () => {
    for (const role of ["operator", "viewer"]) {
      page("/connectors/con_db", role, async function* () {});
      await screen.findByText("db-host-1", { exact: false });
      expect(screen.queryByRole("heading", { name: "Live log" })).toBeNull();
      cleanup();
    }
    page("/connectors/con_local", "owner", async function* () {});
    expect(await screen.findByText(/The built-in connector of an all-in-one has no live log here/)).toBeTruthy();
    expect(screen.queryByRole("button", { name: "Start" })).toBeNull();
  });
});
