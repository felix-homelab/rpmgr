// SPDX-License-Identifier: Apache-2.0

import { timestampFromDate } from "@bufbuild/protobuf/wkt";
import { cleanup, fireEvent, screen, waitFor, within } from "@testing-library/react";
import { afterEach, describe, expect, it } from "vitest";
import { Theme, UserService } from "@/gen/rpmgr/v1/user_pb";
import { auth, show } from "@/testing/api";

afterEach(cleanup);

describe("Sessions", () => {
  it("lists the sessions and ends another one after a confirmation", async () => {
    let sessions = [
      { id: "ses_now", ip: "192.0.2.1", userAgent: "Firefox/140", current: true, lastSeenTime: timestampFromDate(new Date("2026-10-09T10:00:00Z")) },
      { id: "ses_old", ip: "198.51.100.7", userAgent: "Chrome/141", current: false, lastSeenTime: timestampFromDate(new Date("2026-10-01T08:30:00Z")) },
    ];
    const revoked: string[] = [];
    show("/account", auth({
      listSessions: () => ({ sessions }),
      revokeSession: (req) => {
        revoked.push(req.sessionId);
        sessions = sessions.filter((s) => s.id !== req.sessionId);
        return {};
      },
    }), (router) => router.service(UserService, { getMe: () => ({ user: { id: "usr_ada", displayName: "Ada", theme: Theme.SYSTEM } }) }));
    const table = within(await screen.findByRole("table"));
    const rows = await table.findAllByRole("row");
    expect(rows.map((r) => r.textContent)).toEqual([
      "BrowserAddressLast activeActions",
      expect.stringContaining("Firefox/140192.0.2.1Oct 9, 2026"),
      expect.stringContaining("Chrome/141198.51.100.7Oct 1, 2026"),
    ]);
    expect(within(rows[1]!).getByText("This browser")).toBeTruthy();
    expect(within(rows[1]!).queryByRole("button")).toBeNull(); // the current session is ended by signing out
    fireEvent.click(within(rows[2]!).getByRole("button", { name: "End…" }));
    expect(within(rows[2]!).getByText("End the session from 198.51.100.7?")).toBeTruthy();
    fireEvent.click(within(rows[2]!).getByRole("button", { name: "End it" }));
    await waitFor(() => expect(table.getAllByRole("row")).toHaveLength(2));
    expect(revoked).toEqual(["ses_old"]);
  });

  it("asks again after a cancelled confirmation", async () => {
    const revoked: string[] = [];
    show("/account", auth({
      listSessions: () => ({ sessions: [{ id: "ses_old", ip: "198.51.100.7", current: false }] }),
      revokeSession: (req) => (revoked.push(req.sessionId), {}),
    }), (router) => router.service(UserService, { getMe: () => ({ user: { id: "usr_ada", theme: Theme.SYSTEM } }) }));
    const sessions = within(await screen.findByRole("region", { name: "Sessions" }));
    fireEvent.click(await sessions.findByRole("button", { name: "End…" }));
    fireEvent.click(sessions.getByRole("button", { name: "Cancel" }));
    expect(sessions.getByRole("button", { name: "End…" })).toBeTruthy();
    expect(revoked).toEqual([]);
  });
});
