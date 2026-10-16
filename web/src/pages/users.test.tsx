// SPDX-License-Identifier: Apache-2.0

import { Code } from "@connectrpc/connect";
import { cleanup, fireEvent, screen, waitFor, within } from "@testing-library/react";
import { afterEach, describe, expect, it } from "vitest";
import { Theme, UserService, type SetInstanceAdminRequest } from "@/gen/rpmgr/v1/user_pb";
import { apiError, auth, show } from "@/testing/api";

afterEach(cleanup);

function page({ admin = true } = {}) {
  const calls = { set: [] as SetInstanceAdminRequest[], link: [] as string[], removeTotp: [] as string[], list: [] as string[] };
  let steppedUp = false;
  let users = [
    { id: "usr_ada", displayName: "Ada", email: "ada@example.com", instanceAdmin: true, mfa: true, status: "active" },
    { id: "usr_bob", displayName: "Bob", email: "bob@example.com", instanceAdmin: false, mfa: true, status: "active" },
    { id: "usr_cy", displayName: "", email: "cy@example.com", instanceAdmin: false, mfa: false, status: "disabled" },
  ];
  const needStepUp = () => {
    if (!steppedUp) {
      throw apiError(Code.Unauthenticated, "STEP_UP_REQUIRED");
    }
  };
  const view = show("/settings/users", auth({
    getSession: () => ({ userId: "usr_ada", displayName: "Ada", instanceAdmin: admin, memberships: [{ orgId: "org_1", role: "owner" }] }),
    stepUp: () => ((steppedUp = true), {}),
  }), (router) => {
    router.service(UserService, {
      getMe: () => ({ user: { id: "usr_ada", theme: Theme.SYSTEM } }),
      // Two pages: the page reads them all.
      listUsers: (req) => (calls.list.push(req.pageToken), req.pageToken === "" ? { users: users.slice(0, 2), nextPageToken: "p2" } : { users: users.slice(2) }),
      setInstanceAdmin: (req) => {
        needStepUp();
        if (req.userId === "usr_ada" && !req.instanceAdmin) {
          throw apiError(Code.FailedPrecondition);
        }
        calls.set.push(req);
        users = users.map((u) => (u.id === req.userId ? { ...u, instanceAdmin: req.instanceAdmin } : u));
        return { user: users.find((u) => u.id === req.userId) };
      },
      createPasswordResetLink: (req) => (needStepUp(), calls.link.push(req.userId), { url: "https://panel.example.com/reset#rpmgr_prs_fake" }),
      removeUserTOTP: (req) => (needStepUp(), calls.removeTotp.push(req.userId), {}),
    });
  });
  return { ...view, calls };
}

function row(email: string) {
  return within(screen.getByText(email).closest("tr")!);
}

async function confirmStepUp() {
  const stepUp = within(await screen.findByRole("dialog", { name: "Confirm it is you" }));
  fireEvent.change(stepUp.getByLabelText("Password"), { target: { value: "pw" } });
  fireEvent.click(stepUp.getByRole("button", { name: "Confirm" }));
}

describe("Users", () => {
  it("lists every user of every page, with their role, second factor and status", async () => {
    const { calls } = page();
    await screen.findByText("cy@example.com");
    expect(calls.list).toEqual(["", "p2"]);
    expect(row("ada@example.com").getByText("(you)")).toBeTruthy();
    expect(row("bob@example.com").getAllByText("yes")).toHaveLength(1); // a second factor, no Instance Admin
    expect(row("cy@example.com").getByText("disabled")).toBeTruthy();
    expect(row("cy@example.com").getByText("never")).toBeTruthy();
    // A second factor to remove only where there is one, and no recovery of one's own account.
    expect(row("cy@example.com").queryByRole("button", { name: "Remove second factor…" })).toBeNull();
    expect(row("ada@example.com").queryByRole("button", { name: "Reset link" })).toBeNull();
  });

  it("grants the Instance Admin role after a confirmation and a step-up, and shows why the last one stays", async () => {
    const { calls } = page();
    await screen.findByText("bob@example.com");
    fireEvent.click(row("bob@example.com").getByRole("button", { name: "Make Instance Admin…" }));
    expect(row("bob@example.com").getByText(/^Make Bob Instance Admin\?/)).toBeTruthy();
    fireEvent.click(row("bob@example.com").getByRole("button", { name: "Confirm" }));
    await confirmStepUp();
    await waitFor(() => expect(calls.set.map((s) => [s.userId, s.instanceAdmin])).toEqual([["usr_bob", true]]));
    expect(await row("bob@example.com").findByRole("button", { name: "Revoke Instance Admin…" })).toBeTruthy();

    fireEvent.click(row("ada@example.com").getByRole("button", { name: "Revoke Instance Admin…" }));
    fireEvent.click(row("ada@example.com").getByRole("button", { name: "Confirm" }));
    expect((await row("ada@example.com").findByRole("alert")).textContent).toBe("api error");
    expect(calls.set).toHaveLength(1);
  });

  it("makes a reset link and removes a second factor", async () => {
    const { calls } = page();
    await screen.findByText("bob@example.com");
    fireEvent.click(row("bob@example.com").getByRole("button", { name: "Reset link" }));
    await confirmStepUp();
    expect((await row("bob@example.com").findByLabelText("Password reset link for Bob")).textContent).toBe("https://panel.example.com/reset#rpmgr_prs_fake");
    fireEvent.click(row("bob@example.com").getByRole("button", { name: "Remove second factor…" }));
    fireEvent.click(row("bob@example.com").getByRole("button", { name: "Remove it" }));
    await waitFor(() => expect(calls.removeTotp).toEqual(["usr_bob"]));
    expect(calls.link).toEqual(["usr_bob"]);
  });

  it("shows the users to the Instance Admin only", async () => {
    const { calls } = page({ admin: false });
    expect(await screen.findByText(/Instance Admin/)).toBeTruthy();
    expect(calls.list).toEqual([]);
  });
});
