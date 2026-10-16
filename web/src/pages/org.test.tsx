// SPDX-License-Identifier: Apache-2.0

import { Code } from "@connectrpc/connect";
import { cleanup, fireEvent, screen, waitFor, within } from "@testing-library/react";
import { afterEach, describe, expect, it } from "vitest";
import { OrgService, type AcceptInvitationRequest, type CreateInvitationRequest, type UpdateMemberRequest } from "@/gen/rpmgr/v1/org_pb";
import { Theme, UserService } from "@/gen/rpmgr/v1/user_pb";
import { apiError, auth, show } from "@/testing/api";
import { marked, unmatched } from "@/testing/required";

afterEach(cleanup);

function page(path: string, signedIn = true, role = "owner") {
  const calls = { update: [] as UpdateMemberRequest[], remove: [] as string[], invite: [] as CreateInvitationRequest[], accept: [] as AcceptInvitationRequest[], rename: [] as string[], link: [] as string[], removeTotp: [] as string[] };
  let steppedUp = false;
  const view = show(path, auth({
    getSession: () => {
      if (!signedIn) {
        throw apiError(Code.Unauthenticated);
      }
      return { userId: "usr_ada", displayName: "Ada", memberships: [{ orgId: "org_1", role }] };
    },
    stepUp: () => ((steppedUp = true), {}),
  }), (router) => {
    router.service(UserService, {
      getMe: () => ({ user: { id: "usr_ada", theme: Theme.SYSTEM } }),
      createPasswordResetLink: (req) => {
        if (!steppedUp) {
          throw apiError(Code.Unauthenticated, "STEP_UP_REQUIRED");
        }
        if (req.userId === "usr_cy") {
          throw apiError(Code.NotFound);
        }
        calls.link.push(req.userId);
        return { url: "https://panel.example.com/reset#rpmgr_prs_fake", expireTime: { seconds: 1792224000n, nanos: 0 } };
      },
      removeUserTOTP: (req) => {
        if (!steppedUp) {
          throw apiError(Code.Unauthenticated, "STEP_UP_REQUIRED");
        }
        calls.removeTotp.push(req.userId);
        return {};
      },
    });
    router.service(OrgService, {
      getOrg: () => ({ org: { id: "org_1", name: "Acme" } }),
      updateOrg: (req) => (calls.rename.push(req.name), { org: { id: "org_1", name: req.name } }),
      listMembers: () => ({ members: [
        { userId: "usr_ada", displayName: "Ada", email: "ada@example.com", role: "owner" },
        { userId: "usr_bob", displayName: "Bob", email: "bob@example.com", role: "viewer" },
        { userId: "usr_cy", displayName: "Cy", email: "cy@example.com", role: "owner" },
      ] }),
      updateMember: (req) => {
        if (req.role === "admin" && !steppedUp) {
          throw apiError(Code.Unauthenticated, "STEP_UP_REQUIRED");
        }
        calls.update.push(req);
        return {};
      },
      removeMember: (req) => (calls.remove.push(req.userId), {}),
      createInvitation: (req) => (calls.invite.push(req), { url: "https://panel.example.com/invite#rpmgr_inv_fake", emailSent: false }),
      acceptInvitation: (req) => (calls.accept.push(req), { orgId: "org_1", userId: "usr_new" }),
    });
  });
  return { ...view, calls };
}

describe("OrgPage", () => {
  it("renames the org, and grants Admin after a step-up", async () => {
    const { calls } = page("/org");
    const name = await screen.findByLabelText("Name");
    fireEvent.change(name, { target: { value: "Acme Ltd" } });
    fireEvent.click(within(screen.getByRole("form", { name: "The organisation's name" })).getByRole("button", { name: "Save" }));
    await waitFor(() => expect(calls.rename).toEqual(["Acme Ltd"]));
    fireEvent.change(await screen.findByLabelText("Role of Bob"), { target: { value: "admin" } });
    const stepUp = within(await screen.findByRole("dialog", { name: "Confirm it is you" }));
    fireEvent.change(stepUp.getByLabelText("Password"), { target: { value: "pw" } });
    fireEvent.click(stepUp.getByRole("button", { name: "Confirm" }));
    await waitFor(() => expect(calls.update.map((u) => [u.orgId, u.userId, u.role])).toEqual([["org_1", "usr_bob", "admin"]]));
  });

  it("removes a member after a confirmation that names them", async () => {
    const { calls } = page("/org");
    const row = within((await screen.findByText("bob@example.com")).closest("tr")!);
    fireEvent.click(row.getByRole("button", { name: "Remove…" }));
    expect(row.getByText("Remove Bob from the organisation?")).toBeTruthy();
    fireEvent.click(row.getByRole("button", { name: "Remove it" }));
    await waitFor(() => expect(calls.remove).toEqual(["usr_bob"]));
  });

  it("lets an Owner make a reset link and remove a second factor after a step-up, for others only", async () => {
    const { calls } = page("/org");
    const bob = within((await screen.findByText("bob@example.com")).closest("tr")!);
    fireEvent.click(bob.getByRole("button", { name: "Reset link" }));
    const stepUp = within(await screen.findByRole("dialog", { name: "Confirm it is you" }));
    fireEvent.change(stepUp.getByLabelText("Password"), { target: { value: "pw" } });
    fireEvent.click(stepUp.getByRole("button", { name: "Confirm" }));
    expect((await bob.findByLabelText("Password reset link for Bob")).textContent).toBe("https://panel.example.com/reset#rpmgr_prs_fake");
    expect(bob.getByRole("status").textContent).toMatch(/^A one-time link that sets a new password for Bob/);
    expect(calls.link).toEqual(["usr_bob"]);

    fireEvent.click(bob.getByRole("button", { name: "Remove second factor…" }));
    expect(bob.getByText(/^Remove the authenticator and recovery codes of Bob\?/)).toBeTruthy();
    fireEvent.click(bob.getByRole("button", { name: "Remove it" }));
    expect((await bob.findByText("The second factor of Bob is removed, and their sessions have ended.")).getAttribute("role")).toBe("status");
    expect(calls.removeTotp).toEqual(["usr_bob"]);

    // The server refuses a user who is also another org's: the page says why.
    const cy = within(screen.getByText("cy@example.com").closest("tr")!);
    fireEvent.click(cy.getByRole("button", { name: "Reset link" }));
    expect((await cy.findByRole("alert")).textContent).toMatch(/^You cannot recover this account/);
    // No recovery of one's own account here.
    const ada = within(screen.getByText("ada@example.com").closest("tr")!);
    expect(ada.queryByRole("button", { name: "Reset link" })).toBeNull();
  });

  it("lets an Admin make reset links for members who are no Owners, and remove no second factor", async () => {
    page("/org", true, "admin");
    const bob = within((await screen.findByText("bob@example.com")).closest("tr")!);
    expect(bob.getByRole("button", { name: "Reset link" })).toBeTruthy();
    expect(bob.queryByRole("button", { name: "Remove second factor…" })).toBeNull();
    const cy = within(screen.getByText("cy@example.com").closest("tr")!);
    expect(cy.queryByRole("button", { name: "Reset link" })).toBeNull();
  });

  it("makes an invitation link to send by hand when no mail can go out", async () => {
    const { calls } = page("/org");
    const section = within(await screen.findByRole("region", { name: "Invite someone" }));
    expect([marked(screen.getByRole("region", { name: "Invite someone" })), unmatched(screen.getByRole("region", { name: "Invite someone" }))]).toEqual([["E-mail address"], []]);
    fireEvent.change(section.getByLabelText("E-mail address"), { target: { value: " carol@example.com " } });
    fireEvent.change(section.getByLabelText("Role"), { target: { value: "operator" } });
    fireEvent.click(section.getByRole("button", { name: "Make the invitation" }));
    expect((await section.findByRole("status")).textContent).toMatch(/^This controller cannot send e-mail/);
    expect(section.getByLabelText("Invitation link").textContent).toBe("https://panel.example.com/invite#rpmgr_inv_fake");
    expect(calls.invite.map((i) => [i.orgId, i.email, i.role])).toEqual([["org_1", "carol@example.com", "operator"]]);
  });
});

describe("Invite", () => {
  it("joins with the signed-in account", async () => {
    const { calls, history } = page("/invite#rpmgr_inv_tok");
    expect(await screen.findByText("You join as Ada.")).toBeTruthy();
    fireEvent.click(screen.getByRole("button", { name: "Join" }));
    await waitFor(() => expect(history.location.pathname).toBe("/"));
    expect(calls.accept.map((a) => [a.token, a.displayName, a.password])).toEqual([["rpmgr_inv_tok", "", ""]]);
  });

  it("creates an account without a session, and stays on the page", async () => {
    const { calls, history } = page("/invite#rpmgr_inv_tok", false);
    fireEvent.change(await screen.findByLabelText("Your name"), { target: { value: "Carol" } });
    expect([marked(document), unmatched(document)]).toEqual([["Your name", "New password", "Repeat the new password"], []]);
    fireEvent.change(screen.getByLabelText("New password"), { target: { value: "correct horse battery" } });
    fireEvent.change(screen.getByLabelText("Repeat the new password"), { target: { value: "correct horse battery" } });
    fireEvent.click(screen.getByRole("button", { name: "Join" }));
    expect((await screen.findByRole("status")).textContent).toMatch(/^Your account is ready/);
    expect(history.location.pathname).toBe("/invite");
    expect(calls.accept.map((a) => [a.token, a.displayName, a.password])).toEqual([["rpmgr_inv_tok", "Carol", "correct horse battery"]]);
  });
});
