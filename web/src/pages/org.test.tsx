// SPDX-License-Identifier: Apache-2.0

import { Code } from "@connectrpc/connect";
import { cleanup, fireEvent, screen, waitFor, within } from "@testing-library/react";
import { afterEach, describe, expect, it } from "vitest";
import { OrgService, type AcceptInvitationRequest, type CreateInvitationRequest, type UpdateMemberRequest } from "@/gen/rpmgr/v1/org_pb";
import { Theme, UserService } from "@/gen/rpmgr/v1/user_pb";
import { apiError, auth, show } from "@/testing/api";

afterEach(cleanup);

function page(path: string, signedIn = true) {
  const calls = { update: [] as UpdateMemberRequest[], remove: [] as string[], invite: [] as CreateInvitationRequest[], accept: [] as AcceptInvitationRequest[], rename: [] as string[] };
  let steppedUp = false;
  const view = show(path, auth({
    getSession: () => {
      if (!signedIn) {
        throw apiError(Code.Unauthenticated);
      }
      return { userId: "usr_ada", displayName: "Ada", memberships: [{ orgId: "org_1", role: "owner" }] };
    },
    stepUp: () => ((steppedUp = true), {}),
  }), (router) => {
    router.service(UserService, { getMe: () => ({ user: { id: "usr_ada", theme: Theme.SYSTEM } }) });
    router.service(OrgService, {
      getOrg: () => ({ org: { id: "org_1", name: "Acme" } }),
      updateOrg: (req) => (calls.rename.push(req.name), { org: { id: "org_1", name: req.name } }),
      listMembers: () => ({ members: [
        { userId: "usr_ada", displayName: "Ada", email: "ada@example.com", role: "owner" },
        { userId: "usr_bob", displayName: "Bob", email: "bob@example.com", role: "viewer" },
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

  it("makes an invitation link to send by hand when no mail can go out", async () => {
    const { calls } = page("/org");
    const section = within(await screen.findByRole("region", { name: "Invite someone" }));
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
    fireEvent.change(screen.getByLabelText("New password"), { target: { value: "correct horse battery" } });
    fireEvent.change(screen.getByLabelText("Repeat the new password"), { target: { value: "correct horse battery" } });
    fireEvent.click(screen.getByRole("button", { name: "Join" }));
    expect((await screen.findByRole("status")).textContent).toMatch(/^Your account is ready/);
    expect(history.location.pathname).toBe("/invite");
    expect(calls.accept.map((a) => [a.token, a.displayName, a.password])).toEqual([["rpmgr_inv_tok", "Carol", "correct horse battery"]]);
  });
});
