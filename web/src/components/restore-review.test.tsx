// SPDX-License-Identifier: Apache-2.0

import { timestampFromDate } from "@bufbuild/protobuf/wkt";
import { Code } from "@connectrpc/connect";
import { cleanup, fireEvent, screen, waitFor, within } from "@testing-library/react";
import { afterEach, describe, expect, it } from "vitest";
import { OrgService } from "@/gen/rpmgr/v1/org_pb";
import { Theme, UserService } from "@/gen/rpmgr/v1/user_pb";
import { apiError, auth, show } from "@/testing/api";

afterEach(cleanup);

const since = timestampFromDate(new Date("2026-10-09T12:00:00Z"));

// review renders path for Ada with role in org_1; instance and org say whether each is in review.
function review(path: string, { role = "owner", instance = true, org = true, confirm = (): object => ({}) } = {}) {
  const calls = { resumed: [] as string[], confirmed: [] as string[], listed: 0 };
  let steppedUp = false;
  let orgInReview = org;
  const needStepUp = () => {
    if (!steppedUp) {
      throw apiError(Code.Unauthenticated, "STEP_UP_REQUIRED");
    }
  };
  const view = show(path, auth({
    getSession: () => ({ userId: "usr_ada", displayName: "Ada", memberships: [{ orgId: "org_1", role }] }),
    stepUp: () => ((steppedUp = true), {}),
  }), (router) => {
    router.service(UserService, { getMe: () => ({ user: { id: "usr_ada", theme: Theme.SYSTEM }, restoreReviewTime: instance ? since : undefined }) });
    router.service(OrgService, {
      getOrg: () => ({ org: { id: "org_1", name: "Acme", slug: "acme", restoreReviewTime: orgInReview ? since : undefined } }),
      updateOrg: () => {
        throw apiError(Code.FailedPrecondition, "RESTORE_REVIEW");
      },
      listMembers: () => ({ members: [{ userId: "usr_ada", displayName: "Ada", email: "ada@example.com", role }] }),
      listSuspendedAPITokens: () => (calls.listed++, { apiTokens: [{ apiToken: { id: "atk_ci", name: "ci", prefix: "rpmgr_pat_ab12", scopes: ["org.read"], suspendTime: since }, ownerId: "usr_bob", ownerEmail: "bob@example.com" }] }),
      resumeAPIToken: (req) => (needStepUp(), calls.resumed.push(`${req.orgId}/${req.tokenId}`), {}),
      confirmRestoreReview: (req) => {
        needStepUp();
        const out = confirm();
        calls.confirmed.push(req.orgId);
        orgInReview = false;
        return out;
      },
    });
  });
  return { ...view, calls };
}

async function confirmStepUp() {
  const dialog = within(await screen.findByRole("dialog", { name: "Confirm it is you" }));
  fireEvent.change(dialog.getByLabelText("Password"), { target: { value: "pw" } });
  fireEvent.click(dialog.getByRole("button", { name: "Confirm" }));
}

describe("RestoreReviewBanner", () => {
  it("tells everyone that only the Instance Admin ends the review, on the controller host", async () => {
    review("/", { role: "viewer" });
    const banner = within(await screen.findByRole("region", { name: "Restore review" }));
    expect(banner.getByText(/^The instance is in restore review since/)).toBeTruthy();
    expect(banner.getByText("rpmgr restore confirm")).toBeTruthy();
    expect(banner.getByRole("link", { name: "Review your organisation" }).getAttribute("href")).toBe("/org");
    expect(banner.queryByRole("button")).toBeNull(); // nothing in the UI ends the review
  });

  it("is not shown outside a review", async () => {
    review("/", { instance: false, org: false });
    await screen.findByRole("navigation", { name: "Main navigation" });
    await waitFor(() => expect(screen.queryByRole("region", { name: "Restore review" })).toBeNull());
  });

  it("explains a change the review refused", async () => {
    review("/org", { instance: false });
    const name = await screen.findByLabelText("Name");
    fireEvent.change(name, { target: { value: "Acme Ltd" } });
    fireEvent.click(within(screen.getByRole("form", { name: "The organisation's name" })).getByRole("button", { name: "Save" }));
    const banner = within(await screen.findByRole("region", { name: "Restore review" }));
    expect(banner.getByRole("alert").textContent).toMatch(/^That change was not saved: the organisation, or the instance, is read-only/);
    fireEvent.click(banner.getByRole("button", { name: "Dismiss" }));
    await waitFor(() => expect(screen.queryByRole("region", { name: "Restore review" })).toBeNull());
  });
});

describe("OrgPage in restore review", () => {
  it("lets the Owner resume a suspended token and confirm the org, each after a step-up", async () => {
    const { calls } = review("/org");
    const section = within(await screen.findByRole("region", { name: "Review this organisation after the restore" }));
    const row = within((await section.findByText("bob@example.com")).closest("tr")!);
    expect(row.getByText("rpmgr_pat_ab12")).toBeTruthy();
    fireEvent.click(row.getByRole("button", { name: "Resume ci" }));
    await confirmStepUp();
    await waitFor(() => expect(calls.resumed).toEqual(["org_1/atk_ci"]));
    fireEvent.click(section.getByRole("button", { name: "Confirm members and roles" }));
    await waitFor(() => expect(calls.confirmed).toEqual(["org_1"]));
    await waitFor(() => expect(screen.queryByRole("region", { name: "Review this organisation after the restore" })).toBeNull());
  });

  it("shows a refused confirmation", async () => {
    const { calls } = review("/org", { confirm: () => {
      throw apiError(Code.PermissionDenied);
    } });
    const section = within(await screen.findByRole("region", { name: "Review this organisation after the restore" }));
    fireEvent.click(section.getByRole("button", { name: "Confirm members and roles" }));
    await confirmStepUp();
    expect((await section.findByRole("alert")).textContent).toBe("api error");
    expect(calls.confirmed).toEqual([]);
  });

  it("tells a member who is no Owner that the org is read-only, without the checklist", async () => {
    const { calls } = review("/org", { role: "admin" });
    const notice = await screen.findByText(/^This organisation is read-only since the restore/);
    expect(notice.closest("[role=status]")?.textContent).toMatch(/rpmgr restore confirm --org acme$/);
    expect(screen.queryByRole("button", { name: "Confirm members and roles" })).toBeNull();
    expect(calls.listed).toBe(0);
  });
});
