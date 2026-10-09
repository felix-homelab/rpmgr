// SPDX-License-Identifier: Apache-2.0

import { Code, ConnectError } from "@connectrpc/connect";
import { cleanup, fireEvent, screen, within } from "@testing-library/react";
import { afterEach, describe, expect, it } from "vitest";
import { TokenService, type CreateAPITokenRequest } from "@/gen/rpmgr/v1/token_pb";
import { Theme, UserService } from "@/gen/rpmgr/v1/user_pb";
import { apiError, auth, show } from "@/testing/api";

afterEach(cleanup);

// tokens renders the account page of Ada, Owner of org_1; creating a token needs a step-up with the
// password "pw-ok", and refuse, if set, refuses the creation.
function tokens(refuse?: ConnectError) {
  const creates: CreateAPITokenRequest[] = [];
  const revoked: string[] = [];
  let steppedUp = false;
  let list = [{ id: "tok_old", name: "ci", prefix: "rpmgr_pat_AbCd", scopes: ["org.read"] }];
  show("/account", auth({
    getSession: () => ({ userId: "usr_ada", displayName: "Ada", memberships: [{ orgId: "org_1", role: "owner" }] }),
    stepUp: (req) => {
      if (req.password !== "pw-ok") {
        throw apiError(Code.Unauthenticated);
      }
      steppedUp = true;
      return {};
    },
  }), (router) => {
    router.service(UserService, { getMe: () => ({ user: { id: "usr_ada", theme: Theme.SYSTEM } }) });
    router.service(TokenService, {
      listAPITokens: (req) => (expect(req.orgId).toBe("org_1"), { apiTokens: list }),
      createAPIToken: (req) => {
        creates.push(req);
        if (!steppedUp) {
          throw apiError(Code.Unauthenticated, "STEP_UP_REQUIRED");
        }
        if (refuse) {
          throw refuse;
        }
        list = [...list, { id: "tok_new", name: req.name, prefix: "rpmgr_pat_WxYz", scopes: req.scopes }];
        return { token: "rpmgr_pat_WxYzSECRET", apiToken: list[1] };
      },
      revokeAPIToken: (req) => (revoked.push(`${req.orgId} ${req.tokenId}`), (list = list.filter((t) => t.id !== req.tokenId)), {}),
    });
  });
  return { creates, revoked };
}

async function section() {
  return within(await screen.findByRole("region", { name: "API tokens" }));
}

async function fillNew(s: Awaited<ReturnType<typeof section>>, days = "30") {
  fireEvent.click(await s.findByRole("button", { name: "New token…" }));
  fireEvent.change(s.getByLabelText("Name"), { target: { value: "deploy" } });
  fireEvent.change(s.getByLabelText("Valid for (days)"), { target: { value: days } });
  fireEvent.click(s.getByLabelText(/^routes\.write/));
  fireEvent.click(s.getByRole("button", { name: "Create the token" }));
}

describe("API tokens", () => {
  it("creates a token after a step-up and shows it once", async () => {
    const { creates } = tokens();
    const s = await section();
    expect(await s.findByText("ci")).toBeTruthy();
    expect(s.getByText("rpmgr_pat_AbCd…")).toBeTruthy();
    await fillNew(s);
    const dialog = within(await screen.findByRole("dialog", { name: "Confirm it is you" }));
    fireEvent.change(dialog.getByLabelText("Password"), { target: { value: "pw-ok" } });
    fireEvent.click(dialog.getByRole("button", { name: "Confirm" }));
    expect((await s.findByLabelText("The new token")).textContent).toBe("rpmgr_pat_WxYzSECRET");
    expect(await s.findByText("deploy")).toBeTruthy();
    fireEvent.click(s.getByRole("button", { name: "I have copied it" }));
    expect(s.queryByText("rpmgr_pat_WxYzSECRET")).toBeNull();
    expect(creates.map((c) => [c.orgId, c.name, c.scopes, c.ttl?.seconds])).toEqual([
      ["org_1", "deploy", ["org.read", "routes.write"], 30n * 86400n],
      ["org_1", "deploy", ["org.read", "routes.write"], 30n * 86400n],
    ]);
    expect(creates[0]!.requestId).not.toBe("");
    expect(creates[1]!.requestId).toBe(creates[0]!.requestId); // the retry is the same request
  });

  it("refuses a validity outside 1 to 365 days without a request", async () => {
    const { creates } = tokens();
    const s = await section();
    await fillNew(s, "366");
    expect((await s.findByRole("alert")).textContent).toBe("1 to 365 days.");
    expect(creates).toEqual([]);
  });

  it("shows why the server refused the scopes", async () => {
    tokens(new ConnectError("api: the token's scopes exceed your permissions", Code.PermissionDenied));
    const s = await section();
    await fillNew(s);
    const dialog = within(await screen.findByRole("dialog", { name: "Confirm it is you" }));
    fireEvent.change(dialog.getByLabelText("Password"), { target: { value: "pw-ok" } });
    fireEvent.click(dialog.getByRole("button", { name: "Confirm" }));
    expect((await s.findByRole("alert")).textContent).toBe("The token's scopes exceed your permissions.");
  });

  it("revokes a token after a confirmation that names it", async () => {
    const { revoked } = tokens();
    const s = await section();
    fireEvent.click(await s.findByRole("button", { name: "Revoke…" }));
    expect(s.getByText("Revoke the token ci?")).toBeTruthy();
    fireEvent.click(s.getByRole("button", { name: "Revoke it" }));
    expect(await s.findByText("You have no API tokens.")).toBeTruthy();
    expect(revoked).toEqual(["org_1 tok_old"]);
  });
});
