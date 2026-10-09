// SPDX-License-Identifier: Apache-2.0

import { Code, ConnectError } from "@connectrpc/connect";
import { cleanup, fireEvent, screen, waitFor, within } from "@testing-library/react";
import { afterEach, describe, expect, it } from "vitest";
import { Theme, UserService } from "@/gen/rpmgr/v1/user_pb";
import { apiError, auth, show } from "@/testing/api";

afterEach(cleanup);

const codes = Array.from({ length: 10 }, (_, i) => `code-${i}`);

// account renders the account page of Ada with an authenticator or not; every change needs a
// step-up with the password "pw-ok" or the authenticator code "654321".
function account(mfa: boolean) {
  const calls: string[] = [];
  let steppedUp = false;
  const needStepUp = () => {
    if (!steppedUp) {
      throw apiError(Code.Unauthenticated, "STEP_UP_REQUIRED");
    }
  };
  show("/account", auth({
    stepUp: (req) => {
      if (req.password !== "pw-ok" && req.secondFactor !== "654321") {
        throw apiError(Code.Unauthenticated);
      }
      steppedUp = true;
      return {};
    },
  }), (router) =>
    router.service(UserService, {
      getMe: () => ({ user: { id: "usr_ada", email: "ada@example.com", displayName: "Ada", theme: Theme.SYSTEM, mfa } }),
      enrollTOTP: () => (needStepUp(), calls.push("enroll"), { secret: "JBSWY3DPEHPK3PXPJBSWY3DP", uri: "otpauth://totp/rpmgr:ada?secret=JBSWY3DPEHPK3PXPJBSWY3DP" }),
      confirmTOTP: (req) => {
        needStepUp();
        calls.push(`confirm ${req.code}`);
        if (req.code !== "123456") {
          throw new ConnectError("accounts: the code is not valid or was used", Code.InvalidArgument);
        }
        mfa = true;
        return { recoveryCodes: codes };
      },
      regenerateRecoveryCodes: () => (needStepUp(), calls.push("regenerate"), { recoveryCodes: codes }),
      removeTOTP: () => (needStepUp(), calls.push("remove"), (mfa = false), {}),
    }),
  );
  return calls;
}

async function mfaSection() {
  return within(await screen.findByRole("region", { name: "Two-factor authentication" }));
}

async function stepUp(label = "Password", value = "pw-ok") {
  const dialog = within(await screen.findByRole("dialog", { name: "Confirm it is you" }));
  fireEvent.change(await dialog.findByLabelText(label), { target: { value } });
  fireEvent.click(dialog.getByRole("button", { name: "Confirm" }));
}

describe("Authenticator", () => {
  it("sets one up after a step-up and shows the recovery codes once", async () => {
    const calls = account(false);
    const s = await mfaSection();
    fireEvent.click(await s.findByRole("button", { name: "Set up an authenticator" }));
    await stepUp();
    expect(await s.findByRole("img", { name: "QR code for your authenticator app" })).toBeTruthy();
    expect(s.getByText("JBSW Y3DP EHPK 3PXP JBSW Y3DP")).toBeTruthy();
    fireEvent.change(s.getByLabelText("Code from the app"), { target: { value: "000000" } });
    fireEvent.click(s.getByRole("button", { name: "Turn on" }));
    expect((await s.findByRole("alert")).textContent).toBe("The code is not valid or was used.");
    fireEvent.change(s.getByLabelText("Code from the app"), { target: { value: " 123456 " } });
    fireEvent.click(s.getByRole("button", { name: "Turn on" }));
    const list = await s.findByRole("list", { name: "Recovery codes" });
    expect(within(list).getAllByRole("listitem").map((li) => li.textContent)).toEqual(codes);
    fireEvent.click(s.getByRole("button", { name: "I have saved them" }));
    expect(await s.findByText("An authenticator is set up.")).toBeTruthy();
    expect(s.queryByRole("list", { name: "Recovery codes" })).toBeNull();
    expect(calls).toEqual(["enroll", "confirm 000000", "confirm 123456"]);
  });

  it("renews the recovery codes and removes the authenticator", async () => {
    const calls = account(true);
    const s = await mfaSection();
    fireEvent.click(await s.findByRole("button", { name: "New recovery codes" }));
    await stepUp("Authenticator code or recovery code", "654321"); // a user with an authenticator steps up with it
    await s.findByRole("list", { name: "Recovery codes" });
    fireEvent.click(s.getByRole("button", { name: "I have saved them" }));
    fireEvent.click(await s.findByRole("button", { name: "Remove the authenticator…" }));
    expect(s.getByRole("alert").textContent).toContain("ends your other sessions");
    fireEvent.click(s.getByRole("button", { name: "Remove it" }));
    expect(await s.findByRole("button", { name: "Set up an authenticator" })).toBeTruthy();
    expect(calls).toEqual(["regenerate", "remove"]);
  });

  it("shows nothing when the user cancels the step-up", async () => {
    const calls = account(false);
    const s = await mfaSection();
    fireEvent.click(await s.findByRole("button", { name: "Set up an authenticator" }));
    fireEvent.click(await screen.findByRole("button", { name: "Cancel" }));
    await waitFor(() => expect(screen.queryByRole("dialog")).toBeNull());
    expect(s.queryByRole("alert")).toBeNull();
    expect(calls).toEqual([]);
  });

  it("sends a user whom an org requires a second factor of to set one up", async () => {
    let refused = false;
    const { history } = show("/", auth(), (router) =>
      router.service(UserService, {
        getMe: () => {
          if (!refused) {
            refused = true;
            throw apiError(Code.PermissionDenied, "MFA_REQUIRED");
          }
          return { user: { id: "usr_ada", email: "ada@example.com", displayName: "Ada", theme: Theme.SYSTEM } };
        },
      }),
    );
    await waitFor(() => expect(history.location.pathname).toBe("/account"));
    expect((await screen.findByText(/requires two-factor authentication/)).textContent).toContain("Set up an authenticator");
  });
});
