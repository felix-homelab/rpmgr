// SPDX-License-Identifier: Apache-2.0

import { Code, ConnectError } from "@connectrpc/connect";
import { cleanup, fireEvent, screen, waitFor, within } from "@testing-library/react";
import { afterEach, describe, expect, it } from "vitest";
import { Theme, UserService, type ChangePasswordRequest, type UpdateMeRequest } from "@/gen/rpmgr/v1/user_pb";
import { auth, show } from "@/testing/api";

afterEach(() => {
  cleanup();
  delete document.documentElement.dataset.theme;
});

const pw = "correct horse battery";

// account renders the account page of Ada, whose stored theme is theme.
function account(theme: Theme, changePassword?: (req: ChangePasswordRequest) => object) {
  const updates: UpdateMeRequest[] = [];
  let user = { id: "usr_ada", email: "ada@example.com", displayName: "Ada", theme };
  show("/account", auth(), (router) =>
    router.service(UserService, {
      getMe: () => ({ user }),
      updateMe: (req) => {
        updates.push(req);
        user = { ...user, displayName: req.displayName, theme: req.theme || user.theme };
        return { user };
      },
      changePassword: changePassword ?? (() => ({})),
    }),
  );
  return { updates };
}

async function section(name: string) {
  return within(await screen.findByRole("region", { name }));
}

describe("Account", () => {
  it("applies the stored theme on every page", async () => {
    account(Theme.DARK);
    await waitFor(() => expect(document.documentElement.dataset.theme).toBe("dark"));
  });

  it("changes the name and the theme together, and applies the theme at once", async () => {
    const { updates } = account(Theme.SYSTEM);
    const profile = await section("Profile");
    const name = await profile.findByLabelText("Your name");
    expect((name as HTMLInputElement).value).toBe("Ada");
    expect((profile.getByLabelText("E-mail address") as HTMLInputElement).readOnly).toBe(true);
    expect((profile.getByLabelText("Like the system") as HTMLInputElement).checked).toBe(true);
    fireEvent.change(name, { target: { value: "Ada L." } });
    fireEvent.click(profile.getByLabelText("Light"));
    fireEvent.click(profile.getByRole("button", { name: "Save" }));
    expect((await profile.findByRole("status")).textContent).toBe("Saved.");
    expect(updates.map((u) => [u.displayName, u.theme])).toEqual([["Ada L.", Theme.LIGHT]]);
    expect(document.documentElement.dataset.theme).toBe("light");
  });

  it("changes the password", async () => {
    const calls: ChangePasswordRequest[] = [];
    account(Theme.SYSTEM, (req) => (calls.push(req), {}));
    const password = await section("Password");
    fireEvent.change(await password.findByLabelText("Current password"), { target: { value: "old password!" } });
    fireEvent.change(password.getByLabelText("New password"), { target: { value: pw } });
    fireEvent.change(password.getByLabelText("Repeat the new password"), { target: { value: pw } });
    fireEvent.click(password.getByRole("button", { name: "Change the password" }));
    expect((await password.findByRole("status")).textContent).toContain("your other sessions have ended");
    expect(calls.map((c) => [c.currentPassword, c.newPassword])).toEqual([["old password!", pw]]);
    expect((password.getByLabelText("Current password") as HTMLInputElement).value).toBe("");
  });

  it("says when the current password is wrong, and checks the new one first", async () => {
    const calls: ChangePasswordRequest[] = [];
    account(Theme.SYSTEM, (req) => {
      calls.push(req);
      throw new ConnectError("apisvc: the current password is wrong", Code.InvalidArgument);
    });
    const password = await section("Password");
    fireEvent.change(await password.findByLabelText("New password"), { target: { value: pw } });
    fireEvent.click(password.getByRole("button", { name: "Change the password" }));
    expect((await password.findByRole("alert")).textContent).toBe("The two passwords differ.");
    expect(calls).toEqual([]);
    fireEvent.change(password.getByLabelText("Repeat the new password"), { target: { value: pw } });
    fireEvent.click(password.getByRole("button", { name: "Change the password" }));
    await waitFor(() => expect(password.getByRole("alert").textContent).toBe("The current password is wrong."));
  });

  it("is linked from the header", async () => {
    show("/", auth(), (router) => router.service(UserService, { getMe: () => ({ user: { id: "usr_ada", theme: Theme.SYSTEM } }) }));
    expect((await screen.findByRole("link", { name: "Ada" })).getAttribute("href")).toBe("/account");
  });
});
