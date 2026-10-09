// SPDX-License-Identifier: Apache-2.0

import { Code, ConnectError } from "@connectrpc/connect";
import { cleanup, fireEvent, screen, waitFor } from "@testing-library/react";
import { afterEach, describe, expect, it } from "vitest";
import type { CompletePasswordResetRequest } from "@/gen/rpmgr/v1/auth_pb";
import { passwordProblem } from "@/pages/reset";
import { apiError, auth, show } from "@/testing/api";

afterEach(cleanup);

const pw = "correct horse battery";

// links renders path with an API whose CompletePasswordReset answers with answer; Login starts the
// session.
function links(path: string, answer: (req: CompletePasswordResetRequest) => object) {
  let live = false;
  const completed: CompletePasswordResetRequest[] = [];
  const logins: string[] = [];
  const view = show(path, auth({
    getSession: () => {
      if (!live) {
        throw apiError(Code.Unauthenticated);
      }
      return { userId: "usr_ada", email: "ada@example.com", displayName: "Ada" };
    },
    completePasswordReset: (req) => (completed.push(req), answer(req)),
    login: (req) => ((live = true), logins.push(`${req.email} ${req.password}`), { userId: "usr_ada" }),
  }));
  return { ...view, completed, logins };
}

function fill(label: string, value: string) {
  fireEvent.change(screen.getByLabelText(label), { target: { value } });
}

describe("Setup", () => {
  it("creates the first user, signs them in and keeps the token out of the address", async () => {
    const { history, completed, logins } = links("/setup#rpmgr_prs_tok", () => ({ userId: "usr_ada", email: "ada@example.com" }));
    await screen.findByRole("heading", { name: "Create the first account" });
    await waitFor(() => expect(history.location.hash).toBe(""));
    fill("E-mail address", "Ada@Example.com");
    fill("Your name", "Ada");
    fill("New password", pw);
    fill("Repeat the new password", pw);
    fireEvent.click(screen.getByRole("button", { name: "Create the account" }));
    expect(await screen.findByText("Signed in as Ada")).toBeTruthy();
    expect(history.location.pathname).toBe("/");
    expect(completed.map((c) => [c.token, c.email, c.displayName, c.newPassword])).toEqual([["rpmgr_prs_tok", "Ada@Example.com", "Ada", pw]]);
    expect(logins).toEqual([`ada@example.com ${pw}`]); // the address as the server stored it
  });

  it("checks the password before sending it", async () => {
    const { completed } = links("/setup#rpmgr_prs_tok", () => ({}));
    await screen.findByRole("heading", { name: "Create the first account" });
    fill("New password", "short");
    fireEvent.click(screen.getByRole("button", { name: "Create the account" }));
    expect((await screen.findByRole("alert")).textContent).toBe("A password has 12 to 256 characters.");
    fill("New password", pw);
    fill("Repeat the new password", pw + "!");
    fireEvent.click(screen.getByRole("button", { name: "Create the account" }));
    expect((await screen.findByRole("alert")).textContent).toBe("The two passwords differ.");
    expect(completed).toEqual([]);
  });

  it("says when the first user exists already", async () => {
    links("/setup#rpmgr_prs_tok", () => {
      throw apiError(Code.FailedPrecondition);
    });
    await screen.findByRole("heading", { name: "Create the first account" });
    fill("New password", pw);
    fill("Repeat the new password", pw);
    fireEvent.click(screen.getByRole("button", { name: "Create the account" }));
    expect((await screen.findByRole("alert")).textContent).toContain("The first account exists already.");
    expect(screen.getByRole("link", { name: "Sign in" }).getAttribute("href")).toBe("/login");
  });

  it("says when the link lacks its token", async () => {
    links("/setup", () => ({}));
    expect((await screen.findByRole("alert")).textContent).toContain("This link is incomplete.");
  });
});

describe("Reset", () => {
  it("sets the password and offers to sign in", async () => {
    const { completed } = links("/reset#rpmgr_prs_tok", () => ({ userId: "usr_ada", email: "ada@example.com" }));
    await screen.findByRole("heading", { name: "Set a new password" });
    fill("New password", pw);
    fill("Repeat the new password", pw);
    fireEvent.click(screen.getByRole("button", { name: "Set the password" }));
    expect((await screen.findByRole("status")).textContent).toContain("Your password is set");
    expect(screen.getByRole("link", { name: "Sign in" }).getAttribute("href")).toBe("/login");
    expect(completed.map((c) => [c.token, c.newPassword, c.email])).toEqual([["rpmgr_prs_tok", pw, ""]]);
  });

  it("shows why the server refused the link", async () => {
    links("/reset#rpmgr_prs_tok", () => {
      throw new ConnectError("accounts: the link is not valid, was used or has expired", Code.InvalidArgument);
    });
    await screen.findByRole("heading", { name: "Set a new password" });
    fill("New password", pw);
    fill("Repeat the new password", pw);
    fireEvent.click(screen.getByRole("button", { name: "Set the password" }));
    expect((await screen.findByRole("alert")).textContent).toBe("The link is not valid, was used or has expired.");
  });
});

describe("Forgot", () => {
  it.each([
    [undefined, "If an account uses this address, a reset link is on its way."],
    [Code.Unavailable, "This controller cannot send e-mail."],
    [Code.ResourceExhausted, "Too many attempts."],
  ])("answers %s", async (code, want) => {
    let asked = "";
    show("/login", auth({
      getSession: () => {
        throw apiError(Code.Unauthenticated);
      },
      requestPasswordReset: (req) => {
        asked = req.email;
        if (code !== undefined) {
          throw apiError(code, undefined, code === Code.ResourceExhausted ? 5 : undefined);
        }
        return {};
      },
    }));
    fireEvent.click(await screen.findByRole("link", { name: "Forgot your password?" }));
    await screen.findByRole("heading", { name: "Reset your password" });
    fill("E-mail address", "ada@example.com");
    fireEvent.click(screen.getByRole("button", { name: "Send a reset link" }));
    await waitFor(() => expect(screen.getByText((t) => t.startsWith(want))).toBeTruthy());
    expect(asked).toBe("ada@example.com");
  });
});

describe("passwordProblem", () => {
  it.each([
    ["a".repeat(11), "a".repeat(11), "reset.length"],
    ["a".repeat(12), "a".repeat(12), undefined],
    ["a".repeat(256), "a".repeat(256), undefined],
    ["a".repeat(257), "a".repeat(257), "reset.length"],
    ["ü".repeat(12), "ü".repeat(12), undefined], // characters, not bytes
    ["a".repeat(12), "b".repeat(12), "reset.mismatch"],
  ])("%#", (password, confirm, want) => {
    expect(passwordProblem(password, confirm)).toBe(want);
  });
});
