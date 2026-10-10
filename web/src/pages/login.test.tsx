// SPDX-License-Identifier: Apache-2.0

import { Code } from "@connectrpc/connect";
import { cleanup, fireEvent, screen, waitFor } from "@testing-library/react";
import { afterEach, describe, expect, it } from "vitest";
import type { LoginRequest } from "@/gen/rpmgr/v1/auth_pb";
import { safeRedirect } from "@/lib/redirect";
import { apiError, auth, show } from "@/testing/api";

afterEach(cleanup);

// signIn renders the login page, whose Login answers with answer, and signs in.
async function signIn(path: string, answer: (req: LoginRequest) => object) {
  let live = false;
  const calls: LoginRequest[] = [];
  const view = show(path, {
    ...auth(),
    getSession: (req, ctx) => {
      if (!live) {
        throw apiError(Code.Unauthenticated);
      }
      return auth().getSession!(req, ctx);
    },
    login: (req) => {
      calls.push(req);
      const res = answer(req);
      live = true;
      return res;
    },
  });
  fireEvent.change(await screen.findByLabelText("E-mail address"), { target: { value: "ada@example.com" } });
  fireEvent.change(screen.getByLabelText("Password"), { target: { value: "correct horse battery" } });
  fireEvent.click(screen.getByRole("button", { name: "Sign in" }));
  return { ...view, calls };
}

describe("Login", () => {
  it("signs in and goes where the user was going", async () => {
    const { history, calls } = await signIn("/login?redirect=%2F%3Fview%3D1", () => ({ userId: "usr_ada" }));
    await waitFor(() => expect(history.location.href).toBe("/?view=1"));
    expect(await screen.findByText("Signed in as Ada")).toBeTruthy();
    expect(calls.map((c) => [c.email, c.password, c.secondFactor])).toEqual([["ada@example.com", "correct horse battery", ""]]);
  });

  it("says a wrong password without telling which part was wrong", async () => {
    await signIn("/login", () => {
      throw apiError(Code.Unauthenticated);
    });
    expect((await screen.findByRole("alert")).textContent).toBe("The e-mail address or the password is wrong.");
  });

  it("asks for a second factor and signs in with it", async () => {
    const { history, calls } = await signIn("/login", (req) => {
      if (!req.secondFactor) {
        throw apiError(Code.Unauthenticated, "MFA_REQUIRED");
      }
      if (req.secondFactor !== "123456") {
        throw apiError(Code.Unauthenticated);
      }
      return { userId: "usr_ada" };
    });
    const code = await screen.findByLabelText("Authenticator code or recovery code");
    expect(screen.queryByLabelText("Password")).toBeNull();
    fireEvent.change(code, { target: { value: "000000" } });
    fireEvent.click(screen.getByRole("button", { name: "Sign in" }));
    expect((await screen.findByRole("alert")).textContent).toBe("The code is wrong or was used already. Try the next code.");
    fireEvent.change(screen.getByLabelText("Authenticator code or recovery code"), { target: { value: "123456" } });
    fireEvent.click(screen.getByRole("button", { name: "Sign in" }));
    await waitFor(() => expect(history.location.pathname).toBe("/"));
    expect(calls.map((c) => [c.password, c.secondFactor])).toEqual([
      ["correct horse battery", ""],
      ["correct horse battery", "000000"],
      ["correct horse battery", "123456"],
    ]);
  });

  it("says when to try again after too many attempts", async () => {
    await signIn("/login", () => {
      throw apiError(Code.ResourceExhausted, undefined, 30);
    });
    expect((await screen.findByRole("alert")).textContent).toBe("Too many attempts. Try again in 30 seconds.");
  });

  it("never sends the user to another site", async () => {
    const { history } = await signIn("/login?redirect=%2F%2Fevil.example%2Fx", () => ({ userId: "usr_ada" }));
    await waitFor(() => expect(history.location.href).toBe("/"));
    for (const target of ["https://evil.example/", "//evil.example", "/\\evil.example", "javascript:alert(1)", "", undefined, 42]) {
      expect(safeRedirect(target)).toBe("/");
    }
    expect(safeRedirect("/routes?page=2#x")).toBe("/routes?page=2#x");
  });
});
