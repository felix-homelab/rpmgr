// SPDX-License-Identifier: Apache-2.0

import { Code } from "@connectrpc/connect";
import { focusManager } from "@tanstack/react-query";
import { cleanup, fireEvent, screen, waitFor } from "@testing-library/react";
import { afterEach, describe, expect, it } from "vitest";
import { apiError, auth, show } from "@/testing/api";

afterEach(() => {
  cleanup();
  localStorage.clear();
  sessionStorage.clear();
});

describe("App", () => {
  it("shows the overview and the user with a session", async () => {
    show("/", auth());
    expect(await screen.findByText("Signed in as Ada")).toBeTruthy();
    expect(screen.getByRole("heading", { level: 1, name: "Overview" })).toBeTruthy();
    expect(screen.getByRole("navigation", { name: "Main navigation" })).toBeTruthy();
    expect(screen.getByRole("link", { name: "Skip to content" }).getAttribute("href")).toBe("#main");
  });

  it("sends a visitor without a session to sign in, and back afterwards", async () => {
    const { history } = show("/?view=1", auth({}, false));
    expect(await screen.findByRole("heading", { name: "Sign in to rpmgr" })).toBeTruthy();
    expect(history.location.pathname).toBe("/login");
    expect(new URLSearchParams(history.location.search).get("redirect")).toBe("/?view=1");
  });

  it("signs out", async () => {
    let calls = 0;
    const { history } = show("/", auth({ logout: () => ((calls += 1), {}) }));
    fireEvent.click(await screen.findByRole("button", { name: "Sign out" }));
    await waitFor(() => expect(history.location.pathname).toBe("/login"));
    expect(calls).toBe(1);
  });

  it("sends the user to sign in when the session ends", async () => {
    let reads = 0;
    const session = auth().getSession!;
    const { history } = show("/", auth({
      getSession: (req, ctx) => {
        reads += 1;
        if (reads > 1) {
          throw apiError(Code.Unauthenticated); // expired or revoked since
        }
        return session(req, ctx);
      },
    }));
    await screen.findByText("Signed in as Ada");
    focusManager.setFocused(false);
    focusManager.setFocused(true); // the UI reads the session again
    await waitFor(() => expect(history.location.pathname).toBe("/login"));
    expect(new URLSearchParams(history.location.search).get("redirect")).toBe("/");
    focusManager.setFocused(undefined);
  });

  it("shows a page that does not exist as not found", async () => {
    show("/no/such/page", auth());
    expect(await screen.findByRole("heading", { name: "Page not found" })).toBeTruthy();
    expect(screen.getByRole("link", { name: "Go to the overview" }).getAttribute("href")).toBe("/");
  });

  it("keeps nothing in browser storage", async () => {
    show("/", auth());
    await screen.findByText("Signed in as Ada");
    expect(localStorage.length).toBe(0);
    expect(sessionStorage.length).toBe(0);
  });
});
