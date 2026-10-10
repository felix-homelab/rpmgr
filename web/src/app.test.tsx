// SPDX-License-Identifier: Apache-2.0

import { Code, ConnectError, createRouterTransport } from "@connectrpc/connect";
import { createMemoryHistory } from "@tanstack/react-router";
import { cleanup, render, screen } from "@testing-library/react";
import { afterEach, describe, expect, it } from "vitest";
import { App } from "@/app";
import { AuthService } from "@/gen/rpmgr/v1/auth_pb";

// A transport whose GetSession answers with session, or fails with code.
function api(answer: { displayName?: string; email?: string } | Code) {
  return createRouterTransport(({ service }) => {
    service(AuthService, {
      getSession: () => {
        if (typeof answer === "number") {
          throw new ConnectError("no session", answer);
        }
        return answer;
      },
    });
  });
}

function show(path: string, answer: Parameters<typeof api>[0]) {
  return render(<App transport={api(answer)} history={createMemoryHistory({ initialEntries: [path] })} />);
}

afterEach(() => {
  cleanup();
  localStorage.clear();
  sessionStorage.clear();
});

describe("App", () => {
  it("shows the overview with the caller's session, through connect-query", async () => {
    show("/", { displayName: "Ada", email: "ada@example.com" });
    expect(await screen.findByText("Signed in as Ada")).toBeTruthy();
    expect(screen.getByRole("heading", { level: 1, name: "Overview" })).toBeTruthy();
    expect(screen.getByRole("navigation", { name: "Main navigation" })).toBeTruthy();
    expect(screen.getByRole("link", { name: "Skip to content" }).getAttribute("href")).toBe("#main");
  });

  it("names the user by e-mail without a display name", async () => {
    show("/", { email: "ada@example.com" });
    expect(await screen.findByText("Signed in as ada@example.com")).toBeTruthy();
  });

  it("says when nobody is signed in", async () => {
    show("/", Code.Unauthenticated);
    expect(await screen.findByText("You are not signed in.")).toBeTruthy();
  });

  it("says when the controller cannot be reached", async () => {
    show("/", Code.Unavailable);
    expect(await screen.findByText("The controller could not be reached: no session")).toBeTruthy();
  });

  it("shows a page that does not exist as not found", async () => {
    show("/no/such/page", Code.Unauthenticated);
    expect(await screen.findByRole("heading", { name: "Page not found" })).toBeTruthy();
    expect(screen.getByRole("link", { name: "Go to the overview" }).getAttribute("href")).toBe("/");
  });

  it("keeps nothing in browser storage", async () => {
    show("/", { displayName: "Ada" });
    await screen.findByText("Signed in as Ada");
    expect(localStorage.length).toBe(0);
    expect(sessionStorage.length).toBe(0);
  });
});
