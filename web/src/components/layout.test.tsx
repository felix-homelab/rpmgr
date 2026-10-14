// SPDX-License-Identifier: Apache-2.0

import { Code, ConnectError } from "@connectrpc/connect";
import { cleanup, fireEvent, screen, waitFor, within } from "@testing-library/react";
import { afterEach, describe, expect, it } from "vitest";
import { Theme, UserService, type UpdateMeRequest } from "@/gen/rpmgr/v1/user_pb";
import { auth, show } from "@/testing/api";

afterEach(() => {
  cleanup();
  delete document.documentElement.dataset.theme;
});

// signedIn shows path to Ada, whose stored theme is theme, on a controller of version; updateMe
// answers her theme changes, or fails with failure.
function signedIn(path: string, theme = Theme.SYSTEM, failure?: ConnectError, version = "") {
  const updates: UpdateMeRequest[] = [];
  let user = { id: "usr_ada", email: "ada@example.com", displayName: "Ada", theme };
  const session = { getSession: () => ({ userId: "usr_ada", email: "ada@example.com", displayName: "Ada", controllerVersion: version }) };
  const shown = show(path, auth(session), (router) =>
    router.service(UserService, {
      getMe: () => ({ user }),
      updateMe: (req) => {
        updates.push(req);
        if (failure) {
          throw failure;
        }
        user = { ...user, displayName: req.displayName, theme: req.theme || user.theme };
        return { user };
      },
    }),
  );
  return { ...shown, updates };
}

const radio = (name: string) => screen.getByRole("radio", { name }) as HTMLInputElement;

describe("Layout", () => {
  it("groups the pages in the sidebar and marks the current one", async () => {
    signedIn("/routes");
    const nav = within(await screen.findByRole("navigation", { name: "Main navigation" }));
    const group = (name: string) => within(nav.getByRole("list", { name })).getAllByRole("link").map((l) => l.textContent);
    expect(group("Network")).toEqual(["Routes", "Connectors", "Gateways"]);
    expect(group("Security")).toEqual(["Domains & certificates", "Access policies"]);
    expect(group("Administration")).toEqual(["Organisation", "Audit log", "Settings"]);
    await waitFor(() => expect(nav.getByRole("link", { name: "Routes" }).getAttribute("aria-current")).toBe("page"));
    // The overview is current only on its own page, not on every page under /.
    expect(nav.getByRole("link", { name: "Overview" }).getAttribute("aria-current")).toBeNull();
  });

  it("shows the controller's version at the foot of the sidebar and of the menu (D80)", async () => {
    signedIn("/", Theme.SYSTEM, undefined, "0.1.0");
    const aside = await screen.findByRole("complementary");
    await waitFor(() => expect(within(aside).getByText("rpmgr 0.1.0")).toBeTruthy());
    fireEvent.click(screen.getByRole("button", { name: "Open the menu" }));
    expect(within(screen.getByRole("dialog", { name: "Menu" })).getByText("rpmgr 0.1.0")).toBeTruthy();
  });

  it("shows no version before it knows one, nor on the sign-in page", async () => {
    signedIn("/");
    await screen.findByRole("navigation", { name: "Main navigation" });
    expect(screen.queryByText(/^rpmgr /)).toBeNull();
    cleanup();
    show("/", auth({}, false));
    await screen.findByRole("button", { name: "Sign in" });
    expect(screen.queryByText(/^rpmgr /)).toBeNull();
  });

  it("opens the menu on small screens, and closes it when a page is chosen, by its button and by Escape", async () => {
    const { history } = signedIn("/");
    const open = await screen.findByRole("button", { name: "Open the menu" });
    expect(screen.queryByRole("dialog", { name: "Menu" })).toBeNull();

    fireEvent.click(open);
    const menu = within(screen.getByRole("dialog", { name: "Menu" }));
    fireEvent.click(menu.getByRole("link", { name: "Settings" }));
    await waitFor(() => expect(history.location.pathname).toBe("/settings"));
    expect(screen.queryByRole("dialog", { name: "Menu" })).toBeNull();

    fireEvent.click(open);
    fireEvent.click(within(screen.getByRole("dialog", { name: "Menu" })).getByRole("button", { name: "Close the menu" }));
    expect(screen.queryByRole("dialog", { name: "Menu" })).toBeNull();

    fireEvent.click(open);
    fireEvent(screen.getByRole("dialog", { name: "Menu" }), new Event("cancel")); // what Escape sends a modal dialog
    expect(screen.queryByRole("dialog", { name: "Menu" })).toBeNull();
    expect(history.location.pathname).toBe("/settings");
  });

  it("switches the theme at once and saves it with the name unchanged", async () => {
    const { updates } = signedIn("/", Theme.LIGHT);
    await waitFor(() => expect(radio("Light").checked).toBe(true));
    expect(document.documentElement.dataset.theme).toBe("light");

    fireEvent.click(radio("Dark"));
    expect(document.documentElement.dataset.theme).toBe("dark");
    await waitFor(() => expect(updates.map((u) => [u.displayName, u.theme])).toEqual([["Ada", Theme.DARK]]));
    await waitFor(() => expect(radio("Dark").checked).toBe(true));

    fireEvent.click(radio("Like the system"));
    await waitFor(() => expect(radio("Like the system").checked).toBe(true));
    expect(document.documentElement.dataset.theme).toBe("system");
    expect(updates.map((u) => u.theme)).toEqual([Theme.DARK, Theme.SYSTEM]);
    expect(screen.queryByRole("alert")).toBeNull();
  });

  it("goes back to the stored theme and says why when the theme cannot be saved", async () => {
    signedIn("/", Theme.LIGHT, new ConnectError("database unavailable", Code.Unavailable));
    await waitFor(() => expect(radio("Light").checked).toBe(true));
    fireEvent.click(radio("Dark"));
    expect((await screen.findByRole("alert")).textContent).toBe("The theme was not saved: database unavailable");
    expect(document.documentElement.dataset.theme).toBe("light");
    expect(radio("Light").checked).toBe(true);
  });

  it("offers no theme to switch to before it knows the user", async () => {
    show("/", auth()); // GetMe is not served
    await screen.findByText("Signed in as Ada");
    for (const name of ["Like the system", "Light", "Dark"]) {
      expect(radio(name).matches(":disabled")).toBe(true); // by the disabled fieldset
    }
  });

  it("opens the user menu, which Escape, a click elsewhere and a choice close", async () => {
    const { history } = signedIn("/");
    const button = await screen.findByRole("button", { name: "User menu: Ada" });
    expect(button.getAttribute("aria-expanded")).toBe("false");
    expect(screen.queryByRole("link", { name: "Your account" })).toBeNull();

    fireEvent.click(button);
    expect(button.getAttribute("aria-expanded")).toBe("true");
    expect(screen.getByText("ada@example.com")).toBeTruthy();
    fireEvent.keyDown(document, { key: "Escape" });
    expect(screen.queryByRole("link", { name: "Your account" })).toBeNull();
    expect(document.activeElement).toBe(button);

    fireEvent.click(button);
    fireEvent.pointerDown(screen.getByRole("main"));
    expect(screen.queryByRole("link", { name: "Your account" })).toBeNull();

    fireEvent.click(button);
    fireEvent.click(screen.getByRole("link", { name: "Your account" }));
    await waitFor(() => expect(history.location.pathname).toBe("/account"));
    expect(button.getAttribute("aria-expanded")).toBe("false");
  });
});
