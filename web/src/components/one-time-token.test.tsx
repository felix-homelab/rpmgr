// SPDX-License-Identifier: Apache-2.0

import { act, cleanup, fireEvent, render, screen } from "@testing-library/react";
import type { ReactNode } from "react";
import { I18nextProvider } from "react-i18next";
import { afterEach, describe, expect, it, vi } from "vitest";
import { Command, mask, OneTimeToken } from "@/components/one-time-token";
import { i18n } from "@/i18n";

afterEach(() => {
  cleanup();
  vi.useRealTimers();
});

const token = "rpmgr_enr_fakefakefake0123456789_8f2k1a"; // not token-shaped, so the secrets scan passes it
const command = "curl -fsSL 'https://panel.example.com/install.sh' | sudo sh -s -- \\\n  --controller 'https://panel.example.com'";
const byHand = "The browser did not copy it. Select the text and copy it by hand.";

function show(node: ReactNode) {
  render(<I18nextProvider i18n={i18n}>{node}</I18nextProvider>);
}

// clipboard gives the page a clipboard that writeText answers, or none at all.
function clipboard(writeText?: (text: string) => Promise<void>) {
  Object.assign(navigator, { clipboard: writeText && { writeText } });
}

// settle lets the clipboard's promise answer.
const settle = () => act(async () => {});

describe("Command", () => {
  it("copies the command and says so for a moment", async () => {
    vi.useFakeTimers();
    const write = vi.fn(() => Promise.resolve());
    clipboard(write);
    show(<Command command={command} label="Install command" />);
    expect(screen.getByLabelText("Install command").textContent).toBe(command);
    fireEvent.click(screen.getByRole("button", { name: "Copy" }));
    await settle();
    expect(write).toHaveBeenCalledWith(command);
    expect(screen.getByRole("button", { name: "Copied" })).toBeTruthy();
    expect(screen.queryByRole("status")).toBeNull();
    act(() => vi.advanceTimersByTime(2000));
    expect(screen.getByRole("button", { name: "Copy" })).toBeTruthy();
  });

  it.each([
    ["has no clipboard for the page", undefined],
    ["refuses the clipboard", () => Promise.reject(new DOMException("denied", "NotAllowedError"))],
  ])("says to copy it by hand when the browser %s", async (_, write) => {
    clipboard(write);
    show(<Command command={command} label="Install command" />);
    fireEvent.click(screen.getByRole("button", { name: "Copy" }));
    await settle();
    expect(screen.getByRole("status").textContent).toBe(byHand);
    expect(screen.getByRole("button", { name: "Copy" })).toBeTruthy();
  });
});

describe("OneTimeToken", () => {
  it("copies the token and keeps it masked", async () => {
    const write = vi.fn(() => Promise.resolve());
    clipboard(write);
    show(<OneTimeToken token={token} label="Enrollment token" />);
    expect(screen.getByLabelText("Enrollment token").textContent).toBe(mask(token));
    fireEvent.click(screen.getByRole("button", { name: "Copy" }));
    await settle();
    expect(write).toHaveBeenCalledWith(token);
    expect(screen.getByRole("button", { name: "Copied" })).toBeTruthy();
    expect(screen.getByLabelText("Enrollment token").textContent).toBe(mask(token));
    expect(screen.queryByRole("status")).toBeNull();
  });

  it("shows the token to copy by hand when the browser does not copy it", async () => {
    clipboard(undefined);
    show(<OneTimeToken token={token} label="Enrollment token" />);
    fireEvent.click(screen.getByRole("button", { name: "Copy" }));
    await settle();
    expect(screen.getByLabelText("Enrollment token").textContent).toBe(token);
    expect(screen.getByRole("button", { name: "Hide" }).getAttribute("aria-pressed")).toBe("true");
    expect(screen.getByRole("status").textContent).toBe(byHand);
  });
});
