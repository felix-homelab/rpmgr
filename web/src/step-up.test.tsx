// SPDX-License-Identifier: Apache-2.0

import { Code, createRouterTransport } from "@connectrpc/connect";
import { TransportProvider } from "@connectrpc/connect-query";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { cleanup, fireEvent, render, screen } from "@testing-library/react";
import { useState } from "react";
import { I18nextProvider } from "react-i18next";
import { afterEach, describe, expect, it } from "vitest";
import { AuthService, type StepUpRequest } from "@/gen/rpmgr/v1/auth_pb";
import { UserService } from "@/gen/rpmgr/v1/user_pb";
import { i18n } from "@/i18n";
import { StepUpProvider, useStepUp } from "@/step-up";
import { apiError } from "@/testing/api";

afterEach(cleanup);

// Probe runs an action that needs a step-up until one succeeded, and shows how it ended.
function Probe({ action }: { action: () => Promise<string> }) {
  const stepUp = useStepUp();
  const [result, setResult] = useState("");
  return (
    <>
      <button onClick={() => stepUp(action).then(setResult, (err: Error) => setResult(`failed: ${err.message}`))}>Act</button>
      <output>{result}</output>
    </>
  );
}

// setup renders Probe with a user with or without an authenticator, whose StepUp takes secret.
function setup(mfa: boolean, secret: string) {
  let steppedUp = false;
  const requests: StepUpRequest[] = [];
  const transport = createRouterTransport(({ service }) => {
    service(UserService, { getMe: () => ({ user: { id: "usr_ada", mfa } }) });
    service(AuthService, {
      stepUp: (req) => {
        requests.push(req);
        if ((mfa ? req.secondFactor : req.password) !== secret) {
          throw apiError(Code.Unauthenticated);
        }
        steppedUp = true;
        return {};
      },
    });
  });
  let calls = 0;
  const action = async () => {
    calls += 1;
    if (!steppedUp) {
      throw apiError(Code.Unauthenticated, "STEP_UP_REQUIRED");
    }
    return "done";
  };
  render(
    <I18nextProvider i18n={i18n}>
      <TransportProvider transport={transport}>
        <QueryClientProvider client={new QueryClient()}>
          <StepUpProvider>
            <Probe action={action} />
          </StepUpProvider>
        </QueryClientProvider>
      </TransportProvider>
    </I18nextProvider>,
  );
  fireEvent.click(screen.getByRole("button", { name: "Act" }));
  return { requests, calls: () => calls };
}

async function confirm(label: string, value: string) {
  fireEvent.change(await screen.findByLabelText(label), { target: { value } });
  fireEvent.click(screen.getByRole("button", { name: "Confirm" }));
}

describe("step-up", () => {
  it("asks for the password and runs the action again", async () => {
    const { requests, calls } = setup(false, "correct horse battery");
    expect(await screen.findByRole("dialog", { name: "Confirm it is you" })).toBeTruthy();
    await confirm("Password", "wrong");
    expect((await screen.findByRole("alert")).textContent).toBe("The password is wrong.");
    await confirm("Password", "correct horse battery");
    expect(await screen.findByText("done")).toBeTruthy();
    expect(screen.queryByRole("dialog")).toBeNull();
    expect(calls()).toBe(2);
    expect(requests.map((r) => [r.password, r.secondFactor])).toEqual([["wrong", ""], ["correct horse battery", ""]]);
  });

  it("asks a user with an authenticator for a code", async () => {
    const { requests } = setup(true, "123456");
    await confirm("Authenticator code or recovery code", "123456");
    expect(await screen.findByText("done")).toBeTruthy();
    expect(screen.queryByLabelText("Password")).toBeNull();
    expect(requests.map((r) => [r.password, r.secondFactor])).toEqual([["", "123456"]]);
  });

  it("gives the API's error back when the user cancels", async () => {
    const { requests, calls } = setup(false, "x");
    fireEvent.click(await screen.findByRole("button", { name: "Cancel" }));
    expect((await screen.findByText(/^failed:/)).textContent).toContain("api error");
    expect(screen.queryByRole("dialog")).toBeNull();
    expect(requests).toEqual([]);
    expect(calls()).toBe(1);
  });

  it("passes other errors through without a dialog", async () => {
    render(
      <I18nextProvider i18n={i18n}>
        <TransportProvider transport={createRouterTransport(() => {})}>
          <QueryClientProvider client={new QueryClient()}>
            <StepUpProvider>
              <Probe action={() => Promise.reject(apiError(Code.Unauthenticated, "MFA_REQUIRED"))} />
            </StepUpProvider>
          </QueryClientProvider>
        </TransportProvider>
      </I18nextProvider>,
    );
    fireEvent.click(screen.getByRole("button", { name: "Act" }));
    expect(await screen.findByText(/^failed:/)).toBeTruthy();
    expect(screen.queryByRole("dialog")).toBeNull();
  });
});
