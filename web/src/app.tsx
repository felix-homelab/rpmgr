// SPDX-License-Identifier: Apache-2.0

import { Code, ConnectError, type Transport } from "@connectrpc/connect";
import { TransportProvider } from "@connectrpc/connect-query";
import { createConnectTransport } from "@connectrpc/connect-web";
import { MutationCache, QueryCache, QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { RouterProvider, type RouterHistory } from "@tanstack/react-router";
import { useState } from "react";
import { I18nextProvider } from "react-i18next";
import { i18n } from "@/i18n";
import { Reason, reasonOf } from "@/lib/errors";
import { createAppRouter } from "@/router";
import { StepUpProvider } from "@/step-up";

// The API is on the UI's origin, and the session cookie goes with every call (docs/09-web-ui.md,
// "Security of the frontend").
function originTransport(): Transport {
  return createConnectTransport({ baseUrl: window.location.origin });
}

export interface AppProps {
  transport?: Transport; // tests pass a router transport
  history?: RouterHistory; // tests pass a memory history
}

export function App({ transport, history }: AppProps) {
  const [state] = useState(() => {
    const api = transport ?? originTransport();
    // A session that ends while the UI is open, by expiry or revocation, sends the user to sign
    // in and back; a step-up the API asks for is handled where it happens.
    const ended = (err: unknown) => {
      // An org that requires a second factor refuses a user without one until they set one up.
      if (ConnectError.from(err).code === Code.PermissionDenied && reasonOf(err) === Reason.mfaRequired) {
        if (router.state.location.pathname !== "/account") {
          void router.navigate({ to: "/account", search: { mfa: "required" } });
        }
        return;
      }
      if (ConnectError.from(err).code !== Code.Unauthenticated || reasonOf(err) === Reason.stepUpRequired) {
        return;
      }
      const at = router.state.location;
      if (at.pathname !== "/login") {
        queryClient.clear();
        void router.navigate({ to: "/login", search: { redirect: at.href } });
      }
    };
    const queryClient = new QueryClient({
      queryCache: new QueryCache({ onError: ended }),
      mutationCache: new MutationCache({ onError: ended }),
      defaultOptions: { queries: { retry: false } },
    });
    const router = createAppRouter({ queryClient, transport: api }, history);
    return { api, queryClient, router };
  });
  return (
    <I18nextProvider i18n={i18n}>
      <TransportProvider transport={state.api}>
        <QueryClientProvider client={state.queryClient}>
          <StepUpProvider>
            <RouterProvider router={state.router} />
          </StepUpProvider>
        </QueryClientProvider>
      </TransportProvider>
    </I18nextProvider>
  );
}
