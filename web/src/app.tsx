// SPDX-License-Identifier: Apache-2.0

import type { Transport } from "@connectrpc/connect";
import { TransportProvider } from "@connectrpc/connect-query";
import { createConnectTransport } from "@connectrpc/connect-web";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { RouterProvider, type RouterHistory } from "@tanstack/react-router";
import { useState } from "react";
import { I18nextProvider } from "react-i18next";
import { i18n } from "@/i18n";
import { createAppRouter } from "@/router";

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
  const [api] = useState(() => transport ?? originTransport());
  const [queries] = useState(() => new QueryClient({ defaultOptions: { queries: { retry: false } } }));
  const [router] = useState(() => createAppRouter(history));
  return (
    <I18nextProvider i18n={i18n}>
      <TransportProvider transport={api}>
        <QueryClientProvider client={queries}>
          <RouterProvider router={router} />
        </QueryClientProvider>
      </TransportProvider>
    </I18nextProvider>
  );
}
