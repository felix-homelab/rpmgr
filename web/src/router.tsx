// SPDX-License-Identifier: Apache-2.0

import { createRootRoute, createRoute, createRouter, type RouterHistory } from "@tanstack/react-router";
import { Layout } from "@/components/layout";
import { NotFound } from "@/pages/not-found";
import { Overview } from "@/pages/overview";

// The pages of docs/09-web-ui.md, "Information architecture"; each slice adds its own.
const root = createRootRoute({ component: Layout, notFoundComponent: NotFound });
const overview = createRoute({ getParentRoute: () => root, path: "/", component: Overview });

const routeTree = root.addChildren([overview]);

export function createAppRouter(history?: RouterHistory) {
  return createRouter({ routeTree, history, defaultPreload: "intent" });
}

declare module "@tanstack/react-router" {
  interface Register {
    router: ReturnType<typeof createAppRouter>;
  }
}
