// SPDX-License-Identifier: Apache-2.0

import { Code, ConnectError, type Transport } from "@connectrpc/connect";
import type { QueryClient } from "@tanstack/react-query";
import { createRootRouteWithContext, createRoute, createRouter, Outlet, redirect, type RouterHistory } from "@tanstack/react-router";
import { Layout } from "@/components/layout";
import { Account } from "@/pages/account";
import { Forgot } from "@/pages/forgot";
import { Login } from "@/pages/login";
import { NotFound } from "@/pages/not-found";
import { Overview } from "@/pages/overview";
import { Reset } from "@/pages/reset";
import { RouteDetail } from "@/pages/route-detail";
import { RouteEdit } from "@/pages/route-edit";
import { RouteNew } from "@/pages/route-new";
import { Routes, validateRoutesSearch } from "@/pages/routes";
import { Setup } from "@/pages/setup";
import { sessionQuery } from "@/session";

export interface RouterContext {
  queryClient: QueryClient;
  transport: Transport;
}

// The pages of docs/09-web-ui.md, "Information architecture"; each slice adds its own. Pages
// under app need a session: without one, they send the user to sign in and back.
const root = createRootRouteWithContext<RouterContext>()({ component: Outlet, notFoundComponent: NotFound });
const app = createRoute({
  getParentRoute: () => root,
  id: "app",
  component: Layout,
  beforeLoad: async ({ context, location }) => {
    try {
      await context.queryClient.ensureQueryData(sessionQuery(context.transport));
    } catch (err) {
      if (ConnectError.from(err).code === Code.Unauthenticated) {
        throw redirect({ to: "/login", search: { redirect: location.href } });
      }
      throw err;
    }
  },
});
const overview = createRoute({ getParentRoute: () => app, path: "/", component: Overview });
const routes = createRoute({ getParentRoute: () => app, path: "/routes", component: Routes, validateSearch: validateRoutesSearch });
const routeDetail = createRoute({ getParentRoute: () => app, path: "/routes/$routeId", component: RouteDetail });
const routeNew = createRoute({ getParentRoute: () => app, path: "/routes/new", component: RouteNew });
const routeEdit = createRoute({ getParentRoute: () => app, path: "/routes/$routeId/edit", component: RouteEdit });
const account = createRoute({
  getParentRoute: () => app,
  path: "/account",
  component: Account,
  validateSearch: (search: Record<string, unknown>): { mfa?: "required" } => (search.mfa === "required" ? { mfa: "required" } : {}),
});
const login = createRoute({
  getParentRoute: () => root,
  path: "/login",
  component: Login,
  validateSearch: (search: Record<string, unknown>): { redirect?: string } =>
    typeof search.redirect === "string" ? { redirect: search.redirect } : {},
});

// The pages of one-time links (docs/10-operations.md, "Install") and the reset request.
const setup = createRoute({ getParentRoute: () => root, path: "/setup", component: Setup });
const reset = createRoute({ getParentRoute: () => root, path: "/reset", component: Reset });
const forgot = createRoute({ getParentRoute: () => root, path: "/forgot", component: Forgot });

const routeTree = root.addChildren([app.addChildren([overview, routes, routeNew, routeDetail, routeEdit, account]), login, setup, reset, forgot]);

export function createAppRouter(context: RouterContext, history?: RouterHistory) {
  return createRouter({ routeTree, history, context, defaultPreload: "intent" });
}

declare module "@tanstack/react-router" {
  interface Register {
    router: ReturnType<typeof createAppRouter>;
  }
}
