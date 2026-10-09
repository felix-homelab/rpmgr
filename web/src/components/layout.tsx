// SPDX-License-Identifier: Apache-2.0

import { useMutation, useQuery } from "@connectrpc/connect-query";
import { useQueryClient } from "@tanstack/react-query";
import { Link, Outlet, useNavigate } from "@tanstack/react-router";
import { useEffect } from "react";
import { useTranslation } from "react-i18next";
import { Button } from "@/components/ui/button";
import { AuthService } from "@/gen/rpmgr/v1/auth_pb";
import { UserService } from "@/gen/rpmgr/v1/user_pb";
import { applyTheme } from "@/theme";

export function Layout() {
  const { t } = useTranslation();
  const session = useQuery(AuthService.method.getSession, {});
  const me = useQuery(UserService.method.getMe, {});
  const theme = me.data?.user?.theme;
  useEffect(() => {
    if (theme !== undefined) {
      applyTheme(theme);
    }
  }, [theme]);
  const logout = useMutation(AuthService.method.logout);
  const queryClient = useQueryClient();
  const navigate = useNavigate();

  async function signOut() {
    try {
      await logout.mutateAsync({});
    } finally {
      queryClient.clear();
      await navigate({ to: "/login", search: {} });
    }
  }

  return (
    <div className="min-h-screen bg-background text-foreground">
      <a href="#main" className="sr-only focus:not-sr-only focus:absolute focus:p-2">
        {t("app.skip")}
      </a>
      <header className="border-b border-border">
        <div className="mx-auto flex max-w-6xl items-center gap-6 px-4 py-3">
          <span className="font-semibold">{t("app.name")}</span>
          <nav aria-label={t("app.nav")}>
            <Link to="/" className="text-muted-foreground [&.active]:text-foreground [&.active]:font-medium">
              {t("nav.overview")}
            </Link>
            <Link to="/routes" search={{}} className="ml-4 text-muted-foreground [&.active]:text-foreground [&.active]:font-medium">
              {t("nav.routes")}
            </Link>
            <Link to="/connectors" search={{}} className="ml-4 text-muted-foreground [&.active]:text-foreground [&.active]:font-medium">
              {t("nav.connectors")}
            </Link>
            <Link to="/gateways" className="ml-4 text-muted-foreground [&.active]:text-foreground [&.active]:font-medium">
              {t("nav.gateways")}
            </Link>
            <Link to="/domains" className="ml-4 text-muted-foreground [&.active]:text-foreground [&.active]:font-medium">
              {t("nav.domains")}
            </Link>
            <Link to="/policies" className="ml-4 text-muted-foreground [&.active]:text-foreground [&.active]:font-medium">
              {t("nav.policies")}
            </Link>
            <Link to="/org" className="ml-4 text-muted-foreground [&.active]:text-foreground [&.active]:font-medium">
              {t("nav.org")}
            </Link>
            <Link to="/audit" search={{}} className="ml-4 text-muted-foreground [&.active]:text-foreground [&.active]:font-medium">
              {t("nav.audit")}
            </Link>
          </nav>
          <div className="ml-auto flex items-center gap-3 text-sm">
            <Link to="/account" className="text-muted-foreground hover:text-foreground [&.active]:text-foreground">
              {session.data?.displayName || session.data?.email}
            </Link>
            <Button variant="outline" size="sm" onClick={() => void signOut()} disabled={logout.isPending}>
              {t("app.signOut")}
            </Button>
          </div>
        </div>
      </header>
      <main id="main" className="mx-auto max-w-6xl px-4 py-6">
        <Outlet />
      </main>
    </div>
  );
}
