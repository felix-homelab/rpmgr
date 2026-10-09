// SPDX-License-Identifier: Apache-2.0

import { useMutation, useQuery } from "@connectrpc/connect-query";
import { useQueryClient } from "@tanstack/react-query";
import { Link, Outlet, useNavigate } from "@tanstack/react-router";
import { useTranslation } from "react-i18next";
import { Button } from "@/components/ui/button";
import { AuthService } from "@/gen/rpmgr/v1/auth_pb";

export function Layout() {
  const { t } = useTranslation();
  const session = useQuery(AuthService.method.getSession, {});
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
          </nav>
          <div className="ml-auto flex items-center gap-3 text-sm">
            <span className="text-muted-foreground">{session.data?.displayName || session.data?.email}</span>
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
