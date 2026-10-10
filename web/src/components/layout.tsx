// SPDX-License-Identifier: Apache-2.0

import { Link, Outlet } from "@tanstack/react-router";
import { useTranslation } from "react-i18next";

export function Layout() {
  const { t } = useTranslation();
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
        </div>
      </header>
      <main id="main" className="mx-auto max-w-6xl px-4 py-6">
        <Outlet />
      </main>
    </div>
  );
}
