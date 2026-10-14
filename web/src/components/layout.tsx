// SPDX-License-Identifier: Apache-2.0

import { useQuery } from "@connectrpc/connect-query";
import { Outlet } from "@tanstack/react-router";
import { Menu, X } from "lucide-react";
import { useEffect, useRef, useState } from "react";
import { useTranslation } from "react-i18next";
import { CommandPalette } from "@/components/command-palette";
import { Brand, Nav, Version } from "@/components/nav";
import { RestoreReviewBanner } from "@/components/restore-review";
import { ThemeSwitch } from "@/components/theme-switch";
import { Button } from "@/components/ui/button";
import { UserMenu } from "@/components/user-menu";
import { UserService } from "@/gen/rpmgr/v1/user_pb";
import { applyTheme } from "@/theme";

// Layout frames every signed-in page (docs/09-web-ui.md, "Layout and navigation"): the sidebar,
// which is a menu behind a button on small screens, and the top bar with "Go to…", the theme switch
// and the user menu.
export function Layout() {
  const { t } = useTranslation();
  const theme = useQuery(UserService.method.getMe, {}).data?.user?.theme;
  useEffect(() => {
    if (theme !== undefined) {
      applyTheme(theme);
    }
  }, [theme]);
  const [menu, setMenu] = useState(false);

  return (
    <div className="min-h-dvh">
      <a href="#main" className="sr-only focus:not-sr-only focus:fixed focus:top-3 focus:left-3 focus:z-50 focus:rounded-lg focus:bg-card focus:px-3 focus:py-2 focus:shadow-lg">
        {t("app.skip")}
      </a>
      <aside className="fixed inset-y-0 left-0 z-30 hidden w-64 flex-col border-r border-border bg-sidebar lg:flex">
        <Brand />
        <Nav className="flex-1 overflow-y-auto px-3 pt-2 pb-6" />
        <Version />
      </aside>
      {menu && <MenuDrawer onClose={() => setMenu(false)} />}
      <div className="lg:pl-64">
        <header className="sticky top-0 z-20 flex h-16 items-center gap-2 border-b border-border bg-background/85 px-4 backdrop-blur sm:gap-3 sm:px-6 lg:px-8">
          <Button variant="ghost" size="icon" className="-ml-2 lg:hidden" aria-label={t("app.openMenu")} onClick={() => setMenu(true)}>
            <Menu aria-hidden="true" />
          </Button>
          <div className="min-w-0 flex-1">
            <CommandPalette />
          </div>
          <ThemeSwitch />
          <UserMenu />
        </header>
        <RestoreReviewBanner />
        <main id="main" tabIndex={-1} className="w-full px-4 py-6 focus:outline-none sm:px-6 lg:px-8 lg:py-8">
          <Outlet />
        </main>
      </div>
    </div>
  );
}

// MenuDrawer is the sidebar on small screens: a modal dialog from the left, which Escape, a click
// beside it, its close button and choosing a page close.
function MenuDrawer({ onClose }: { onClose: () => void }) {
  const { t } = useTranslation();
  const dialog = useRef<HTMLDialogElement>(null);
  useEffect(() => dialog.current?.showModal(), []);
  return (
    <dialog ref={dialog} aria-label={t("app.menu")} onCancel={onClose} onClick={(e) => e.target === e.currentTarget && onClose()}
      className="m-0 h-dvh max-h-dvh w-72 max-w-[85vw] border-r border-border bg-sidebar p-0 shadow-xl open:flex open:flex-col">
      <div className="flex items-center justify-between pr-3">
        <Brand />
        <Button variant="ghost" size="icon" aria-label={t("app.closeMenu")} onClick={onClose}>
          <X aria-hidden="true" />
        </Button>
      </div>
      <Nav className="flex-1 overflow-y-auto px-3 pt-2 pb-6" onNavigate={onClose} />
      <Version />
    </dialog>
  );
}
