// SPDX-License-Identifier: Apache-2.0

import { useQuery } from "@connectrpc/connect-query";
import { Link, linkOptions, type LinkOptions } from "@tanstack/react-router";
import { Cable, Globe, LayoutDashboard, Route, ScrollText, Server, Settings, ShieldCheck, Users, Waypoints, Webhook, type LucideIcon } from "lucide-react";
import { useId } from "react";
import { useTranslation } from "react-i18next";
import { AuthService } from "@/gen/rpmgr/v1/auth_pb";
import { cn } from "@/lib/utils";

export interface NavItem {
  key: string; // the page's name is nav.<key>
  icon: LucideIcon;
  link: LinkOptions;
}

// navGroups are the pages of the sidebar, in the groups of docs/09-web-ui.md, "Layout and
// navigation". The command palette offers the same pages.
export const navGroups: { key?: string; items: NavItem[] }[] = [
  { items: [{ key: "overview", icon: LayoutDashboard, link: linkOptions({ to: "/", activeOptions: { exact: true } }) }] },
  {
    key: "network",
    items: [
      { key: "routes", icon: Route, link: linkOptions({ to: "/routes", search: {}, activeOptions: { includeSearch: false } }) },
      { key: "connectors", icon: Cable, link: linkOptions({ to: "/connectors", search: {}, activeOptions: { includeSearch: false } }) },
      { key: "gateways", icon: Server, link: linkOptions({ to: "/gateways" }) },
    ],
  },
  {
    key: "security",
    items: [
      { key: "domains", icon: Globe, link: linkOptions({ to: "/domains" }) },
      { key: "policies", icon: ShieldCheck, link: linkOptions({ to: "/policies" }) },
    ],
  },
  {
    key: "admin",
    items: [
      { key: "org", icon: Users, link: linkOptions({ to: "/org" }) },
      { key: "webhooks", icon: Webhook, link: linkOptions({ to: "/webhooks" }) },
      { key: "audit", icon: ScrollText, link: linkOptions({ to: "/audit", search: {}, activeOptions: { includeSearch: false } }) },
      { key: "settings", icon: Settings, link: linkOptions({ to: "/settings" }) },
    ],
  },
];

// Mark is the product's mark, for the eye only: its name is always next to it.
export function Mark() {
  return (
    <span aria-hidden="true" className="grid size-8 place-items-center rounded-lg bg-primary text-primary-foreground">
      <Waypoints className="size-4.5" />
    </span>
  );
}

// Brand is the product's mark and name, which lead to the overview.
export function Brand() {
  const { t } = useTranslation();
  return (
    <Link to="/" className="flex h-16 shrink-0 items-center gap-2.5 px-5 text-base font-semibold tracking-tight">
      <Mark />
      {t("app.name")}
    </Link>
  );
}

// Version is the version of rpmgr the controller runs, at the foot of the sidebar (D80); nothing
// until the session is read.
export function Version() {
  const { t } = useTranslation();
  const version = useQuery(AuthService.method.getSession, {}).data?.controllerVersion;
  if (!version) {
    return null;
  }
  return <p className="shrink-0 border-t border-border px-5 py-3 text-xs text-muted-foreground">{t("app.version", { version })}</p>;
}

// Nav is the main navigation; the current page is marked for the eye and, by the router's
// aria-current, for screen readers. onNavigate runs when a page is chosen, so that the menu on
// small screens closes.
export function Nav({ className, onNavigate }: { className?: string; onNavigate?: () => void }) {
  const { t } = useTranslation();
  const id = useId();
  return (
    <nav aria-label={t("app.nav")} className={cn("grid content-start gap-6", className)}>
      {navGroups.map((group, i) => (
        <div key={group.key ?? i} className="grid gap-1">
          {group.key && (
            <p id={`${id}-${group.key}`} className="px-3 pb-1 text-xs font-medium tracking-wide text-muted-foreground uppercase">
              {t(`nav.groups.${group.key}`)}
            </p>
          )}
          <ul aria-labelledby={group.key && `${id}-${group.key}`} className="grid gap-0.5">
            {group.items.map((item) => (
              <li key={item.key}>
                <Link {...item.link} onClick={onNavigate}
                  className="flex min-h-9 items-center gap-3 rounded-lg px-3 text-sm font-medium text-muted-foreground transition-colors hover:bg-muted hover:text-foreground [&.active]:bg-accent [&.active]:text-accent-foreground">
                  <item.icon aria-hidden="true" className="size-4.5 shrink-0" />
                  {t(`nav.${item.key}`)}
                </Link>
              </li>
            ))}
          </ul>
        </div>
      ))}
    </nav>
  );
}
