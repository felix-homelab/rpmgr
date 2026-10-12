// SPDX-License-Identifier: Apache-2.0

import { useNavigate } from "@tanstack/react-router";
import { Search } from "lucide-react";
import { useEffect, useId, useRef, useState, type KeyboardEvent } from "react";
import { useTranslation } from "react-i18next";
import { navGroups } from "@/components/nav";
import { useConnectors, useGateways, useGroups, useRoutes } from "@/routes-data";
import { useOrg } from "@/session";

export interface Command {
  // What it is, such as "Route"; resources are found by name and ID, the rest by label.
  kind: string;
  label: string;
  id?: string;
  run: () => void;
}

// matches returns the commands that match a query, those whose label starts with it first. Without
// a query, it returns those that are not resources.
export function matches(commands: Command[], query: string): Command[] {
  const q = query.trim().toLowerCase();
  if (q === "") {
    return commands.filter((c) => !c.id);
  }
  const rank = (c: Command) => {
    const label = c.label.toLowerCase();
    return label.startsWith(q) ? 0 : label.includes(q) ? 1 : c.id?.toLowerCase().startsWith(q) ? 2 : 3;
  };
  return commands.map((c) => ({ c, r: rank(c) })).filter((x) => x.r < 3).sort((a, b) => a.r - b.r).map((x) => x.c);
}

// CommandPalette opens on Ctrl+K or ⌘K, or from its button, and jumps to a page or a resource by
// name or ID, or runs a common action (docs/09-web-ui.md, U9).
export function CommandPalette() {
  const { t } = useTranslation();
  const [open, setOpen] = useState(false);
  useEffect(() => {
    const onKey = (e: globalThis.KeyboardEvent) => {
      if ((e.ctrlKey || e.metaKey) && e.key.toLowerCase() === "k") {
        e.preventDefault();
        setOpen(true);
      }
    };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, []);
  return (
    <>
      <button type="button" aria-keyshortcuts="Control+K Meta+K" onClick={() => setOpen(true)}
        className="flex h-9 w-full max-w-md items-center gap-2 rounded-lg border border-input bg-card px-3 text-sm text-muted-foreground shadow-xs transition-colors hover:bg-muted">
        <Search aria-hidden="true" className="size-4 shrink-0" />
        <span className="flex-1 truncate text-left">{t("palette.open")}</span>
        <kbd className="hidden rounded border border-border bg-muted px-1.5 font-sans text-xs sm:inline">Ctrl K</kbd>
      </button>
      {open && <Palette onClose={() => setOpen(false)} />}
    </>
  );
}

function useCommands(): Command[] {
  const { t } = useTranslation();
  const navigate = useNavigate();
  const org = useOrg()?.orgId;
  const routes = useRoutes(org).data ?? [];
  const connectors = useConnectors(org).data ?? [];
  const groups = useGroups(org).data ?? [];
  const gateways = useGateways(org).data ?? [];
  const page = (label: string, go: () => Promise<void>) => ({ kind: t("palette.page"), label, run: () => void go() });
  return [
    { kind: t("palette.action"), label: t("palette.createRoute"), run: () => void navigate({ to: "/routes/new" }) },
    { kind: t("palette.action"), label: t("palette.enroll"), run: () => void navigate({ to: "/connectors", search: { enroll: true } }) },
    ...navGroups.flatMap((g) => g.items).map((item) => page(t(`nav.${item.key}`), () => navigate(item.link))),
    page(t("palette.account"), () => navigate({ to: "/account" })),
    ...routes.map((r) => ({ kind: t("palette.route"), label: r.name, id: r.id, run: () => void navigate({ to: "/routes/$routeId", params: { routeId: r.id } }) })),
    ...connectors.map((c) => ({ kind: t("palette.connector"), label: c.name, id: c.id,
      run: () => void navigate({ to: "/connectors/$connectorId", params: { connectorId: c.id } }) })),
    ...groups.map((g) => ({ kind: t("palette.group"), label: g.name, id: g.id, run: () => void navigate({ to: "/gateways/$groupId", params: { groupId: g.id } }) })),
    ...gateways.map((g) => ({ kind: t("palette.gateway"), label: g.name, id: g.id,
      run: () => void navigate({ to: "/gateways/$groupId", params: { groupId: g.gatewayGroupId } }) })),
  ];
}

const most = 50;

function Palette({ onClose }: { onClose: () => void }) {
  const { t } = useTranslation();
  const dialog = useRef<HTMLDialogElement>(null);
  const list = useId();
  useEffect(() => dialog.current?.showModal(), []);
  const [query, setQuery] = useState("");
  const [active, setActive] = useState(0);
  const shown = matches(useCommands(), query).slice(0, most);
  const current = Math.min(active, shown.length - 1);
  // The effect returns nothing: browsers whose scrollIntoView returns a promise would otherwise
  // hand React the promise as its cleanup.
  useEffect(() => {
    document.getElementById(`${list}-${current}`)?.scrollIntoView?.({ block: "nearest" });
  }, [list, current]);
  function run(c: Command | undefined) {
    if (c) {
      onClose();
      c.run();
    }
  }
  function onKey(e: KeyboardEvent<HTMLInputElement>) {
    const step = { ArrowDown: 1, ArrowUp: -1 }[e.key];
    if (step && shown.length > 0) {
      e.preventDefault();
      setActive((current + step + shown.length) % shown.length);
    } else if (e.key === "Enter") {
      e.preventDefault();
      run(shown[current]);
    }
  }
  return (
    <dialog ref={dialog} aria-label={t("palette.title")} onCancel={onClose} onClick={(e) => e.target === e.currentTarget && onClose()}
      className="mx-auto mt-[12vh] w-[calc(100%-2rem)] max-w-xl overflow-hidden rounded-xl border border-border bg-card p-0 shadow-2xl">
      <div className="flex items-center gap-2 border-b border-border px-4 focus-within:border-ring">
        <Search aria-hidden="true" className="size-4 shrink-0 text-muted-foreground" />
        <input role="combobox" aria-expanded="true" aria-controls={list} aria-autocomplete="list" aria-label={t("palette.search")}
          aria-activedescendant={current >= 0 ? `${list}-${current}` : undefined} value={query} autoFocus placeholder={t("palette.search")}
          onChange={(e) => { setQuery(e.target.value); setActive(0); }} onKeyDown={onKey}
          className="h-12 w-full bg-transparent text-sm placeholder:text-muted-foreground focus-visible:outline-none" />
      </div>
      <ul id={list} role="listbox" aria-label={t("palette.results")} className="max-h-80 overflow-y-auto p-2 text-sm">
        {shown.map((c, i) => (
          <li key={`${c.kind}-${c.id ?? c.label}`} id={`${list}-${i}`} role="option" aria-selected={i === current}
            onClick={() => run(c)} onMouseMove={() => setActive(i)}
            className="flex cursor-pointer items-center justify-between gap-4 rounded-lg px-3 py-2 aria-selected:bg-accent aria-selected:text-accent-foreground">
            <span className="truncate font-medium">{c.label}</span>
            <span className="shrink-0 text-xs text-muted-foreground">{c.id ? `${c.kind} · ${c.id}` : c.kind}</span>
          </li>
        ))}
      </ul>
      {shown.length === 0 && <p className="px-5 pb-5 text-sm text-muted-foreground">{t("palette.none")}</p>}
    </dialog>
  );
}
