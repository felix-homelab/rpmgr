// SPDX-License-Identifier: Apache-2.0

import { useMutation, useQuery } from "@connectrpc/connect-query";
import { useQueryClient } from "@tanstack/react-query";
import { Link, useNavigate } from "@tanstack/react-router";
import { ChevronDown, LogOut, UserRound } from "lucide-react";
import { useEffect, useId, useRef, useState } from "react";
import { useTranslation } from "react-i18next";
import { AuthService } from "@/gen/rpmgr/v1/auth_pb";

const item = "flex w-full items-center gap-2.5 rounded-lg px-2.5 py-2 text-left text-sm hover:bg-muted [&_svg]:size-4 [&_svg]:text-muted-foreground";

// UserMenu names the signed-in user and leads to their account and to signing out. It is a
// disclosure: its button opens the panel under it, and Escape, a click elsewhere or a choice close
// it; Escape returns to the button.
export function UserMenu() {
  const { t } = useTranslation();
  const session = useQuery(AuthService.method.getSession, {}).data;
  const logout = useMutation(AuthService.method.logout);
  const queryClient = useQueryClient();
  const navigate = useNavigate();
  const [open, setOpen] = useState(false);
  const id = useId();
  const root = useRef<HTMLDivElement>(null);
  const button = useRef<HTMLButtonElement>(null);
  const name = session?.displayName || session?.email || "";

  useEffect(() => {
    if (!open) {
      return;
    }
    const outside = (e: PointerEvent) => {
      if (!root.current?.contains(e.target as Node)) {
        setOpen(false);
      }
    };
    const escape = (e: KeyboardEvent) => {
      if (e.key === "Escape") {
        setOpen(false);
        button.current?.focus();
      }
    };
    document.addEventListener("pointerdown", outside);
    document.addEventListener("keydown", escape);
    return () => {
      document.removeEventListener("pointerdown", outside);
      document.removeEventListener("keydown", escape);
    };
  }, [open]);

  async function signOut() {
    setOpen(false);
    try {
      await logout.mutateAsync({});
    } finally {
      queryClient.clear();
      await navigate({ to: "/login", search: {} });
    }
  }

  return (
    <div ref={root} className="relative">
      <button ref={button} type="button" aria-expanded={open} aria-controls={id} aria-label={t("app.userMenu", { name })}
        onClick={() => setOpen(!open)} className="flex h-9 items-center gap-2 rounded-lg pr-2 pl-1 transition-colors hover:bg-muted">
        <span aria-hidden="true" className="grid size-7 place-items-center rounded-full bg-primary/12 text-xs font-semibold text-accent-foreground uppercase">
          {name.slice(0, 1)}
        </span>
        <span aria-hidden="true" className="hidden max-w-40 truncate text-sm font-medium sm:block">{name}</span>
        <ChevronDown aria-hidden="true" className="size-4 text-muted-foreground" />
      </button>
      {open && (
        <div id={id} className="absolute top-full right-0 z-40 mt-2 w-64 rounded-xl border border-border bg-card p-1.5 shadow-lg">
          <div className="px-2.5 py-2">
            <p className="truncate text-sm font-medium">{name}</p>
            {session?.displayName && <p className="truncate text-xs text-muted-foreground">{session.email}</p>}
          </div>
          <hr className="my-1 border-border" />
          <Link to="/account" onClick={() => setOpen(false)} className={item}>
            <UserRound aria-hidden="true" />
            {t("app.account")}
          </Link>
          <button type="button" onClick={() => void signOut()} disabled={logout.isPending} className={item}>
            <LogOut aria-hidden="true" />
            {t("app.signOut")}
          </button>
        </div>
      )}
    </div>
  );
}
