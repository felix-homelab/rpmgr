// SPDX-License-Identifier: Apache-2.0

import { CircleAlert } from "lucide-react";
import type { ReactNode } from "react";
import { useTranslation } from "react-i18next";
import { Mark } from "@/components/nav";

// PublicPage frames the pages that need no session: sign-in, first-user setup and resets, each a
// card in the middle of the page under the product's mark.
export function PublicPage({ title, children }: { title: string; children: ReactNode }) {
  const { t } = useTranslation();
  return (
    <main className="grid min-h-dvh place-items-center px-4 py-12">
      <div className="w-full max-w-sm">
        <p className="mb-6 flex items-center justify-center gap-2.5 text-lg font-semibold tracking-tight">
          <Mark />
          {t("app.name")}
        </p>
        <div className="rounded-xl border border-border bg-card p-6 shadow-sm sm:p-8">
          <h1 className="text-xl font-semibold tracking-tight">{title}</h1>
          <div className="mt-6">{children}</div>
        </div>
      </div>
    </main>
  );
}

// Alert is a message that screen readers announce when it appears; an error stands out in a box.
export function Alert({ children, tone = "error" }: { children: ReactNode; tone?: "error" | "info" }) {
  if (tone === "info") {
    return <p role="status" className="text-sm">{children}</p>;
  }
  return (
    <p role="alert" className="flex items-start gap-2 rounded-lg border border-destructive/30 bg-destructive/8 px-3 py-2 text-sm text-destructive">
      <CircleAlert aria-hidden="true" className="mt-0.5 size-4 shrink-0" />
      <span>{children}</span>
    </p>
  );
}
