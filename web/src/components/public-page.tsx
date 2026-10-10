// SPDX-License-Identifier: Apache-2.0

import type { ReactNode } from "react";

// PublicPage frames the pages that need no session: sign-in, first-user setup and resets.
export function PublicPage({ title, children }: { title: string; children: ReactNode }) {
  return (
    <main className="mx-auto mt-16 max-w-sm px-4">
      <h1 className="text-2xl font-semibold">{title}</h1>
      <div className="mt-6">{children}</div>
    </main>
  );
}

// Alert is a message that screen readers announce when it appears.
export function Alert({ children, tone = "error" }: { children: ReactNode; tone?: "error" | "info" }) {
  return (
    <p role={tone === "error" ? "alert" : "status"} className={tone === "error" ? "text-sm text-destructive" : "text-sm"}>
      {children}
    </p>
  );
}
