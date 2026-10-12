// SPDX-License-Identifier: Apache-2.0

import type { ComponentProps } from "react";
import { cn } from "@/lib/utils";

// RowList is a list whose rows hold details, actions or forms, separated by lines. In a card it
// reaches the card's edges and its bottom; framed, it is a card of its own.
export function RowList({ className, framed = false, ...props }: ComponentProps<"ul"> & { framed?: boolean }) {
  return (
    <ul className={cn(framed ? "divide-y divide-border rounded-xl border border-border bg-card shadow-xs"
      : "-mx-5 -mb-5 divide-y divide-border border-t border-border", className)} {...props} />
  );
}

export function Row({ className, ...props }: ComponentProps<"li">) {
  return <li className={cn("grid gap-3 px-5 py-4 text-sm", className)} {...props} />;
}

// panel is the look of a form that opens above a list, or of a block set apart in a row.
export const panel = "grid gap-3 rounded-lg border border-border bg-muted/40 p-4";
