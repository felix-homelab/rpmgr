// SPDX-License-Identifier: Apache-2.0
// Adapted from shadcn/ui (https://github.com/shadcn-ui/ui), Copyright (c) 2023 shadcn, under the MIT
// License in LICENSE.shadcn-ui.md.

import { ChevronDown } from "lucide-react";
import type { ComponentProps } from "react";
import { cn } from "@/lib/utils";

// control is the look of every text field and select: a bordered box in the card colour whose
// border takes the accent colour on focus.
export const control =
  "w-full rounded-lg border border-input bg-card px-3 text-sm shadow-xs transition-colors placeholder:text-muted-foreground focus-visible:border-ring focus-visible:outline-none focus-visible:ring-3 focus-visible:ring-ring/25 disabled:cursor-not-allowed disabled:opacity-50 aria-invalid:border-destructive read-only:bg-muted";

export function Input({ className, ...props }: ComponentProps<"input">) {
  return <input className={cn(control, "flex h-9 py-1", className)} {...props} />;
}

export function Textarea({ className, ...props }: ComponentProps<"textarea">) {
  return <textarea className={cn(control, "min-h-20 py-2", className)} {...props} />;
}

// Select is the browser's own select, so it keeps its keyboard and screen-reader behaviour, drawn
// like a text field with a chevron.
export function Select({ className, ...props }: ComponentProps<"select">) {
  return (
    <span className={cn("relative inline-flex", className)}>
      <select className={cn(control, "h-9 appearance-none pr-8")} {...props} />
      <ChevronDown className="pointer-events-none absolute top-1/2 right-2.5 size-4 -translate-y-1/2 text-muted-foreground" />
    </span>
  );
}
