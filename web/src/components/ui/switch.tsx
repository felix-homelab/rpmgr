// SPDX-License-Identifier: Apache-2.0

import type { ComponentProps } from "react";
import { cn } from "@/lib/utils";

// Switch is an on/off button (role switch) drawn as a track with a thumb, its label next to it.
export function Switch({ checked, className, children, ...props }: Omit<ComponentProps<"button">, "role"> & { checked: boolean }) {
  return (
    <button type="button" role="switch" aria-checked={checked}
      className={cn("group inline-flex h-8 items-center gap-2 rounded-lg px-1.5 text-sm font-medium hover:bg-muted disabled:opacity-50", className)} {...props}>
      <span aria-hidden="true" className="relative h-5 w-9 shrink-0 rounded-full bg-input transition-colors group-aria-checked:bg-primary">
        <span className="absolute top-0.5 left-0.5 size-4 rounded-full bg-card shadow-sm transition-transform group-aria-checked:translate-x-4" />
      </span>
      {children}
    </button>
  );
}
