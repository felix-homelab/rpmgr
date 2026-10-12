// SPDX-License-Identifier: Apache-2.0
// Adapted from shadcn/ui (https://github.com/shadcn-ui/ui), Copyright (c) 2023 shadcn, under the MIT
// License in LICENSE.shadcn-ui.md.

import type { ComponentProps } from "react";
import { cn } from "@/lib/utils";

// Table is a table that scrolls sideways on narrow screens rather than squeezing its columns. It
// has its own frame, unless it sits in a card (framed={false}), whose edges it then reaches.
export function Table({ className, framed = true, ...props }: ComponentProps<"table"> & { framed?: boolean }) {
  return (
    <div className={framed ? "w-full overflow-x-auto rounded-xl border border-border bg-card shadow-xs" : "-mx-5 overflow-x-auto"}>
      <table className={cn("w-full text-left text-sm", className)} {...props} />
    </div>
  );
}

export function THead({ className, ...props }: ComponentProps<"thead">) {
  return <thead className={cn("border-b border-border bg-muted/50 text-muted-foreground", className)} {...props} />;
}

// TH is a column's heading.
export function TH({ className, ...props }: ComponentProps<"th">) {
  return <th scope="col" className={cn("px-4 py-2.5 font-medium whitespace-nowrap first:pl-5 last:pr-5", className)} {...props} />;
}

export function TR({ className, ...props }: ComponentProps<"tr">) {
  return <tr className={cn("border-t border-border align-top first:border-t-0", className)} {...props} />;
}

export function TD({ className, ...props }: ComponentProps<"td">) {
  return <td className={cn("px-4 py-3 first:pl-5 last:pr-5", className)} {...props} />;
}
