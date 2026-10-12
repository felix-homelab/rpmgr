// SPDX-License-Identifier: Apache-2.0
// Adapted from shadcn/ui (https://github.com/shadcn-ui/ui), Copyright (c) 2023 shadcn, under the MIT
// License in LICENSE.shadcn-ui.md.

import { useId, type ComponentProps, type ReactNode } from "react";
import { cn } from "@/lib/utils";

// Card is a region of a page with a title, which names it for screen readers, an optional
// description and actions, and its content.
export function Card({ title, description, actions, className, children, ...props }:
  Omit<ComponentProps<"section">, "title"> & { title?: ReactNode; description?: ReactNode; actions?: ReactNode }) {
  const id = useId();
  return (
    <section aria-labelledby={title ? id : undefined} className={cn("grid content-start gap-4 rounded-xl border border-border bg-card p-5 shadow-xs", className)} {...props}>
      {(title || actions) && (
        <div className="flex flex-wrap items-start justify-between gap-x-4 gap-y-2">
          <div className="grid gap-1">
            {title && <h2 id={id} className="font-semibold">{title}</h2>}
            {description && <p className="text-sm text-muted-foreground">{description}</p>}
          </div>
          {actions && <div className="flex flex-wrap items-center gap-2">{actions}</div>}
        </div>
      )}
      {children}
    </section>
  );
}
