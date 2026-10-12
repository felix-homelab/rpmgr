// SPDX-License-Identifier: Apache-2.0

import type { ReactNode } from "react";

// PageHeader is the top of a page: its title, the page's only first-level heading, with an optional
// description and the page's actions to the right.
export function PageHeader({ id, title, description, actions }: { id?: string; title: ReactNode; description?: ReactNode; actions?: ReactNode }) {
  return (
    <div className="flex flex-wrap items-end justify-between gap-x-6 gap-y-3">
      <div className="grid gap-1">
        <h1 id={id} className="text-2xl font-semibold tracking-tight">{title}</h1>
        {description && <p className="text-sm text-muted-foreground">{description}</p>}
      </div>
      {actions && <div className="flex flex-wrap items-center gap-2">{actions}</div>}
    </div>
  );
}
