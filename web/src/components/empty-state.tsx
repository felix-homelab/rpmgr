// SPDX-License-Identifier: Apache-2.0

import type { LucideIcon } from "lucide-react";
import type { ReactNode } from "react";

// EmptyState stands where a list has nothing to show: what is missing, and the action that adds
// the first one, if there is one.
export function EmptyState({ icon: Icon, children, action }: { icon?: LucideIcon; children: ReactNode; action?: ReactNode }) {
  return (
    <div className="grid justify-items-center gap-3 rounded-xl border border-dashed border-border px-6 py-10 text-center text-sm text-muted-foreground">
      {Icon && <Icon aria-hidden="true" className="size-6" />}
      <p>{children}</p>
      {action}
    </div>
  );
}
