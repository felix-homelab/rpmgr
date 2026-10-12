// SPDX-License-Identifier: Apache-2.0
// Adapted from shadcn/ui (https://github.com/shadcn-ui/ui), Copyright (c) 2023 shadcn, under the MIT
// License in LICENSE.shadcn-ui.md.

import { cva, type VariantProps } from "class-variance-authority";
import type { ComponentProps } from "react";
import { cn } from "@/lib/utils";

// The tones of a badge. Each badge also carries text, and states carry an icon, so that no state is
// told by colour alone (docs/09-web-ui.md, U8).
const badgeVariants = cva(
  "inline-flex w-fit items-center gap-1 rounded-full px-2 py-0.5 text-xs font-medium whitespace-nowrap [&_svg]:size-3.5 [&_svg]:shrink-0",
  {
    variants: {
      tone: {
        neutral: "bg-muted text-muted-foreground",
        accent: "bg-primary/12 text-accent-foreground",
        ok: "bg-ok/12 text-ok",
        warn: "bg-warn/12 text-warn",
        danger: "bg-destructive/12 text-destructive",
      },
    },
    defaultVariants: { tone: "neutral" },
  },
);

export type Tone = NonNullable<VariantProps<typeof badgeVariants>["tone"]>;

export function Badge({ className, tone, ...props }: ComponentProps<"span"> & VariantProps<typeof badgeVariants>) {
  return <span className={cn(badgeVariants({ tone }), className)} {...props} />;
}
