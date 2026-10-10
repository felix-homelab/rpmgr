// SPDX-License-Identifier: Apache-2.0

import { useId, type ComponentProps } from "react";
import { Input } from "@/components/ui/input";

export interface FieldProps extends ComponentProps<"input"> {
  label: string;
  hint?: string;
}

// Field is a labelled input with an optional hint that screen readers announce with it.
export function Field({ label, hint, ...props }: FieldProps) {
  const id = useId();
  return (
    <div className="grid gap-1.5">
      <label htmlFor={id} className="text-sm font-medium">
        {label}
      </label>
      <Input id={id} aria-describedby={hint ? `${id}-hint` : undefined} {...props} />
      {hint && (
        <p id={`${id}-hint`} className="text-xs text-muted-foreground">
          {hint}
        </p>
      )}
    </div>
  );
}
