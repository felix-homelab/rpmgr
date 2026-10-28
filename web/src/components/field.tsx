// SPDX-License-Identifier: Apache-2.0

import { useId, type ComponentProps } from "react";
import { Input } from "@/components/ui/input";
import { cn } from "@/lib/utils";

// labelClass is the look of a field's label. A required field's label ends in a red asterisk
// (index.css, "required-mark"); its control carries the required attribute for screen readers.
export const labelClass = (required?: boolean) => cn("text-sm font-medium", required && "required-mark");

export interface FieldProps extends ComponentProps<"input"> {
  label: string;
  hint?: string;
  // error is what is wrong with the value, from the form's check or the API's answer.
  error?: string;
}

// Field is a labelled input with an optional hint, and the error of its value, that screen readers
// announce with it.
export function Field({ label, hint, error, ...props }: FieldProps) {
  const id = useId();
  return (
    <div className="grid gap-1.5">
      <label htmlFor={id} className={labelClass(props.required)}>
        {label}
      </label>
      <Input id={id} aria-invalid={error ? true : undefined} aria-describedby={[hint && `${id}-hint`, error && `${id}-error`].filter(Boolean).join(" ") || undefined} {...props} />
      {hint && (
        <p id={`${id}-hint`} className="text-xs text-muted-foreground">
          {hint}
        </p>
      )}
      {error && (
        <p id={`${id}-error`} className="text-xs text-destructive">
          {error}
        </p>
      )}
    </div>
  );
}
