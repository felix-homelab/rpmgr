// SPDX-License-Identifier: Apache-2.0

import { useId } from "react";
import { labelClass } from "@/components/field";
import { Textarea } from "@/components/ui/input";

// LinesField edits a list of strings, one per line; a required one needs at least a line.
export function LinesField({ label, hint, required, value, onChange }: {
  label: string; hint?: string; required?: boolean; value: string[]; onChange: (v: string[]) => void;
}) {
  const id = useId();
  return (
    <div className="grid gap-1.5">
      <label htmlFor={id} className={labelClass(required)}>{label}</label>
      <Textarea id={id} rows={2} required={required} aria-describedby={hint ? `${id}-hint` : undefined} className="min-h-16" value={value.join("\n")}
        onChange={(e) => onChange(e.target.value.split("\n").map((l) => l.trim()).filter((l, i, all) => l !== "" || i === all.length - 1))} />
      {hint && <p id={`${id}-hint`} className="text-xs text-muted-foreground">{hint}</p>}
    </div>
  );
}

// trimmed drops empty lines from what LinesField produced while typing.
export const trimmed = (v: string[]) => v.map((l) => l.trim()).filter(Boolean);
