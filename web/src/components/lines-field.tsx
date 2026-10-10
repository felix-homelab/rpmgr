// SPDX-License-Identifier: Apache-2.0

import { useId } from "react";

// LinesField edits a list of strings, one per line.
export function LinesField({ label, hint, value, onChange }: { label: string; hint?: string; value: string[]; onChange: (v: string[]) => void }) {
  const id = useId();
  return (
    <div className="grid gap-1.5">
      <label htmlFor={id} className="text-sm font-medium">{label}</label>
      <textarea id={id} rows={2} aria-describedby={hint ? `${id}-hint` : undefined}
        className="rounded-md border border-border bg-background px-3 py-1.5 text-sm" value={value.join("\n")}
        onChange={(e) => onChange(e.target.value.split("\n").map((l) => l.trim()).filter((l, i, all) => l !== "" || i === all.length - 1))} />
      {hint && <p id={`${id}-hint`} className="text-xs text-muted-foreground">{hint}</p>}
    </div>
  );
}

// trimmed drops empty lines from what LinesField produced while typing.
export const trimmed = (v: string[]) => v.map((l) => l.trim()).filter(Boolean);
