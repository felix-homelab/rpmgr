// SPDX-License-Identifier: Apache-2.0

import { useId } from "react";
import type { Path, UseFormReturn } from "react-hook-form";
import { useTranslation } from "react-i18next";
import { Input } from "@/components/ui/input";
import type { RouteField, RouteValues } from "@/route-form/fields";

// FormField is one labelled field of the route form, with its error.
export function FormField<V extends RouteValues>({ field, form }: { field: RouteField; form: UseFormReturn<V> }) {
  const { t } = useTranslation();
  const id = useId();
  const error = form.formState.errors[field.key]?.message as string | undefined;
  const common = { id, "aria-invalid": error ? true : undefined, "aria-describedby": `${id}-hint ${id}-error`, ...form.register(field.key as Path<V>) };
  const box = "rounded-md border border-border bg-background px-3 py-1.5 text-sm";
  let input;
  switch (field.kind) {
    case "longtext":
    case "lines":
    case "pairs":
      input = <textarea rows={field.kind === "longtext" ? 2 : 3} className={box} {...common} />;
      break;
    case "select":
      input = (
        <select className={`h-9 ${box}`} {...common}>
          {field.options?.map(([v, k]) => <option key={v} value={v}>{t(`routeForm.options.${field.key}.${k}`)}</option>)}
        </select>
      );
      break;
    case "tristate":
      input = (
        <select className={`h-9 ${box}`} {...common}>
          {["", "true", "false"].map((v) => <option key={v} value={v}>{t(`routeForm.tristate.${v || "default"}`)}</option>)}
        </select>
      );
      break;
    default:
      input = <Input inputMode={field.kind.endsWith("umber") ? "numeric" : undefined} {...common} />;
  }
  return (
    <div className="grid gap-1.5">
      <label htmlFor={id} className="text-sm font-medium">{t(`routeForm.fields.${field.key}`)}</label>
      {input}
      <p id={`${id}-hint`} className="text-xs text-muted-foreground">{t(`routeForm.hints.${field.kind}`, { defaultValue: "" })}</p>
      {error && <p id={`${id}-error`} role="alert" className="text-sm text-destructive">{error}</p>}
    </div>
  );
}
