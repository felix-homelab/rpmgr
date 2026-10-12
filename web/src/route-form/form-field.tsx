// SPDX-License-Identifier: Apache-2.0

import { useId } from "react";
import type { Path, UseFormReturn } from "react-hook-form";
import { useTranslation } from "react-i18next";
import { Input, Select, Textarea } from "@/components/ui/input";
import type { RouteField, RouteValues } from "@/route-form/fields";

// FormField is one labelled field of the route form, with its hint, if its kind has one, and its
// error. Screen readers hear both with the field.
export function FormField<V extends RouteValues>({ field, form }: { field: RouteField; form: UseFormReturn<V> }) {
  const { t, i18n } = useTranslation();
  const id = useId();
  const error = form.formState.errors[field.key]?.message as string | undefined;
  // A kind without a hint has no key, and t() would show the key itself.
  const hintKey = `routeForm.hints.${field.kind}`;
  const hint = i18n.exists(hintKey) ? t(hintKey) : "";
  const described = [hint && `${id}-hint`, error && `${id}-error`].filter(Boolean).join(" ") || undefined;
  const common = { id, "aria-invalid": error ? true : undefined, "aria-describedby": described, ...form.register(field.key as Path<V>) };
  let input;
  switch (field.kind) {
    case "longtext":
    case "lines":
    case "pairs":
      input = <Textarea rows={field.kind === "longtext" ? 2 : 3} {...common} />;
      break;
    case "select":
      input = (
        <Select {...common}>
          {field.options?.map(([v, k]) => <option key={v} value={v}>{t(`routeForm.options.${field.key}.${k}`)}</option>)}
        </Select>
      );
      break;
    case "tristate":
      input = (
        <Select {...common}>
          {["", "true", "false"].map((v) => <option key={v} value={v}>{t(`routeForm.tristate.${v || "default"}`)}</option>)}
        </Select>
      );
      break;
    default:
      input = <Input inputMode={field.kind.endsWith("umber") ? "numeric" : undefined} {...common} />;
  }
  return (
    <div className="grid gap-1.5">
      <label htmlFor={id} className="text-sm font-medium">{t(`routeForm.fields.${field.key}`)}</label>
      {input}
      {hint && <p id={`${id}-hint`} className="text-xs text-muted-foreground">{hint}</p>}
      {error && <p id={`${id}-error`} role="alert" className="text-sm text-destructive">{error}</p>}
    </div>
  );
}
