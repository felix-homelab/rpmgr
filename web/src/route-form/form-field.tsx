// SPDX-License-Identifier: Apache-2.0

import { useId, type ReactNode } from "react";
import { useWatch, type Control, type Path, type UseFormReturn } from "react-hook-form";
import { useTranslation } from "react-i18next";
import { labelClass } from "@/components/field";
import { Input, Select, Textarea } from "@/components/ui/input";
import { CertificateSelect } from "@/route-form/certificate-select";
import { needsValue, type RouteField, type RouteValues } from "@/route-form/fields";

// FieldGrid lays the route form's fields out in two columns on wide screens; they read across, row
// by row, in the form's order.
export function FieldGrid({ children }: { children: ReactNode }) {
  return <div className="grid gap-4 xl:grid-cols-2 xl:items-start">{children}</div>;
}

// FormField is one labelled field of the route form, with its hint, if its kind or format has one,
// and its error. Screen readers hear both with the field, and whether it is required. A field shown
// only in some cases, such as the uploaded certificate, is left out otherwise. On the edit page
// (editing), a field set when the route is created shows its value read-only and is not sent
// changed.
export function FormField<V extends RouteValues>({ field, form, editing = false }: {
  field: RouteField; form: UseFormReturn<V>; editing?: boolean;
}) {
  const { t, i18n } = useTranslation();
  const id = useId();
  const control = form.control as unknown as Control<RouteValues>;
  const values = useWatch({ control }) as RouteValues;
  if (field.shown && !field.shown(values)) {
    return null;
  }
  const fixed = editing && field.fixed;
  const required = !fixed && needsValue(field, values);
  const warning = field.warning?.(values);
  const error = form.formState.errors[field.key]?.message as string | undefined;
  // A kind without a hint has no key, and t() would show the key itself.
  const hintKey = `routeForm.hints.${fixed ? "fixed" : field.hint ?? field.format?.kind ?? field.kind}`;
  const hint = i18n.exists(hintKey) ? t(hintKey) : "";
  const described = [hint && `${id}-hint`, error && `${id}-error`].filter(Boolean).join(" ") || undefined;
  const aria = { id, required, "aria-invalid": error ? true : undefined, "aria-describedby": described };
  const common = () => ({ ...aria, ...form.register(field.key as Path<V>) });
  let input;
  if (fixed) {
    const v = values[field.key] ?? "";
    const option = field.options?.find(([o]) => o === v)?.[1];
    input = <Input {...aria} readOnly value={option ? t(`routeForm.options.${field.key}.${option}`) : v} />;
  } else switch (field.kind) {
    case "longtext":
    case "lines":
    case "pairs":
      input = <Textarea rows={field.kind === "longtext" ? 2 : 3} {...common()} />;
      break;
    case "select":
      input = (
        <Select {...common()}>
          {field.options?.map(([v, k]) => <option key={v} value={v}>{t(`routeForm.options.${field.key}.${k}`)}</option>)}
        </Select>
      );
      break;
    case "tristate":
      input = (
        <Select {...common()}>
          {["", "true", "false"].map((v) => <option key={v} value={v}>{t(`routeForm.tristate.${v || "default"}`)}</option>)}
        </Select>
      );
      break;
    case "certificate":
      // Controlled, so that it shows the form's value whatever certificates it offers.
      input = <CertificateSelect {...aria} control={control} name={field.key} hostnames={values[field.covers ?? "hostnames"] ?? ""} />;
      break;
    default:
      input = <Input inputMode={field.kind.endsWith("umber") ? "numeric" : undefined} {...common()} />;
  }
  return (
    <div className="grid gap-1.5">
      <label htmlFor={id} className={labelClass(required)}>{t(`routeForm.fields.${field.key}`)}</label>
      {input}
      {hint && <p id={`${id}-hint`} className="text-xs text-muted-foreground">{hint}</p>}
      {warning && <p role="status" className="rounded-md border border-destructive/50 bg-destructive/5 p-2 text-sm text-destructive">{t(warning)}</p>}
      {error && <p id={`${id}-error`} role="alert" className="text-sm text-destructive">{error}</p>}
    </div>
  );
}
