// SPDX-License-Identifier: Apache-2.0

import { useId } from "react";
import { useTranslation } from "react-i18next";
import { labelClass } from "@/components/field";
import { Textarea } from "@/components/ui/input";

// PemField takes PEM text, pasted or read from a file in the browser; nothing is uploaded until the
// form is sent.
export function PemField({ label, value, onChange, secret, required }: {
  label: string; value: string; onChange: (v: string) => void; secret?: boolean; required?: boolean;
}) {
  const { t } = useTranslation();
  const id = useId();
  return (
    <div className="grid gap-1.5">
      <label htmlFor={id} className={labelClass(required)}>{label}</label>
      <Textarea id={id} rows={4} required={required} spellCheck={false} autoComplete="off" className="font-mono text-xs"
        value={value} onChange={(e) => onChange(e.target.value)} />
      <label className="flex flex-wrap items-center gap-2 text-xs text-muted-foreground">
        {t(secret ? "pem.fileSecret" : "pem.file")}
        <input type="file" accept=".pem,.crt,.key,text/plain"
          className="text-xs file:mr-2 file:rounded-md file:border file:border-border file:bg-card file:px-2.5 file:py-1 file:text-xs file:font-medium file:text-foreground hover:file:bg-muted"
          onChange={(e) => void e.target.files?.[0]?.text().then(onChange)} />
      </label>
    </div>
  );
}
