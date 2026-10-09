// SPDX-License-Identifier: Apache-2.0

import { useId } from "react";
import { useTranslation } from "react-i18next";

// PemField takes PEM text, pasted or read from a file in the browser; nothing is uploaded until the
// form is sent.
export function PemField({ label, value, onChange, secret }: { label: string; value: string; onChange: (v: string) => void; secret?: boolean }) {
  const { t } = useTranslation();
  const id = useId();
  return (
    <div className="grid gap-1.5">
      <label htmlFor={id} className="text-sm font-medium">{label}</label>
      <textarea id={id} rows={4} spellCheck={false} autoComplete="off" className="rounded-md border border-border bg-background px-3 py-1.5 font-mono text-xs"
        value={value} onChange={(e) => onChange(e.target.value)} />
      <label className="text-xs text-muted-foreground">
        {t(secret ? "pem.fileSecret" : "pem.file")}{" "}
        <input type="file" accept=".pem,.crt,.key,text/plain" className="text-xs"
          onChange={(e) => void e.target.files?.[0]?.text().then(onChange)} />
      </label>
    </div>
  );
}
