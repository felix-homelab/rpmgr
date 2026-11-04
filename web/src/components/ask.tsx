// SPDX-License-Identifier: Apache-2.0

import { useState, type ReactNode } from "react";
import { useTranslation } from "react-i18next";
import { Button } from "@/components/ui/button";

// Ask is an action that needs a confirmation naming its object (docs/09-web-ui.md, U7): a button
// that opens the question, and the question's confirm and cancel buttons. The answer is up to
// onConfirm, which may ask for a step-up first.
export function Ask({ label, question, confirm, busy, destructive, disabled, onConfirm }: {
  label: string; question: ReactNode; confirm: string; busy?: boolean; destructive?: boolean; disabled?: boolean; onConfirm: () => Promise<void>;
}) {
  const { t } = useTranslation();
  const [asking, setAsking] = useState(false);
  if (!asking) {
    return <Button size="sm" variant={destructive ? "destructive" : "outline"} disabled={disabled} onClick={() => setAsking(true)}>{label}</Button>;
  }
  return (
    <div className="flex flex-wrap items-center gap-2" role="group" aria-label={label}>
      <span>{question}</span>
      <Button size="sm" variant={destructive ? "destructive" : "default"} disabled={busy} onClick={() => void onConfirm().finally(() => setAsking(false))}>{confirm}</Button>
      <Button size="sm" variant="outline" onClick={() => setAsking(false)}>{t("stepUp.cancel")}</Button>
    </div>
  );
}
