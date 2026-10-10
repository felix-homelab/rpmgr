// SPDX-License-Identifier: Apache-2.0

import { useState } from "react";
import { useTranslation } from "react-i18next";
import { Button } from "@/components/ui/button";

// mask hides a token but its kind and its checksum (docs/09-web-ui.md, "Enroll connector dialog").
export function mask(token: string): string {
  const kind = token.indexOf("_", "rpmgr_".length) + 1;
  return `${token.slice(0, kind)}${"•".repeat(12)}${token.slice(token.lastIndexOf("_"))}`;
}

// OneTimeToken shows a token the server returns only once: masked until shown, with a copy button.
export function OneTimeToken({ token, label }: { token: string; label: string }) {
  const { t } = useTranslation();
  const [show, setShow] = useState(false);
  return (
    <div className="flex items-center gap-2">
      <code aria-label={label} className="grow break-all rounded bg-muted p-2 font-mono text-xs">{show ? token : mask(token)}</code>
      <Button size="sm" variant="outline" onClick={() => void navigator.clipboard?.writeText(token)}>{t("mfa.copy")}</Button>
      <Button size="sm" variant="outline" aria-pressed={show} onClick={() => setShow(!show)}>{t(show ? "enroll.hide" : "enroll.show")}</Button>
    </div>
  );
}

// Command shows a command to run on a host, with a copy button.
export function Command({ command, label }: { command: string; label: string }) {
  const { t } = useTranslation();
  return (
    <div className="flex items-start gap-2">
      <pre aria-label={label} className="grow overflow-x-auto rounded bg-muted p-2 font-mono text-xs">{command}</pre>
      <Button size="sm" variant="outline" onClick={() => void navigator.clipboard?.writeText(command)}>{t("mfa.copy")}</Button>
    </div>
  );
}
