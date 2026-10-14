// SPDX-License-Identifier: Apache-2.0

import { Copy } from "lucide-react";
import { useTranslation } from "react-i18next";
import { Button } from "@/components/ui/button";
import { ownPort, policyCommand } from "@/routes-data";

// PolicyHint shows, for a target a connector's local policy blocks, the command that lets it
// through with a copy button, or, for one of rpmgr's own ports, why nothing does
// (docs/09-web-ui.md, U4; ADR-0019).
export function PolicyHint({ detail, className = "bg-card" }: { detail: string; className?: string }) {
  const { t } = useTranslation();
  const command = policyCommand(detail);
  if (command === undefined) {
    return <span>{t("notServing.ownPort", { target: detail.slice(0, -ownPort.length) })}</span>;
  }
  return (
    <span className="flex flex-wrap items-center gap-2">
      <code className={`rounded-md px-2 py-1 font-mono ${className}`}>{command}</code>
      <Button size="sm" variant="outline" onClick={() => void navigator.clipboard?.writeText(command)}>
        <Copy aria-hidden="true" />{t("mfa.copy")}
      </Button>
    </span>
  );
}
