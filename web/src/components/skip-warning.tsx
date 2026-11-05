// SPDX-License-Identifier: Apache-2.0

import { useQuery } from "@connectrpc/connect-query";
import { useTranslation } from "react-i18next";
import { ReleaseService, type PreviewRolloutResponse } from "@/gen/rpmgr/v1/release_pb";

// useRolloutPreview asks which agents a rollout would skip because the update policy their host
// reported refuses the release, and whether that leaves its first stage testing nothing, in which
// case `blocked` says why and the rollout must not start (CreateRollout refuses it). A staged
// rollout names its canary agents, an easy one its queue; a staged rollout with no canary yet
// previews every agent. A failed preview gives no data: the host is the authority in the end, so a
// missing warning never blocks a rollout.
export function useRolloutPreview(releaseId: string, stage: { canaryAgentIds?: string[]; agentIds?: string[] }) {
  const canary = stage.canaryAgentIds ?? [];
  const queue = stage.agentIds ?? [];
  const preview = useQuery(ReleaseService.method.previewRollout, { releaseId, canaryAgentIds: canary, agentIds: queue },
    { enabled: stage.agentIds === undefined || queue.length > 0 });
  return preview.data;
}

// SkipWarning warns before a rollout starts which agents it will skip, with the name, the reason
// and the command that changes the host's policy for each (docs/09-web-ui.md, "Settings"), or, when
// the first stage would test nothing, an error saying so. It shows nothing when no agent is
// skipped.
export function SkipWarning({ preview }: { preview?: PreviewRolloutResponse }) {
  const { t } = useTranslation();
  const skipped = preview?.skipped ?? [];
  if (skipped.length === 0) return null;
  const blocked = !!preview?.blocked;
  return (
    <div role="alert" className={`grid gap-2 rounded-lg border p-3 text-sm ${blocked ? "border-destructive/40 bg-destructive/10" : "border-warn/40 bg-warn/10"}`}>
      <p className={`font-medium ${blocked ? "text-destructive" : "text-warn"}`}>
        {t("updates.skip.title", { count: skipped.length, total: preview?.total ?? skipped.length })}
      </p>
      {blocked && <p className="font-medium text-destructive">{t("updates.skip.blocked")}</p>}
      <p className="text-muted-foreground">{t("updates.skip.help")}</p>
      <ul className="grid gap-2">
        {skipped.map((a) => (
          <li key={a.agentId} className="grid gap-0.5">
            <span><span className="font-medium">{a.agentName}</span>: {a.reason}</span>
            <code className="w-fit rounded bg-muted px-1.5 py-0.5 text-xs">{a.command}</code>
          </li>
        ))}
      </ul>
    </div>
  );
}
