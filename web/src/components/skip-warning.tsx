// SPDX-License-Identifier: Apache-2.0

import { useQuery } from "@connectrpc/connect-query";
import { useTranslation } from "react-i18next";
import { ReleaseService } from "@/gen/rpmgr/v1/release_pb";

// SkipWarning warns before a rollout starts which agents it will skip because the update policy
// their host reported refuses the release: how many of how many, and for each the name, the reason
// and the command that changes the host's policy (docs/09-web-ui.md, "Settings"). agentIds is an
// easy rollout's queue; left out it previews a staged rollout, which targets every agent. It shows
// nothing while it loads, when the preview fails, or when no agent is skipped: the host is the
// authority in the end, so a missing warning never blocks a rollout.
export function SkipWarning({ releaseId, agentIds }: { releaseId: string; agentIds?: string[] }) {
  const { t } = useTranslation();
  const preview = useQuery(ReleaseService.method.previewRollout, { releaseId, agentIds: agentIds ?? [] },
    { enabled: !agentIds || agentIds.length > 0 });
  const skipped = preview.data?.skipped ?? [];
  if (skipped.length === 0) return null;
  return (
    <div role="alert" className="grid gap-2 rounded-lg border border-warn/40 bg-warn/10 p-3 text-sm">
      <p className="font-medium text-warn">{t("updates.skip.title", { count: skipped.length, total: preview.data?.total ?? skipped.length })}</p>
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
