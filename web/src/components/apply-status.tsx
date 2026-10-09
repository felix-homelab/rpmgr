// SPDX-License-Identifier: Apache-2.0

import { create } from "@bufbuild/protobuf";
import { createClient } from "@connectrpc/connect";
import { useTransport } from "@connectrpc/connect-query";
import { useEffect, useState } from "react";
import { useTranslation } from "react-i18next";
import type { Revision } from "@/gen/rpmgr/v1/common_pb";
import { ApplyState, ApplyStatusSchema, StatusService, type ApplyStatus } from "@/gen/rpmgr/v1/status_pb";
import { when } from "@/lib/format";
import { cn } from "@/lib/utils";

const final = new Set([ApplyState.APPLIED, ApplyState.REJECTED, ApplyState.APPLY_TIMEOUT]);

// useLiveApplyStatus follows a revision's apply status from the one a write returned, through
// WatchApplyStatus, until it is final or the watch ends (docs/07-api.md, "Writes and apply status").
export function useLiveApplyStatus(orgId: string, revision: Revision | undefined, first: ApplyStatus | undefined): ApplyStatus | undefined {
  const transport = useTransport();
  const [live, setLive] = useState<{ revision: Revision; status: ApplyStatus }>();
  useEffect(() => {
    if (!revision || !first || final.has(first.state)) {
      return;
    }
    const abort = new AbortController();
    void (async () => {
      try {
        const stream = createClient(StatusService, transport).watchApplyStatus({ orgId, revision }, { signal: abort.signal });
        for await (const m of stream) {
          setLive({ revision, status: m.applyStatus ?? create(ApplyStatusSchema) });
        }
      } catch {
        // The watch ended early, or the page went away; the status shown stays the last one.
      }
    })();
    return () => abort.abort();
  }, [orgId, revision, first, transport]);
  return live && live.revision === revision ? live.status : first;
}

// ApplyStatusView says how far the org's agents are with a revision (docs/09-web-ui.md, U2): the
// state over the online agents, each that has not applied it with its reasons, and the offline
// agents, which get it when they connect. Screen readers hear each change (U8).
export function ApplyStatusView({ status, revision, name }: { status: ApplyStatus; revision?: Revision; name: (id: string) => string }) {
  const { t } = useTranslation();
  const look = {
    [ApplyState.UNSPECIFIED]: ["?", "unknown", ""],
    [ApplyState.PENDING]: ["⧗", "pending", "text-muted-foreground"],
    [ApplyState.APPLIED]: ["✓", "applied", "text-ok"],
    [ApplyState.REJECTED]: ["✕", "rejected", "text-destructive"],
    [ApplyState.APPLY_TIMEOUT]: ["⏱", "timeout", "text-destructive"],
  }[status.state];
  return (
    <div role="status" aria-live="polite" className="grid gap-1 text-sm">
      <p className={cn("font-medium", look[2])}>
        <span aria-hidden="true">{look[0]} </span>
        {t(`apply.${look[1]}`, { applied: status.agentsApplied, total: status.agentsTotal, seq: revision ? String(revision.seq) : "" })}
      </p>
      {status.agents.length > 0 && (
        <ul className="grid gap-0.5">
          {status.agents.map((a) => (
            <li key={a.agentId}>
              {name(a.agentId)}: {t(`apply.agent.${ApplyState[a.state]}`, { defaultValue: ApplyState[a.state] })}
              {a.errors.length > 0 && ` — ${a.errors.map((e) => e.message).join("; ")}`}
            </li>
          ))}
        </ul>
      )}
      {status.offline.length > 0 && (
        <p className="text-muted-foreground">
          {t("apply.offline", { agents: status.offline.map((o) => (o.lastSeenTime ? `${name(o.agentId)} (${when(o.lastSeenTime)})` : name(o.agentId))).join(", ") })}
        </p>
      )}
    </div>
  );
}
