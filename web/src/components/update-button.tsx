// SPDX-License-Identifier: Apache-2.0

import { ConnectError } from "@connectrpc/connect";
import { useMutation, useQuery } from "@connectrpc/connect-query";
import { useQueryClient } from "@tanstack/react-query";
import { ArrowUpCircle } from "lucide-react";
import { useId, useState } from "react";
import { useTranslation } from "react-i18next";
import { Button } from "@/components/ui/button";
import { ReleaseService, RolloutTargetState, type RolloutTarget } from "@/gen/rpmgr/v1/release_pb";
import { RolloutMode } from "@/gen/rpmgr/v1/settings_pb";
import { Reason, reasonOf } from "@/lib/errors";
import { useOrg } from "@/session";
import { useStepUp } from "@/step-up";

// UpdatableAgent is what the Update button needs to know of a connector or gateway.
export interface UpdatableAgent {
  id: string;
  version: string; // empty while it never connected
  online: boolean;
  builtIn: boolean;
  enrolled: boolean;
  overTheAir: boolean; // its last session announced the capability ota
}

const open = [RolloutTargetState.PENDING, RolloutTargetState.OFFERED, RolloutTargetState.STAGED];

// updateBlock is why an agent cannot be updated to the controller's version now, as a key of
// updates.button.why, or "" when it can. queued tells that it has a place in the running easy
// rollout already (D129; docs/09-web-ui.md, "Settings").
export function updateBlock(a: UpdatableAgent, target: string | undefined, active: { mode: RolloutMode; version: string } | undefined,
  queued: RolloutTarget | undefined): string {
  if (a.builtIn) return "builtIn";
  if (!a.enrolled) return "notEnrolled";
  if (!a.version) return "neverConnected";
  if (!a.overTheAir) return "noUpdater";
  if (!target) return "noRelease";
  if (a.version === target) return "upToDate";
  if (active && active.mode !== RolloutMode.EASY) return "staged";
  if (active && active.version !== target) return "otherRelease";
  if (queued && open.includes(queued.state)) return "queued";
  if (queued?.state === RolloutTargetState.SKIPPED) return "skipped";
  // The agent keeps its place, so adding it again would change nothing in this rollout.
  if (queued && [RolloutTargetState.ROLLED_BACK, RolloutTargetState.REFUSED, RolloutTargetState.STALLED].includes(queued.state)) return "failed";
  if (!a.online) return "offline";
  return "";
}

// UpdateButton updates one connector or gateway to the controller's own version: after a step-up
// it joins the running easy rollout of that version, or starts one with this agent alone
// (UpgradeAgents, D129). It is shown to an Instance Admin only, and disabled with its reason
// while the agent cannot be updated; target is the agent's place in the running rollout.
export function UpdateButton({ agent, target }: { agent: UpdatableAgent; target?: RolloutTarget }) {
  const { t } = useTranslation();
  const id = useId();
  const org = useOrg();
  const admin = !!org?.instanceAdmin;
  const releases = useQuery(ReleaseService.method.listReleases, { pageSize: 200 }, { enabled: admin });
  const active = useQuery(ReleaseService.method.listRollouts, { activeOnly: true }, { enabled: admin, refetchInterval: 5000 });
  const upgrade = useMutation(ReleaseService.method.upgradeAgents);
  const stepUp = useStepUp();
  const queryClient = useQueryClient();
  const [said, setSaid] = useState("");
  if (!admin || !releases.data || !active.data) return null;
  // The target is the controller's own release, if the controller has recorded it.
  const own = releases.data.releases.find((r) => r.controllerVersion);
  const running = active.data.rollouts[0];
  const block = updateBlock(agent, own?.version, running && { mode: running.mode, version: running.version }, target);
  async function go() {
    setSaid("");
    try {
      // The agent's place in the queue shows once the lists are read again.
      await stepUp(() => upgrade.mutateAsync({ agentIds: [agent.id] }));
      await queryClient.invalidateQueries();
    } catch (err) {
      if (reasonOf(err) !== Reason.stepUpRequired) setSaid(ConnectError.from(err).rawMessage);
    }
  }
  const why = block && t(`updates.button.why.${block}`, { position: target?.position, reason: target?.reason, version: running?.version });
  return (
    <span className="inline-flex flex-wrap items-center gap-2">
      <Button size="sm" variant="outline" disabled={!!block || upgrade.isPending} aria-describedby={why ? `${id}-why` : undefined}
        onClick={() => void go()}>
        <ArrowUpCircle aria-hidden="true" />{own ? t("updates.button.label", { version: own.version }) : t("updates.button.labelNone")}
      </Button>
      {why && <span id={`${id}-why`} className="text-xs text-muted-foreground">{why}</span>}
      {said && <span role="alert" className="text-xs text-destructive">{said}</span>}
    </span>
  );
}
