// SPDX-License-Identifier: Apache-2.0

import { useTranslation } from "react-i18next";
import { Status, type Look } from "@/components/status";
import { RolloutTargetState, type RolloutTarget } from "@/gen/rpmgr/v1/release_pb";

const looks: Record<RolloutTargetState, [string, Look]> = {
  [RolloutTargetState.UNSPECIFIED]: ["unspecified", "unknown"],
  [RolloutTargetState.PENDING]: ["pending", "unknown"],
  [RolloutTargetState.OFFERED]: ["offered", "pending"],
  [RolloutTargetState.STAGED]: ["staged", "pending"],
  [RolloutTargetState.UPDATED]: ["updated", "ok"],
  [RolloutTargetState.ROLLED_BACK]: ["rolledBack", "alert"],
  [RolloutTargetState.REFUSED]: ["refused", "failed"],
  [RolloutTargetState.SKIPPED]: ["skipped", "off"],
  [RolloutTargetState.STALLED]: ["stalled", "warn"],
};

// UpdateState is where an agent stands in the running rollout, and whether it is below the oldest
// version the controller accepts, with the reason of its last Goodbye (docs/09-web-ui.md,
// "Settings").
export function UpdateState({ target, belowMinimum, goodbyeReason }: {
  target?: RolloutTarget; belowMinimum?: boolean; goodbyeReason?: string;
}) {
  const { t } = useTranslation();
  if (belowMinimum) {
    return <Status look="warn"><span title={goodbyeReason}>{t("updates.belowMinimum")}</span></Status>;
  }
  if (!target) {
    return <>—</>;
  }
  const [state, look] = looks[target.state];
  return (
    <span className="flex flex-wrap items-center gap-2">
      <Status look={look}>{t(`updates.targetStates.${state}`)}</Status>
      {target.reason && <span className="text-xs text-muted-foreground">{target.reason}</span>}
    </span>
  );
}
