// SPDX-License-Identifier: Apache-2.0

import { ConnectError } from "@connectrpc/connect";
import { useMutation, useQuery } from "@connectrpc/connect-query";
import { useNavigate } from "@tanstack/react-router";
import { ArrowUpCircle } from "lucide-react";
import { useId, useState } from "react";
import { useTranslation } from "react-i18next";
import { Button } from "@/components/ui/button";
import { ControllerUpdateState, ReleaseService, type Release } from "@/gen/rpmgr/v1/release_pb";
import { Reason, reasonOf } from "@/lib/errors";
import { useStepUp } from "@/step-up";

// UpdateControllerButton updates the controller, or the all-in-one, to a release newer than the one
// that runs: after a step-up the controller stages it for the root updater of its host and the
// "Updating…" page follows the update (D158; docs/09-web-ui.md, "Settings"). It is disabled with
// its reason while the release is not mirrored, a rollout runs, another update is under way, or
// the host cannot take one, such as on PostgreSQL. The Instance Admin's page only; rollout says
// whether a rollout runs.
export function UpdateControllerButton({ release, rollout }: { release: Release; rollout: boolean }) {
  const { t } = useTranslation();
  const id = useId();
  const navigate = useNavigate();
  const status = useQuery(ReleaseService.method.getControllerUpdate, {}, { refetchInterval: 5000 });
  const update = useMutation(ReleaseService.method.updateController);
  const stepUp = useStepUp();
  const [said, setSaid] = useState("");
  if (!release.newerThanController || !status.data) return null;
  // A controller older than the first that can update itself is updated by hand once.
  if (status.data.byHand) return <span className="text-xs text-muted-foreground">{t("updates.controllerButton.byHand")}</span>;
  const current = status.data.update?.state;
  const blocked = status.data.blocked;
  const why = blocked ? t("updates.controllerButton.why.blocked", { reason: blocked })
    : !release.mirrored ? t("updates.controllerButton.why.notMirrored")
      : rollout ? t("updates.controllerButton.why.rollout")
        : current === ControllerUpdateState.STAGED || current === ControllerUpdateState.UPDATING ? t("updates.controllerButton.why.underWay") : "";
  async function go() {
    setSaid("");
    try {
      const resp = await stepUp(() => update.mutateAsync({ releaseId: release.id }));
      if (resp) {
        void navigate({ to: "/updating", search: { to: release.version, from: status.data?.runningVersion } });
      }
    } catch (err) {
      if (reasonOf(err) !== Reason.stepUpRequired) setSaid(ConnectError.from(err).rawMessage);
    }
  }
  return (
    <span className="inline-flex flex-wrap items-center justify-end gap-2">
      <Button size="sm" variant="outline" disabled={!!why || update.isPending} aria-describedby={why ? `${id}-why` : undefined}
        onClick={() => void go()}>
        <ArrowUpCircle aria-hidden="true" />{t("updates.controllerButton.label", { version: release.version })}
      </Button>
      {why && <span id={`${id}-why`} className="text-xs text-muted-foreground">{why}</span>}
      {said && <span role="alert" className="text-xs text-destructive">{said}</span>}
    </span>
  );
}
