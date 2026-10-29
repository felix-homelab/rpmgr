// SPDX-License-Identifier: Apache-2.0

import { useQuery } from "@connectrpc/connect-query";
import { Link, useNavigate } from "@tanstack/react-router";
import { Check, Circle, LoaderCircle, X } from "lucide-react";
import { useEffect, useState } from "react";
import { useTranslation } from "react-i18next";
import { Mark } from "@/components/nav";
import { Alert } from "@/components/public-page";
import { AuthService } from "@/gen/rpmgr/v1/auth_pb";
import { ControllerUpdateState, ReleaseService, type ControllerUpdate } from "@/gen/rpmgr/v1/release_pb";

// The steps of the controller's own update, in order (docs/09-web-ui.md, "Settings"): the
// controller stages the files, the root updater verifies them, backs the database up, restarts
// the role, and the new version migrates and becomes ready.
export const updateSteps = ["downloading", "verifying", "backingUp", "handingOver", "migrating", "ready"] as const;
export type StepState = "done" | "current" | "pending" | "failed";

// How often the page asks the controller, and when it gives up (docs/09-web-ui.md); tests shorten
// both.
export const timing = { poll: 2000, giveUp: 15 * 60 * 1000 };

// stepIndex is the step the updater reports, as an index of updateSteps; the staged release waits
// for the updater, so its verification is next.
function stepIndex(u: ControllerUpdate | undefined): number {
  switch (u?.step) {
    case "backing_up": return 2;
    case "handing_over": return 3;
    case "waiting": return 4;
    default: return 1;
  }
}

// stepStates is each step's state: all done once the new version answers; the step reached
// failed when the update failed (reached is the furthest step seen); else the reported one current.
export function stepStates(u: ControllerUpdate | undefined, done: boolean, failed: boolean, reached: number): StepState[] {
  const at = done ? updateSteps.length : failed ? reached : Math.max(stepIndex(u), reached);
  return updateSteps.map((_, i) => (i < at ? "done" : i === at ? (failed ? "failed" : "current") : "pending"));
}

const failures = [ControllerUpdateState.ROLLED_BACK, ControllerUpdateState.ROLLBACK_FAILED, ControllerUpdateState.REFUSED];

// validateUpdatingSearch reads the version the update installs and the one it replaces.
export function validateUpdatingSearch(s: Record<string, unknown>): { to?: string; from?: string } {
  const str = (v: unknown) => (typeof v === "string" && v !== "" ? v : undefined);
  return { to: str(s.to), from: str(s.from) };
}

// Updating follows the update of the controller itself: it asks the controller in the background
// while the controller restarts, shows the steps the root updater reports, goes back to the
// dashboard when the new version answers, and says that the old version still runs when the
// update failed. A session that ended, as after a restore, sends the user to sign in, as any page
// does (D158; docs/09-web-ui.md, "Settings").
export function Updating({ to, from }: { to?: string; from?: string }) {
  const { t } = useTranslation();
  const navigate = useNavigate();
  // The session answers with the version that runs; a controller that is restarting answers
  // nothing, and the query keeps the last answer, so only a success counts.
  const session = useQuery(AuthService.method.getSession, {}, { refetchInterval: timing.poll, retry: false });
  const update = useQuery(ReleaseService.method.getControllerUpdate, {}, { refetchInterval: timing.poll, retry: false });
  const [reached, setReached] = useState(1);
  const [gaveUp, setGaveUp] = useState(false);
  useEffect(() => {
    const timer = setTimeout(() => setGaveUp(true), timing.giveUp);
    return () => clearTimeout(timer);
  }, []);
  const running = session.data?.controllerVersion;
  const u = update.data?.update;
  const ours = u?.version === to ? u : undefined;
  const done = !!to && running === to;
  const failed = !done && !!ours && failures.includes(ours.state);
  useEffect(() => {
    if (done) {
      void navigate({ to: "/", replace: true });
    }
  }, [done, navigate]);
  // The furthest step seen stays, so that the controller's silence while it restarts does not set
  // the steps back.
  if (ours && stepIndex(ours) > reached) {
    setReached(stepIndex(ours));
  }
  const states = stepStates(ours, done, failed, reached);
  const here = from ?? (running !== to ? running : undefined);
  return (
    <main className="mx-auto grid min-h-dvh w-full max-w-2xl content-center gap-6 px-4 py-12">
      <p className="flex items-center gap-2.5 text-lg font-semibold tracking-tight"><Mark />{t("app.name")}</p>
      <section aria-labelledby="updating-title" className="rounded-xl border border-border bg-card p-6 shadow-sm sm:p-8">
        <h1 id="updating-title" className="text-xl font-semibold tracking-tight">{t("updating.title", { version: to ?? "" })}</h1>
        <p className="mt-2 text-sm text-muted-foreground">{t("updating.keepOpen")}</p>
        <ol aria-label={t("updating.steps")} className="mt-6 grid gap-2">
          {updateSteps.map((step, i) => (
            <li key={step} aria-current={states[i] === "current" ? "step" : undefined} className="flex items-center gap-2.5 text-sm">
              <StepIcon state={states[i]!} />
              <span className={states[i] === "pending" ? "text-muted-foreground" : "font-medium"}>{t(`updating.step.${step}`)}</span>
              {states[i] === "current" && <span className="text-muted-foreground">{t(`updating.detail.${step}`)}</span>}
            </li>
          ))}
        </ol>
        <div className="mt-6 grid gap-3">
          {!done && !failed && !gaveUp && session.isError && <Alert tone="info">{t("updating.restarting")}</Alert>}
          {failed && (
            <>
              <Alert>{ours?.state === ControllerUpdateState.ROLLBACK_FAILED
                ? t("updating.rollbackFailed", { reason: ours.reason })
                : t("updating.failed", { version: here ?? "", reason: ours?.reason ?? "" })}</Alert>
              <p><Link to="/" className="text-sm underline">{t("updating.dashboard")}</Link></p>
            </>
          )}
          {!done && !failed && gaveUp && <Alert>{t("updating.gaveUp")}</Alert>}
        </div>
      </section>
    </main>
  );
}

function StepIcon({ state }: { state: StepState }) {
  const cls = "size-4 shrink-0";
  switch (state) {
    case "done": return <Check aria-hidden="true" className={`${cls} text-emerald-600`} />;
    case "failed": return <X aria-hidden="true" className={`${cls} text-destructive`} />;
    case "current": return <LoaderCircle aria-hidden="true" className={`${cls} animate-spin`} />;
    default: return <Circle aria-hidden="true" className={`${cls} text-muted-foreground`} />;
  }
}
