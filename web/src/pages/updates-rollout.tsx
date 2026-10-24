// SPDX-License-Identifier: Apache-2.0

import { ConnectError } from "@connectrpc/connect";
import { useMutation, useQuery } from "@connectrpc/connect-query";
import { useQueryClient } from "@tanstack/react-query";
import { ChevronDown, Circle, CircleCheck, CircleDot, Search } from "lucide-react";
import { useEffect, useId, useMemo, useRef, useState, type FormEvent } from "react";
import { useTranslation } from "react-i18next";
import { Alert } from "@/components/public-page";
import { Status, type Look } from "@/components/status";
import { Button } from "@/components/ui/button";
import { Card } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Table, TD, TH, THead, TR } from "@/components/ui/table";
import { ConnectorService, type Connector } from "@/gen/rpmgr/v1/connector_pb";
import { GatewayService, type Gateway } from "@/gen/rpmgr/v1/gateway_pb";
import {
  AgentKind, ReleaseService, RolloutStage, RolloutState, RolloutTargetState,
  type Release, type Rollout, type RolloutTarget,
} from "@/gen/rpmgr/v1/release_pb";
import { RolloutMode } from "@/gen/rpmgr/v1/settings_pb";
import { Reason, reasonOf } from "@/lib/errors";
import { EasyRolloutCard } from "@/pages/updates-easy";
import { useOrg } from "@/session";
import { useStepUp } from "@/step-up";

// The default path of a rollout: the test agents, then this share of the other agents, then every
// agent (docs/04-security.md, "Over-the-air updates").
const firstPercent = 25;
// The shares offered beside it; the API takes any percentage from 1 to 99 above the current one.
const percents = [10, 25, 50, 75];
// The most test agents a rollout takes (CreateRolloutRequest).
const maxTestAgents = 50;

// rolloutStates are a rollout's state as its key in the texts and its look.
export const rolloutStates: Record<RolloutState, [string, Look]> = {
  [RolloutState.UNSPECIFIED]: ["unspecified", "unknown"],
  [RolloutState.RUNNING]: ["running", "pending"],
  [RolloutState.PAUSED]: ["paused", "warn"],
  [RolloutState.COMPLETED]: ["completed", "ok"],
  [RolloutState.CANCELLED]: ["cancelled", "off"],
};

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

type Agent = { id: string; name: string; kind: AgentKind; version: string; online: boolean };

// rolloutAgents are the agents a rollout updates, as CreateRollout chooses them: connectors and
// enrolled gateways that are neither built in nor decommissioned; left counts the others.
function rolloutAgents(connectors: Connector[], gateways: Gateway[]) {
  const agents: Agent[] = [];
  let left = 0;
  for (const c of connectors) {
    if (c.builtIn || c.decommissionTime) {
      left++;
      continue;
    }
    agents.push({ id: c.id, name: c.name, kind: AgentKind.CONNECTOR, version: c.session?.version ?? "", online: !!c.session?.connected });
  }
  for (const g of gateways) {
    if (g.builtIn || g.decommissionTime || !g.status?.enrolled) {
      left++;
      continue;
    }
    agents.push({ id: g.id, name: g.name, kind: AgentKind.GATEWAY, version: g.status.version, online: g.status.connected });
  }
  agents.sort((a, b) => a.name.localeCompare(b.name));
  return { agents, left };
}

// suggest pre-ticks the first online connector and the first online gateway that do not run the
// release yet.
function suggest(agents: Agent[], version: string): Set<string> {
  const first = (kind: AgentKind) => agents.find((a) => a.kind === kind && a.online && a.version !== version)?.id;
  return new Set([first(AgentKind.CONNECTOR), first(AgentKind.GATEWAY)].filter((id): id is string => !!id));
}

// RolloutDialog starts a rollout in two steps: the test agents, from the user's org, which update
// first; then the plan, which starts after a step-up.
export function RolloutDialog({ release, onClose }: { release: Release; onClose: () => void }) {
  const { t } = useTranslation();
  const dialog = useRef<HTMLDialogElement>(null);
  const id = useId();
  const org = useOrg();
  const stepUp = useStepUp();
  const create = useMutation(ReleaseService.method.createRollout);
  const queryClient = useQueryClient();
  const connectors = useQuery(ConnectorService.method.listConnectors, { orgId: org?.orgId ?? "", pageSize: 200 }, { enabled: !!org });
  const gateways = useQuery(GatewayService.method.listGateways, { orgId: org?.orgId ?? "", pageSize: 200 }, { enabled: !!org });
  const [review, setReview] = useState(false);
  const [chosen, setChosen] = useState<Set<string>>();
  const [q, setQ] = useState("");
  const [error, setError] = useState("");
  useEffect(() => dialog.current?.showModal(), []);
  const loaded = !!connectors.data && !!gateways.data;
  const { agents, left } = useMemo(() => rolloutAgents(connectors.data?.connectors ?? [], gateways.data?.gateways ?? []),
    [connectors.data, gateways.data]);
  // Until the user changes it, the choice is the suggestion.
  const picked = chosen ?? (loaded ? suggest(agents, release.version) : new Set<string>());
  const tests = agents.filter((a) => picked.has(a.id));
  const already = agents.filter((a) => a.version === release.version).length;
  const shown = agents.filter((a) => a.name.toLowerCase().includes(q.trim().toLowerCase()));
  const blocked = picked.size === 0 ? t("updates.chooseTest") : picked.size > maxTestAgents ? t("updates.tooManyTest", { max: maxTestAgents }) : "";
  const listError = connectors.error ?? gateways.error;
  function toggle(agent: string, on: boolean) {
    const next = new Set(picked);
    if (on) next.add(agent); else next.delete(agent);
    setChosen(next);
  }
  async function start(e: FormEvent) {
    e.preventDefault();
    setError("");
    try {
      await stepUp(() => create.mutateAsync({ releaseId: release.id, canaryAgentIds: tests.map((a) => a.id) }));
      await queryClient.invalidateQueries();
      onClose();
    } catch (err) {
      if (reasonOf(err) !== Reason.stepUpRequired) {
        setError(ConnectError.from(err).rawMessage);
      }
    }
  }
  const others = agents.length - tests.length;
  const first = Math.round((others * firstPercent) / 100);
  return (
    <dialog ref={dialog} aria-labelledby={`${id}-title`} aria-describedby={`${id}-step`} onCancel={onClose}
      className="m-auto max-h-[calc(100dvh-2rem)] w-[calc(100%-2rem)] max-w-2xl rounded-xl border border-border bg-card p-6 shadow-2xl">
      <h2 id={`${id}-title`} className="text-lg font-semibold">{t("updates.rolloutTitle", { version: release.version })}</h2>
      <p id={`${id}-step`} className="text-sm text-muted-foreground">
        {review ? t("updates.stepReview") : t("updates.stepAgents")}
      </p>
      {!review ? (
        <form onSubmit={(e) => { e.preventDefault(); if (!blocked) setReview(true); }} className="mt-5 grid gap-4" noValidate>
          <p className="text-sm">{t("updates.testHelp")}</p>
          <label className="grid gap-1.5 text-xs font-medium text-muted-foreground">
            {t("updates.searchAgents")}
            <span className="relative">
              <Search aria-hidden="true" className="pointer-events-none absolute top-1/2 left-3 size-4 -translate-y-1/2" />
              <Input type="search" className="pl-9 text-foreground" value={q} onChange={(e) => setQ(e.target.value)} />
            </span>
          </label>
          <fieldset className="grid max-h-72 gap-3 overflow-y-auto rounded-lg border border-border p-3">
            <legend className="sr-only">{t("updates.testAgents")}</legend>
            {!loaded && !listError && <p className="text-sm text-muted-foreground">{t("updates.loading")}</p>}
            {[AgentKind.CONNECTOR, AgentKind.GATEWAY].map((kind) => {
              const list = shown.filter((a) => a.kind === kind);
              const name = kind === AgentKind.GATEWAY ? "gateway" : "connector";
              return list.length > 0 && (
                <div key={kind} role="group" aria-labelledby={`${id}-${name}`} className="grid gap-1">
                  <h3 id={`${id}-${name}`} className="text-xs font-semibold tracking-wide text-muted-foreground uppercase">{t(`updates.groups.${name}`)}</h3>
                  {list.map((a) => (
                    <label key={a.id} className="flex flex-wrap items-center gap-x-3 gap-y-1 py-1 text-sm">
                      <input type="checkbox" className="size-4 accent-primary" checked={picked.has(a.id)} disabled={a.version === release.version}
                        onChange={(e) => toggle(a.id, e.target.checked)} />
                      <span className="font-medium">{a.name}</span>
                      <span className="text-muted-foreground">{a.version || t("updates.neverConnected")}</span>
                      <Status look={a.online ? "ok" : "off"}>{a.online ? t("updates.online") : t("updates.offline")}</Status>
                      {a.version === release.version && <span className="text-xs text-muted-foreground">{t("updates.alreadyRuns", { version: release.version })}</span>}
                    </label>
                  ))}
                </div>
              );
            })}
            {loaded && shown.length === 0 && <p className="text-sm text-muted-foreground">{agents.length ? t("updates.noMatch") : t("updates.noAgents")}</p>}
          </fieldset>
          {loaded && agents.length > 0 && !agents.some((a) => a.online) && <p className="text-sm text-warn">{t("updates.noOnline")}</p>}
          {tests.some((a) => !a.online) && <p className="text-sm text-warn">{t("updates.offlineChosen")}</p>}
          {listError && <Alert>{ConnectError.from(listError).rawMessage}</Alert>}
          {/* The choice in words, since the list may scroll a ticked agent out of view. */}
          {tests.length > 0 && <p className="text-sm">{t("updates.chosen", { count: tests.length, names: tests.map((a) => a.name).join(", ") })}</p>}
          {loaded && (
            <p className="text-sm text-muted-foreground">
              {[t("updates.inRollout", { count: agents.length }),
                already > 0 && t("updates.alreadyCount", { count: already, version: release.version }),
                left > 0 && t("updates.notIncluded", { count: left })].filter(Boolean).join(" · ")}
            </p>
          )}
          <div className="flex flex-wrap items-center justify-end gap-2">
            {loaded && blocked && <p id={`${id}-why`} className="mr-auto text-sm text-muted-foreground">{blocked}</p>}
            <Button type="button" variant="outline" onClick={onClose}>{t("updates.cancel")}</Button>
            <Button type="submit" disabled={!loaded || !!blocked} aria-describedby={blocked ? `${id}-why` : undefined}>{t("updates.next")}</Button>
          </div>
        </form>
      ) : (
        <form onSubmit={start} className="mt-5 grid gap-4" noValidate>
          <ol className="grid gap-3 text-sm" aria-label={t("updates.plan")}>
            <PlanStep n={1} title={t("updates.stageTest")}>{t("updates.planTest", { count: tests.length, names: tests.map((a) => a.name).join(", ") })}</PlanStep>
            <PlanStep n={2} title={`${firstPercent} %`}>{t("updates.planPercent", { count: first })}</PlanStep>
            <PlanStep n={3} title={t("updates.allAgents")}>{t("updates.planAll", { count: others - first })}</PlanStep>
          </ol>
          <p className="text-sm text-muted-foreground">{t("updates.planHelp")}</p>
          {error && <Alert>{error}</Alert>}
          <div className="flex justify-end gap-2">
            <Button type="button" variant="outline" onClick={() => setReview(false)}>{t("updates.back")}</Button>
            <Button type="submit" disabled={create.isPending}>{t("updates.start")}</Button>
          </div>
        </form>
      )}
    </dialog>
  );
}

function PlanStep({ n, title, children }: { n: number; title: string; children: string }) {
  return (
    <li className="flex gap-3">
      <span aria-hidden="true" className="grid size-6 shrink-0 place-items-center rounded-full bg-accent text-xs font-semibold text-accent-foreground">{n}</span>
      <span className="grid">
        <span className="font-medium">{title}</span>
        <span className="text-muted-foreground">{children}</span>
      </span>
    </li>
  );
}

// Next is the stage a rollout continues to: a percentage or every agent.
type Next = number | "all";

// inStage tells whether the rollout's current stage takes a target: the test agents always, then
// the agents whose bucket is below the percentage, then every agent (RolloutStage).
function inStage(x: RolloutTarget, r: Rollout) {
  return x.canary || r.stage === RolloutStage.ALL || (r.stage === RolloutStage.PERCENTAGE && x.bucket < r.percentage);
}

// more counts the agents a stage adds to the current one.
function more(targets: RolloutTarget[], r: Rollout, next: Next) {
  return targets.filter((x) => !inStage(x, r) && (next === "all" || x.bucket < next)).length;
}

// defaultNext is the next stage of the default path.
function defaultNext(r: Rollout): Next {
  return r.stage === RolloutStage.CANARY || r.percentage < firstPercent ? firstPercent : "all";
}

// groupTargets splits a rollout's agents: problems first, then the ones the current stage is
// updating, the ones waiting for a later stage, the updated and the skipped.
function groupTargets(targets: RolloutTarget[], r: Rollout) {
  const groups = { problems: [] as RolloutTarget[], updating: [] as RolloutTarget[], waiting: [] as RolloutTarget[],
    done: [] as RolloutTarget[], skipped: [] as RolloutTarget[] };
  for (const x of targets) {
    switch (x.state) {
      case RolloutTargetState.ROLLED_BACK:
      case RolloutTargetState.REFUSED:
      case RolloutTargetState.STALLED:
        groups.problems.push(x);
        break;
      case RolloutTargetState.UPDATED:
        groups.done.push(x);
        break;
      case RolloutTargetState.SKIPPED:
        groups.skipped.push(x);
        break;
      default:
        (inStage(x, r) ? groups.updating : groups.waiting).push(x);
    }
  }
  return groups;
}

// ActiveRollout follows the running or paused rollout: where it stands on its path, how many agents
// updated, what to do next, and each agent by group. It refreshes while the page is open, because
// the rollout job moves it.
export function ActiveRollout() {
  const active = useQuery(ReleaseService.method.listRollouts, { activeOnly: true }, { refetchInterval: 5000 });
  const rollout = active.data?.rollouts[0];
  if (!rollout) return null;
  return rollout.mode === RolloutMode.EASY ? <EasyRolloutCard rollout={rollout} /> : <RolloutCard rollout={rollout} />;
}

function RolloutCard({ rollout }: { rollout: Rollout }) {
  const { t } = useTranslation();
  const list = useQuery(ReleaseService.method.listRolloutTargets, { rolloutId: rollout.id, pageSize: 500 }, { refetchInterval: 5000 });
  const targets = list.data?.rolloutTargets ?? [];
  // Only a complete list tells that the stage is done; with more than one page the server decides.
  const complete = !!list.data && !list.data.nextPageToken;
  const groups = groupTargets(targets, rollout);
  const [state, look] = rolloutStates[rollout.state];
  return (
    <Card title={t("updates.rollout")} description={t("updates.rolloutOf", { version: rollout.version })}
      actions={<Status look={look}>{t(`updates.states.${state}`)}</Status>}>
      <Stages rollout={rollout} targets={targets} />
      <Progress rollout={rollout} />
      {rollout.pauseReason && <p role="status" className="text-sm text-warn">{t("updates.paused", { reason: rollout.pauseReason })}</p>}
      <RolloutActions rollout={rollout} targets={targets} updating={complete ? groups.updating.length : 0} />
      <TargetGroups groups={groups} />
      {list.data?.nextPageToken && <p className="text-sm text-muted-foreground">{t("updates.truncated")}</p>}
    </Card>
  );
}

// Stages draws the rollout's path: the stages done, the current one and the ones to come, each with
// its agents.
function Stages({ rollout, targets }: { rollout: Rollout; targets: RolloutTarget[] }) {
  const { t } = useTranslation();
  const updated = (xs: RolloutTarget[]) => xs.filter((x) => x.state === RolloutTargetState.UPDATED).length;
  const tests = targets.filter((x) => x.canary);
  const current = targets.filter((x) => inStage(x, rollout));
  const stages: { key: string; label: string; state: "done" | "current" | "next"; note: string }[] = [{
    key: "test", label: t("updates.stageTest"), state: rollout.stage === RolloutStage.CANARY ? "current" : "done",
    note: t("updates.stageUpdated", { updated: updated(tests), total: tests.length }),
  }];
  if (rollout.stage === RolloutStage.PERCENTAGE) {
    stages.push({ key: "percent", label: `${rollout.percentage} %`, state: "current",
      note: t("updates.stageUpdated", { updated: updated(current), total: current.length }) });
  }
  const next = defaultNext(rollout);
  if (rollout.stage !== RolloutStage.ALL && next !== "all") {
    stages.push({ key: "next", label: `${next} %`, state: "next", note: t("updates.stageWaiting", { count: more(targets, rollout, next) }) });
  }
  stages.push(rollout.stage === RolloutStage.ALL
    ? { key: "all", label: t("updates.allAgents"), state: "current", note: t("updates.stageUpdated", { updated: updated(current), total: current.length }) }
    : { key: "all", label: t("updates.allAgents"), state: "next", note: t("updates.stageWaiting", { count: more(targets, rollout, "all") }) });
  return (
    // A row on wider screens; on a phone a column, without the lines between the stages.
    <ol className="grid gap-2 sm:flex sm:flex-wrap sm:items-start sm:gap-x-2 sm:gap-y-3" aria-label={t("updates.stages")}>
      {stages.map((s, i) => {
        const Icon = s.state === "done" ? CircleCheck : s.state === "current" ? CircleDot : Circle;
        return (
          <li key={s.key} aria-current={s.state === "current" ? "step" : undefined} className="flex items-start gap-2">
            {i > 0 && <span aria-hidden="true" className="mt-2.5 hidden h-px w-10 bg-border sm:block" />}
            <Icon aria-hidden="true" className={s.state === "done" ? "mt-0.5 size-4 text-ok" : s.state === "current" ? "mt-0.5 size-4 text-primary" : "mt-0.5 size-4 text-muted-foreground"} />
            <span className="grid">
              <span className={s.state === "next" ? "text-sm text-muted-foreground" : "text-sm font-medium"}>
                {s.label}<span className="sr-only">{`, ${t(`updates.stageStates.${s.state}`)}`}</span>
              </span>
              <span className="text-xs text-muted-foreground">{s.note}</span>
            </span>
          </li>
        );
      })}
    </ol>
  );
}

// Progress is the share of the rollout's agents that updated, of those it did not skip.
export function Progress({ rollout }: { rollout: Rollout }) {
  const { t } = useTranslation();
  const c = rollout.counts;
  const all = c ? c.pending + c.offered + c.staged + c.updated + c.rolledBack + c.refused + c.skipped + c.stalled : 0;
  const skipped = c?.skipped ?? 0;
  const updated = c?.updated ?? 0;
  const of = all - skipped;
  const text = t("updates.progress", { updated, total: of });
  return (
    <div className="grid gap-1.5">
      <div role="progressbar" aria-label={t("updates.progressLabel")} aria-valuemin={0} aria-valuemax={of} aria-valuenow={updated}
        aria-valuetext={text} className="h-2 overflow-hidden rounded-full bg-muted">
        <div className="h-full rounded-full bg-primary transition-[width]" style={{ width: `${of > 0 ? (updated / of) * 100 : 0}%` }} />
      </div>
      <p aria-live="polite" className="text-sm text-muted-foreground">
        {skipped > 0 ? `${text} · ${t("updates.progressSkipped", { count: skipped })}` : text}
      </p>
    </div>
  );
}

// RolloutActions continues the rollout under the etag the page read, and pauses, resumes or cancels
// it (RolloutControls); a stale etag reloads it. Continue is offered while the rollout runs below
// "all agents", as the API allows, and once the agents of the current stage are done (updated,
// skipped or failed).
function RolloutActions({ rollout, targets, updating }: { rollout: Rollout; targets: RolloutTarget[]; updating: number }) {
  const { t } = useTranslation();
  const id = useId();
  const stepUp = useStepUp();
  const queryClient = useQueryClient();
  const advance = useMutation(ReleaseService.method.advanceRollout);
  const [choice, setChoice] = useState<Next | "other">();
  const [other, setOther] = useState("");
  const [choosing, setChoosing] = useState(false);
  const [error, setError] = useState("");
  const run = (f: () => Promise<unknown>) => runChange(f, queryClient, setError);
  const running = rollout.state === RolloutState.RUNNING;
  const options: Next[] = [...percents.filter((p) => p > rollout.percentage), "all"];
  // A choice the rollout has passed meanwhile falls back to the default path.
  const pick = choice === "other" || (choice !== undefined && options.includes(choice)) ? choice : defaultNext(rollout);
  const otherValid = /^\d+$/.test(other) && Number(other) > rollout.percentage && Number(other) <= 99;
  const next: Next | undefined = pick === "other" ? (otherValid ? Number(other) : undefined) : pick;
  const label = next === undefined ? t("updates.continue")
    : t("updates.continueTo", { stage: next === "all" ? t("updates.allAgentsLower") : `${next} %`, count: more(targets, rollout, next) });
  async function go() {
    if (next === undefined) return;
    const done = await run(() => stepUp(() => advance.mutateAsync(next === "all"
      ? { rolloutId: rollout.id, etag: rollout.etag, next: { case: "all" as const, value: true } }
      : { rolloutId: rollout.id, etag: rollout.etag, next: { case: "percentage" as const, value: next } })));
    if (done) {
      setChoice(undefined);
      setOther("");
      setChoosing(false);
    }
  }
  return (
    <div className="grid gap-3">
      {running && rollout.stage !== RolloutStage.ALL && (
        <div className="grid gap-2">
          <div className="flex flex-wrap items-center gap-2">
            <Button disabled={next === undefined || updating > 0 || advance.isPending} aria-describedby={updating > 0 ? `${id}-wait` : undefined}
              onClick={() => void go()}>{label}</Button>
            <Button variant="outline" aria-expanded={choosing} aria-controls={`${id}-choices`} onClick={() => setChoosing(!choosing)}>
              {t("updates.otherStage")}<ChevronDown aria-hidden="true" className={choosing ? "rotate-180" : undefined} />
            </Button>
          </div>
          {updating > 0 && <p id={`${id}-wait`} className="text-sm text-muted-foreground">{t("updates.waitStage", { count: updating })}</p>}
          {choosing && (
            <fieldset id={`${id}-choices`} className="grid gap-2 rounded-lg border border-border p-3">
              <legend className="px-1 text-sm font-medium">{t("updates.nextStage")}</legend>
              {options.map((o) => (
                <label key={o} className="flex items-center gap-2 text-sm">
                  <input type="radio" name={`${id}-next`} className="size-4 accent-primary" checked={pick === o} onChange={() => setChoice(o)} />
                  {o === "all" ? t("updates.allAgents") : `${o} %`}
                </label>
              ))}
              <label className="flex items-center gap-2 text-sm">
                <input type="radio" name={`${id}-next`} className="size-4 accent-primary" checked={pick === "other"} onChange={() => setChoice("other")} />
                {t("updates.otherPercent")}
              </label>
              {pick === "other" && (
                <div className="grid gap-1 pl-6">
                  <Input className="w-24" inputMode="numeric" aria-label={t("updates.percent")} value={other} aria-invalid={other !== "" && !otherValid}
                    aria-describedby={`${id}-range`} onChange={(e) => setOther(e.target.value.trim())} />
                  <p id={`${id}-range`} className={other !== "" && !otherValid ? "text-sm text-destructive" : "text-sm text-muted-foreground"}>
                    {t("updates.percentRange", { min: rollout.percentage + 1 })}
                  </p>
                </div>
              )}
            </fieldset>
          )}
        </div>
      )}
      {running && rollout.stage === RolloutStage.ALL && <p className="text-sm text-muted-foreground">{t("updates.allNow")}</p>}
      {error && <Alert>{error}</Alert>}
      <RolloutControls rollout={rollout} />
    </div>
  );
}

// runChange runs a change of a rollout and reloads the page's data; an error other than a step-up
// the user declined is shown.
async function runChange(f: () => Promise<unknown>, queryClient: ReturnType<typeof useQueryClient>, setError: (e: string) => void) {
  setError("");
  try {
    await f();
    await queryClient.invalidateQueries();
    return true;
  } catch (err) {
    if (reasonOf(err) !== Reason.stepUpRequired) {
      setError(ConnectError.from(err).rawMessage);
    }
    return false;
  }
}

// RolloutControls pauses a running rollout, resumes a paused one and cancels either, after asking,
// under the etag the page read; all but a pause after a step-up. Staged and easy rollouts share it.
export function RolloutControls({ rollout }: { rollout: Rollout }) {
  const { t } = useTranslation();
  const stepUp = useStepUp();
  const queryClient = useQueryClient();
  const pause = useMutation(ReleaseService.method.pauseRollout);
  const resume = useMutation(ReleaseService.method.resumeRollout);
  const cancel = useMutation(ReleaseService.method.cancelRollout);
  const [asking, setAsking] = useState(false);
  const [error, setError] = useState("");
  const run = (f: () => Promise<unknown>) => runChange(f, queryClient, setError);
  const running = rollout.state === RolloutState.RUNNING;
  return (
    <div className="grid gap-3">
      <div className="flex flex-wrap items-center gap-2">
        {running && (
          <Button size="sm" variant="outline" disabled={pause.isPending}
            onClick={() => void run(() => pause.mutateAsync({ rolloutId: rollout.id, etag: rollout.etag }))}>{t("updates.pause")}</Button>
        )}
        {rollout.state === RolloutState.PAUSED && (
          <Button size="sm" disabled={resume.isPending}
            onClick={() => void run(() => stepUp(() => resume.mutateAsync({ rolloutId: rollout.id, etag: rollout.etag })))}>{t("updates.resume")}</Button>
        )}
        {asking ? (
          <>
            <Button size="sm" variant="destructive" disabled={cancel.isPending}
              onClick={() => void run(() => stepUp(() => cancel.mutateAsync({ rolloutId: rollout.id, etag: rollout.etag })))}>{t("updates.cancelIt")}</Button>
            <Button size="sm" variant="outline" onClick={() => setAsking(false)}>{t("updates.keep")}</Button>
          </>
        ) : (
          <Button size="sm" variant="outline" onClick={() => setAsking(true)}>{t("updates.cancel")}</Button>
        )}
      </div>
      {asking && <p role="alert" className="text-sm text-destructive">{t("updates.cancelAsk")}</p>}
      {error && <Alert>{error}</Alert>}
    </div>
  );
}

// TargetGroups lists the rollout's agents by group, problems first; the long groups start closed.
function TargetGroups({ groups }: { groups: ReturnType<typeof groupTargets> }) {
  const { t } = useTranslation();
  const order = ["problems", "updating", "waiting", "done", "skipped"] as const;
  return (
    // Each group reaches the card's edges, as its table does (Table, framed={false}).
    <div className="grid min-w-0">
      {order.map((key) => groups[key].length > 0 && (
        <details key={key} open={key === "problems" || key === "updating"} className="-mx-5 min-w-0 border-t border-border px-5">
          <summary className="cursor-pointer py-2.5 text-sm font-medium">
            {t(`updates.targetGroups.${key}`)} <span className="text-muted-foreground">({groups[key].length})</span>
          </summary>
          <Table framed={false}>
            <THead>
              <tr>{["agent", "kind", "state", "reason"].map((c) => <TH key={c}>{t(`updates.targetColumns.${c}`)}</TH>)}</tr>
            </THead>
            <tbody>
              {groups[key].map((x) => <TargetRow key={x.id} target={x} waiting={key === "waiting"} />)}
            </tbody>
          </Table>
        </details>
      ))}
    </div>
  );
}

function TargetRow({ target, waiting }: { target: RolloutTarget; waiting: boolean }) {
  const { t } = useTranslation();
  const [state, look] = looks[target.state];
  return (
    <TR>
      <TD className="font-medium whitespace-nowrap">{target.agentName || target.agentId}</TD>
      <TD className="whitespace-nowrap">{target.agentKind === AgentKind.GATEWAY ? t("updates.kinds.gateway") : t("updates.kinds.connector")}</TD>
      <TD className="whitespace-nowrap">{waiting ? <Status look="unknown">{t("updates.waits")}</Status> : <Status look={look}>{t(`updates.targetStates.${state}`)}</Status>}</TD>
      <TD className="min-w-48 text-muted-foreground">{target.reason || "—"}</TD>
    </TR>
  );
}
