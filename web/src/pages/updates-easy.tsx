// SPDX-License-Identifier: Apache-2.0

import { ConnectError } from "@connectrpc/connect";
import { useMutation, useQuery } from "@connectrpc/connect-query";
import { useQueryClient } from "@tanstack/react-query";
import { ArrowDown, ArrowUp, Search } from "lucide-react";
import { useEffect, useId, useMemo, useRef, useState, type FormEvent } from "react";
import { useTranslation } from "react-i18next";
import { Alert } from "@/components/public-page";
import { Status } from "@/components/status";
import { UpdateState } from "@/components/update-state";
import { Button } from "@/components/ui/button";
import { Card } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { ConnectorService, type Connector } from "@/gen/rpmgr/v1/connector_pb";
import { GatewayService, type Gateway } from "@/gen/rpmgr/v1/gateway_pb";
import {
  AgentKind, ReleaseService, RolloutState, RolloutTargetState, type Release, type Rollout, type RolloutTarget,
} from "@/gen/rpmgr/v1/release_pb";
import { RolloutMode } from "@/gen/rpmgr/v1/settings_pb";
import { Reason, reasonOf } from "@/lib/errors";
import { Progress, RolloutControls, rolloutStates } from "@/pages/updates-rollout";
import { useOrg } from "@/session";
import { useStepUp } from "@/step-up";

// The most agents an easy rollout takes at its start (CreateRolloutRequest).
const maxQueue = 1000;

// Candidate is an agent of the org the start dialog lists: why it cannot take the release, if it
// cannot.
export type Candidate = { id: string; name: string; kind: AgentKind; version: string; online: boolean; why?: string };

// candidates are the org's connectors and enrolled gateways in service, the connectors first and
// then the gateways, each by name, which is the order of a new queue (D129). An agent that is
// built in, has no over-the-air updater or runs the release already says why it cannot take it.
export function candidates(connectors: Connector[], gateways: Gateway[], version: string): Candidate[] {
  const why = (builtIn: boolean, enrolled: boolean, ota: boolean, v: string) =>
    builtIn ? "builtIn" : !enrolled ? "notEnrolled" : !v ? "neverConnected" : !ota ? "noUpdater" : v === version ? "alreadyRuns" : undefined;
  const byName = (a: Candidate, b: Candidate) => a.name.localeCompare(b.name);
  const cons = connectors.filter((c) => !c.decommissionTime).map((c): Candidate => ({
    id: c.id, name: c.name, kind: AgentKind.CONNECTOR, version: c.session?.version ?? "", online: !!c.session?.connected,
    why: why(c.builtIn, true, !!c.session?.overTheAir, c.session?.version ?? ""),
  })).sort(byName);
  const gws = gateways.filter((g) => !g.decommissionTime).map((g): Candidate => ({
    id: g.id, name: g.name, kind: AgentKind.GATEWAY, version: g.status?.version ?? "", online: !!g.status?.connected,
    why: why(g.builtIn, !!g.status?.enrolled, !!g.status?.overTheAir, g.status?.version ?? ""),
  })).sort(byName);
  return [...cons, ...gws];
}

// insert puts an agent into a queue at the place the default order gives it among the agents
// queued already, so that a queue made by ticking follows that order until the user moves one.
function insert(queue: string[], id: string, rank: Map<string, number>) {
  const at = queue.findIndex((q) => (rank.get(q) ?? 0) > (rank.get(id) ?? 0));
  return at < 0 ? [...queue, id] : [...queue.slice(0, at), id, ...queue.slice(at)];
}

// EasyRolloutDialog starts an easy rollout: the agents the user ticks get the release one after
// another, in the order shown beside the list, which Move up and Move down change; Start starts it
// after a step-up (docs/09-web-ui.md, "Settings"; D129).
export function EasyRolloutDialog({ release, onClose }: { release: Release; onClose: () => void }) {
  const { t } = useTranslation();
  const dialog = useRef<HTMLDialogElement>(null);
  const id = useId();
  const org = useOrg();
  const stepUp = useStepUp();
  const create = useMutation(ReleaseService.method.createRollout);
  const queryClient = useQueryClient();
  const connectors = useQuery(ConnectorService.method.listConnectors, { orgId: org?.orgId ?? "", pageSize: 200 }, { enabled: !!org });
  const gateways = useQuery(GatewayService.method.listGateways, { orgId: org?.orgId ?? "", pageSize: 200 }, { enabled: !!org });
  const [queue, setQueue] = useState<string[]>([]);
  const [q, setQ] = useState("");
  const [error, setError] = useState("");
  useEffect(() => dialog.current?.showModal(), []);
  const loaded = !!connectors.data && !!gateways.data;
  const all = useMemo(() => candidates(connectors.data?.connectors ?? [], gateways.data?.gateways ?? [], release.version),
    [connectors.data, gateways.data, release.version]);
  const eligible = all.filter((a) => !a.why);
  const others = all.filter((a) => a.why);
  const rank = useMemo(() => new Map(all.map((a, i) => [a.id, i])), [all]);
  const byId = useMemo(() => new Map(all.map((a) => [a.id, a])), [all]);
  const shown = eligible.filter((a) => a.name.toLowerCase().includes(q.trim().toLowerCase()));
  const listError = connectors.error ?? gateways.error;
  const blocked = queue.length === 0 ? t("updates.easy.chooseOne") : queue.length > maxQueue ? t("updates.easy.tooMany", { max: maxQueue }) : "";
  function toggle(agent: string, on: boolean) {
    setQueue(on ? insert(queue, agent, rank) : queue.filter((x) => x !== agent));
  }
  function selectAll() {
    let next = queue;
    for (const a of shown) if (!next.includes(a.id)) next = insert(next, a.id, rank);
    setQueue(next);
  }
  function move(i: number, by: -1 | 1) {
    const next = [...queue];
    next.splice(i + by, 0, ...next.splice(i, 1));
    setQueue(next);
  }
  async function start(e: FormEvent) {
    e.preventDefault();
    if (blocked) return;
    setError("");
    try {
      await stepUp(() => create.mutateAsync({ releaseId: release.id, mode: RolloutMode.EASY, agentIds: queue }));
      await queryClient.invalidateQueries();
      onClose();
    } catch (err) {
      if (reasonOf(err) !== Reason.stepUpRequired) {
        setError(ConnectError.from(err).rawMessage);
      }
    }
  }
  return (
    <dialog ref={dialog} aria-labelledby={`${id}-title`} aria-describedby={`${id}-help`} onCancel={onClose}
      className="m-auto max-h-[calc(100dvh-2rem)] w-[calc(100%-2rem)] max-w-3xl rounded-xl border border-border bg-card p-6 shadow-2xl">
      <h2 id={`${id}-title`} className="text-lg font-semibold">{t("updates.rolloutTitle", { version: release.version })}</h2>
      <p id={`${id}-help`} className="text-sm text-muted-foreground">{t("updates.easy.help")}</p>
      <form onSubmit={start} className="mt-5 grid gap-4" noValidate>
        <div className="grid gap-4 sm:grid-cols-2">
          <div className="grid content-start gap-3">
            <div className="flex flex-wrap items-end gap-2">
              <label className="grid flex-1 gap-1.5 text-xs font-medium text-muted-foreground">
                {t("updates.searchAgents")}
                <span className="relative">
                  <Search aria-hidden="true" className="pointer-events-none absolute top-1/2 left-3 size-4 -translate-y-1/2" />
                  <Input type="search" className="pl-9 text-foreground" value={q} onChange={(e) => setQ(e.target.value)} />
                </span>
              </label>
              <Button type="button" variant="outline" disabled={shown.length === 0} onClick={selectAll}>{t("updates.easy.selectAll")}</Button>
            </div>
            <fieldset aria-label={t("updates.easy.agents")} className="grid max-h-72 gap-3 overflow-y-auto rounded-lg border border-border p-3">
              {!loaded && !listError && <p className="text-sm text-muted-foreground">{t("updates.loading")}</p>}
              {[AgentKind.CONNECTOR, AgentKind.GATEWAY].map((kind) => {
                const list = shown.filter((a) => a.kind === kind);
                const name = kind === AgentKind.GATEWAY ? "gateway" : "connector";
                return list.length > 0 && (
                  <div key={kind} role="group" aria-labelledby={`${id}-${name}`} className="grid gap-1">
                    <h3 id={`${id}-${name}`} className="text-xs font-semibold tracking-wide text-muted-foreground uppercase">{t(`updates.groups.${name}`)}</h3>
                    {list.map((a) => (
                      <label key={a.id} className="flex flex-wrap items-center gap-x-3 gap-y-1 py-1 text-sm">
                        <input type="checkbox" className="size-4 accent-primary" checked={queue.includes(a.id)}
                          onChange={(e) => toggle(a.id, e.target.checked)} />
                        <span className="font-medium">{a.name}</span>
                        <span className="text-muted-foreground">{a.version}</span>
                        <Status look={a.online ? "ok" : "off"}>{a.online ? t("updates.online") : t("updates.offline")}</Status>
                      </label>
                    ))}
                  </div>
                );
              })}
              {loaded && shown.length === 0 && <p className="text-sm text-muted-foreground">{eligible.length ? t("updates.noMatch") : t("updates.easy.noEligible")}</p>}
            </fieldset>
            {others.length > 0 && (
              <div className="grid gap-1 text-sm">
                <h3 className="text-xs font-semibold tracking-wide text-muted-foreground uppercase">{t("updates.easy.cannot")}</h3>
                <ul className="grid gap-0.5 text-muted-foreground">
                  {others.map((a) => <li key={a.id}>{t("updates.easy.cannotOne", { name: a.name, why: t(`updates.easy.why.${a.why}`, { version: release.version }) })}</li>)}
                </ul>
              </div>
            )}
          </div>
          <div className="grid content-start gap-2">
            <h3 id={`${id}-order`} className="text-xs font-semibold tracking-wide text-muted-foreground uppercase">{t("updates.easy.order")}</h3>
            {queue.length === 0 ? <p className="text-sm text-muted-foreground">{t("updates.easy.orderEmpty")}</p> : (
              <ol aria-labelledby={`${id}-order`} className="grid max-h-80 gap-1 overflow-y-auto">
                {queue.map((x, i) => {
                  const a = byId.get(x);
                  const name = a?.name ?? x;
                  return (
                    <li key={x} className="flex items-center gap-2 rounded-lg border border-border px-2 py-1 text-sm">
                      <span aria-hidden="true" className="w-6 text-right text-muted-foreground tabular-nums">{i + 1}</span>
                      <span className="min-w-0 flex-1 truncate font-medium">{name}</span>
                      <span className="text-xs text-muted-foreground">{a?.kind === AgentKind.GATEWAY ? t("updates.kinds.gateway") : t("updates.kinds.connector")}</span>
                      <Button type="button" size="icon" variant="ghost" disabled={i === 0} aria-label={t("updates.easy.moveUp", { name })}
                        onClick={() => move(i, -1)}><ArrowUp aria-hidden="true" /></Button>
                      <Button type="button" size="icon" variant="ghost" disabled={i === queue.length - 1} aria-label={t("updates.easy.moveDown", { name })}
                        onClick={() => move(i, 1)}><ArrowDown aria-hidden="true" /></Button>
                    </li>
                  );
                })}
              </ol>
            )}
          </div>
        </div>
        {queue.some((x) => !byId.get(x)?.online) && <p className="text-sm text-warn">{t("updates.easy.offlineChosen")}</p>}
        {listError && <Alert>{ConnectError.from(listError).rawMessage}</Alert>}
        {error && <Alert>{error}</Alert>}
        <div className="flex flex-wrap items-center justify-end gap-2">
          {loaded && blocked && <p id={`${id}-why`} className="mr-auto text-sm text-muted-foreground">{blocked}</p>}
          <Button type="button" variant="outline" onClick={onClose}>{t("updates.cancel")}</Button>
          <Button type="submit" disabled={!loaded || !!blocked || create.isPending} aria-describedby={blocked ? `${id}-why` : undefined}>
            {t("updates.easy.start", { count: queue.length })}
          </Button>
        </div>
      </form>
    </dialog>
  );
}

const failedStates = [RolloutTargetState.ROLLED_BACK, RolloutTargetState.REFUSED, RolloutTargetState.STALLED];
const atRest = [...failedStates, RolloutTargetState.UPDATED, RolloutTargetState.SKIPPED];

// queueParts splits an easy rollout's queue by place: the agent whose turn it is, those still to
// come, and those done, failed or skipped.
export function queueParts(targets: RolloutTarget[]) {
  const sorted = [...targets].sort((a, b) => a.position - b.position);
  const open = sorted.filter((x) => !atRest.includes(x.state));
  return {
    current: open[0], next: open.slice(1),
    done: sorted.filter((x) => x.state === RolloutTargetState.UPDATED),
    failed: sorted.filter((x) => failedStates.includes(x.state)),
    skipped: sorted.filter((x) => x.state === RolloutTargetState.SKIPPED),
  };
}

// EasyRolloutCard follows an easy rollout: the agent whose turn it is, the queue to come, and the
// agents done, failed and skipped, with the count of failures in sight; after failures in a row
// the rollout pauses and says why, with Resume and Cancel (D129).
export function EasyRolloutCard({ rollout }: { rollout: Rollout }) {
  const { t } = useTranslation();
  const list = useQuery(ReleaseService.method.listRolloutTargets, { rolloutId: rollout.id, pageSize: 500 }, { refetchInterval: 5000 });
  const parts = queueParts(list.data?.rolloutTargets ?? []);
  const c = rollout.counts;
  const failures = (c?.rolledBack ?? 0) + (c?.refused ?? 0) + (c?.stalled ?? 0);
  const [state, look] = rolloutStates[rollout.state];
  return (
    <Card title={t("updates.rollout")} description={t("updates.easy.rolloutOf", { version: rollout.version })}
      actions={<span className="flex flex-wrap items-center gap-2">
        {failures > 0 && <Status look="failed">{t("updates.easy.failedCount", { count: failures })}</Status>}
        <Status look={look}>{t(`updates.states.${state}`)}</Status>
      </span>}>
      <Progress rollout={rollout} />
      {rollout.pauseReason && <p role="status" className="text-sm text-warn">{t("updates.paused", { reason: rollout.pauseReason })}</p>}
      {rollout.state === RolloutState.PAUSED && failures > 0 && <p className="text-sm text-muted-foreground">{t("updates.easy.pausedHelp")}</p>}
      <dl className="grid gap-3 text-sm sm:grid-cols-[8rem_1fr]">
        <QueuePart label={t("updates.easy.now")} targets={parts.current ? [parts.current] : []} empty={t("updates.easy.nobody")} state />
        <QueuePart label={t("updates.easy.next")} targets={parts.next} empty={t("updates.easy.nobody")} numbered />
        <QueuePart label={t("updates.easy.updated")} targets={parts.done} empty={t("updates.easy.nobody")} />
        <QueuePart label={t("updates.easy.failed")} targets={parts.failed} empty={t("updates.easy.nobody")} state />
        {parts.skipped.length > 0 && <QueuePart label={t("updates.easy.skipped")} targets={parts.skipped} empty="" state />}
      </dl>
      {list.data?.nextPageToken && <p className="text-sm text-muted-foreground">{t("updates.truncated")}</p>}
      <RolloutControls rollout={rollout} />
    </Card>
  );
}

function QueuePart({ label, targets, empty, state = false, numbered = false }: {
  label: string; targets: RolloutTarget[]; empty: string; state?: boolean; numbered?: boolean;
}) {
  const List = numbered ? "ol" : "ul";
  return (
    <>
      <dt className="font-medium">{label}</dt>
      <dd className="min-w-0">
        {targets.length === 0 ? <span className="text-muted-foreground">{empty}</span> : (
          <List className="grid gap-1">
            {targets.map((x) => (
              <li key={x.id} className="flex flex-wrap items-center gap-x-3 gap-y-1">
                {numbered && <span className="w-6 text-right text-muted-foreground tabular-nums">{x.position}</span>}
                <span className="font-medium">{x.agentName || x.agentId}</span>
                {state && <UpdateState target={x} />}
              </li>
            ))}
          </List>
        )}
      </dd>
    </>
  );
}
