// SPDX-License-Identifier: Apache-2.0

import { ConnectError } from "@connectrpc/connect";
import { useMutation, useQuery } from "@connectrpc/connect-query";
import { useQueryClient } from "@tanstack/react-query";
import { useEffect, useRef, useState, type FormEvent } from "react";
import { useTranslation } from "react-i18next";
import { Alert } from "@/components/public-page";
import { Status, type Look } from "@/components/status";
import { Button } from "@/components/ui/button";
import { Card } from "@/components/ui/card";
import { Input, Select } from "@/components/ui/input";
import { Table, TD, TH, THead, TR } from "@/components/ui/table";
import { ConnectorService } from "@/gen/rpmgr/v1/connector_pb";
import { GatewayService } from "@/gen/rpmgr/v1/gateway_pb";
import {
  AgentKind, ReleaseService, ReleaseSource, RolloutStage, RolloutState, RolloutTargetState,
  type Release, type Rollout, type RolloutTarget,
} from "@/gen/rpmgr/v1/release_pb";
import { UpdateChannel } from "@/gen/rpmgr/v1/settings_pb";
import { Reason, reasonOf } from "@/lib/errors";
import { InstanceAdminPage, InstanceSettingsSection } from "@/pages/settings";
import { useOrg } from "@/session";
import { useStepUp } from "@/step-up";

const sources: Record<ReleaseSource, string> = {
  [ReleaseSource.UNSPECIFIED]: "unspecified",
  [ReleaseSource.CHECK]: "check",
  [ReleaseSource.UPLOAD]: "upload",
  [ReleaseSource.IMPORT]: "import",
};

const stages: Record<RolloutStage, string> = {
  [RolloutStage.UNSPECIFIED]: "unspecified",
  [RolloutStage.CANARY]: "canary",
  [RolloutStage.PERCENTAGE]: "percentage",
  [RolloutStage.ALL]: "all",
};

const states: Record<RolloutState, [string, Look]> = {
  [RolloutState.UNSPECIFIED]: ["unspecified", "unknown"],
  [RolloutState.RUNNING]: ["running", "pending"],
  [RolloutState.PAUSED]: ["paused", "warn"],
  [RolloutState.COMPLETED]: ["completed", "ok"],
  [RolloutState.CANCELLED]: ["cancelled", "off"],
};

const targets: Record<RolloutTargetState, [string, Look]> = {
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

// Updates runs staged rollouts and uploads signed releases for air-gapped installations, next to
// the release check and the update channel (docs/09-web-ui.md, "Settings";
// docs/04-security.md, "Over-the-air updates"; D121).
export function Updates() {
  const { t } = useTranslation();
  return (
    <InstanceAdminPage title={t("settings.updates")}>
      <InstanceSettingsSection title={t("settings.sections.updates")} sections={["updates"]} />
      <Releases />
      <ActiveRollout />
    </InstanceAdminPage>
  );
}

// Releases lists the releases the controller verified and starts a rollout of one of them.
function Releases() {
  const { t } = useTranslation();
  const list = useQuery(ReleaseService.method.listReleases, { pageSize: 200 });
  const active = useQuery(ReleaseService.method.listRollouts, { activeOnly: true });
  const [uploading, setUploading] = useState(false);
  const [rolling, setRolling] = useState<Release>();
  const running = active.data?.rollouts[0];
  return (
    <>
      <Card title={t("updates.releases")} actions={<Button size="sm" variant="outline" onClick={() => setUploading(true)}>{t("updates.upload")}</Button>}>
        {list.error && <Alert>{ConnectError.from(list.error).rawMessage}</Alert>}
        {list.data && (
          <Table framed={false}>
            <THead>
              <tr>{["version", "channel", "source", "mirrored", "controller", ""].map((c, i) => <TH key={i}>{c ? t(`updates.columns.${c}`) : ""}</TH>)}</tr>
            </THead>
            <tbody>
              {list.data.releases.map((r) => (
                <TR key={r.id}>
                  <TD className="font-medium">{r.version}</TD>
                  <TD>{r.channel === UpdateChannel.PRERELEASE ? t("updates.channels.prerelease") : t("updates.channels.stable")}</TD>
                  <TD>{t(`updates.sources.${sources[r.source]}`)}</TD>
                  <TD>{r.mirrored ? t("updates.yes") : t("updates.no")}</TD>
                  <TD>{r.controllerVersion ? t("updates.thisController") : r.newerThanController ? t("updates.newer") : "—"}</TD>
                  <TD className="text-right">
                    <Button size="sm" variant="outline" disabled={r.newerThanController || !!running}
                      onClick={() => setRolling(r)}>{t("updates.rollOut")}</Button>
                  </TD>
                </TR>
              ))}
              {list.data.releases.length === 0 && <TR><TD colSpan={6}>{t("updates.noReleases")}</TD></TR>}
            </tbody>
          </Table>
        )}
        {list.data?.nextPageToken && <p className="text-sm text-muted-foreground">{t("updates.more")}</p>}
      </Card>
      {uploading && <UploadDialog onClose={() => setUploading(false)} />}
      {rolling && <RolloutDialog release={rolling} onClose={() => setRolling(undefined)} />}
    </>
  );
}

// UploadDialog records a release from its four signed files, after a step-up; the artifacts come
// from the release source or `rpmgr release import` on the controller host.
function UploadDialog({ onClose }: { onClose: () => void }) {
  const { t } = useTranslation();
  const dialog = useRef<HTMLDialogElement>(null);
  const stepUp = useStepUp();
  const upload = useMutation(ReleaseService.method.uploadRelease);
  const queryClient = useQueryClient();
  const [files, setFiles] = useState<Record<string, File>>({});
  const [error, setError] = useState("");
  useEffect(() => dialog.current?.showModal(), []);
  async function bytes(name: string): Promise<Uint8Array> {
    const f = files[name];
    return f ? new Uint8Array(await f.arrayBuffer()) : new Uint8Array();
  }
  async function submit(e: FormEvent) {
    e.preventDefault();
    setError("");
    const files = await readFiles(bytes);
    try {
      await stepUp(() => upload.mutateAsync(files));
      await queryClient.invalidateQueries();
      onClose();
    } catch (err) {
      if (reasonOf(err) !== Reason.stepUpRequired) {
        setError(ConnectError.from(err).rawMessage);
      }
    }
  }
  return (
    <dialog ref={dialog} aria-labelledby="upload-title" onCancel={onClose}
      className="m-auto w-[calc(100%-2rem)] max-w-xl rounded-xl border border-border bg-card p-6 shadow-2xl">
      <h2 id="upload-title" className="text-lg font-semibold">{t("updates.uploadTitle")}</h2>
      <form onSubmit={submit} className="mt-5 grid gap-4" noValidate>
        {["signingKey", "statementSignature", "manifest", "manifestSignature"].map((name) => (
          <label key={name} className="grid gap-1.5 text-sm font-medium">
            {t(`updates.files.${name}`)}
            <input type="file" className="font-normal" onChange={(e) => setFiles({ ...files, [name]: e.target.files?.[0] as File })} />
          </label>
        ))}
        {error && <Alert>{error}</Alert>}
        <div className="flex justify-end gap-2">
          <Button type="button" variant="outline" onClick={onClose}>{t("updates.cancel")}</Button>
          <Button type="submit" disabled={upload.isPending}>{t("updates.uploadIt")}</Button>
        </div>
      </form>
    </dialog>
  );
}

// readFiles reads the four signed files of a release upload.
async function readFiles(bytes: (name: string) => Promise<Uint8Array>) {
  return {
    signingKeyStatement: await bytes("signingKey"),
    statementSignature: await bytes("statementSignature"),
    manifest: await bytes("manifest"),
    manifestSignature: await bytes("manifestSignature"),
  };
}

// RolloutDialog asks for the canary agents of a new rollout, from the user's org, and starts it
// after a step-up.
function RolloutDialog({ release, onClose }: { release: Release; onClose: () => void }) {
  const { t } = useTranslation();
  const dialog = useRef<HTMLDialogElement>(null);
  const org = useOrg();
  const stepUp = useStepUp();
  const create = useMutation(ReleaseService.method.createRollout);
  const queryClient = useQueryClient();
  const connectors = useQuery(ConnectorService.method.listConnectors, { orgId: org?.orgId ?? "", pageSize: 200 }, { enabled: !!org });
  const gateways = useQuery(GatewayService.method.listGateways, { orgId: org?.orgId ?? "", pageSize: 200 }, { enabled: !!org });
  const [chosen, setChosen] = useState<Set<string>>(new Set());
  const [error, setError] = useState("");
  useEffect(() => dialog.current?.showModal(), []);
  const agents = [
    ...(connectors.data?.connectors ?? []).filter((c) => !c.builtIn).map((c) => ({ id: c.id, name: c.name, kind: AgentKind.CONNECTOR })),
    ...(gateways.data?.gateways ?? []).filter((g) => !g.builtIn).map((g) => ({ id: g.id, name: g.name, kind: AgentKind.GATEWAY })),
  ];
  async function submit(e: FormEvent) {
    e.preventDefault();
    setError("");
    if (chosen.size === 0) {
      setError(t("updates.chooseCanary"));
      return;
    }
    try {
      await stepUp(() => create.mutateAsync({ releaseId: release.id, canaryAgentIds: [...chosen] }));
      await queryClient.invalidateQueries();
      onClose();
    } catch (err) {
      if (reasonOf(err) !== Reason.stepUpRequired) {
        setError(ConnectError.from(err).rawMessage);
      }
    }
  }
  return (
    <dialog ref={dialog} aria-labelledby="rollout-title" onCancel={onClose}
      className="m-auto w-[calc(100%-2rem)] max-w-xl rounded-xl border border-border bg-card p-6 shadow-2xl">
      <h2 id="rollout-title" className="text-lg font-semibold">{t("updates.rolloutTitle", { version: release.version })}</h2>
      <form onSubmit={submit} className="mt-5 grid gap-4" noValidate>
        <fieldset className="grid gap-2">
          <legend className="text-sm font-medium">{t("updates.canaries")}</legend>
          {agents.map((a) => (
            <label key={a.id} className="flex items-center gap-2 text-sm">
              <input type="checkbox" className="size-4 accent-primary" checked={chosen.has(a.id)}
                onChange={(e) => {
                  const next = new Set(chosen);
                  if (e.target.checked) next.add(a.id); else next.delete(a.id);
                  setChosen(next);
                }} />
              {a.name} <span className="text-muted-foreground">{t(`updates.kinds.${a.kind === AgentKind.GATEWAY ? "gateway" : "connector"}`)}</span>
            </label>
          ))}
          {agents.length === 0 && <p className="text-sm text-muted-foreground">{t("updates.noAgents")}</p>}
        </fieldset>
        {error && <Alert>{error}</Alert>}
        <div className="flex justify-end gap-2">
          <Button type="button" variant="outline" onClick={onClose}>{t("updates.cancel")}</Button>
          <Button type="submit" disabled={create.isPending}>{t("updates.start")}</Button>
        </div>
      </form>
    </dialog>
  );
}

// ActiveRollout follows the running or paused rollout, with each agent's state and reason, and
// lets the Instance Admin advance, pause, resume or cancel it. The counts refresh while the page
// is open, because the rollout job moves them.
function ActiveRollout() {
  const { t } = useTranslation();
  const active = useQuery(ReleaseService.method.listRollouts, { activeOnly: true }, { refetchInterval: 5000 });
  const rollout = active.data?.rollouts[0];
  if (!rollout) {
    return null;
  }
  return (
    <Card title={t("updates.rollout")} description={t("updates.rolloutOf", { version: rollout.version })}>
      <RolloutSummary rollout={rollout} />
      <RolloutActions rollout={rollout} />
      <Targets rolloutId={rollout.id} />
    </Card>
  );
}

function RolloutSummary({ rollout }: { rollout: Rollout }) {
  const { t } = useTranslation();
  const [state, tone] = states[rollout.state];
  const c = rollout.counts;
  const stage = rollout.stage === RolloutStage.PERCENTAGE ? t("updates.stagePercent", { percent: rollout.percentage }) : t(`updates.stages.${stages[rollout.stage]}`);
  return (
    <div className="grid gap-1.5 text-sm">
      <p><Status look={tone}>{t(`updates.states.${state}`)}</Status> <span className="text-muted-foreground">{stage}</span></p>
      {rollout.pauseReason && <p role="status" className="text-warn-foreground">{t("updates.paused", { reason: rollout.pauseReason })}</p>}
      <p className="text-muted-foreground">
        {t("updates.counts", { updated: c?.updated ?? 0, pending: c?.pending ?? 0, skipped: c?.skipped ?? 0,
          rolledBack: c?.rolledBack ?? 0, stalled: c?.stalled ?? 0 })}
      </p>
    </div>
  );
}

// RolloutActions changes the rollout under the etag the page read; a stale etag reloads the page.
function RolloutActions({ rollout }: { rollout: Rollout }) {
  const { t } = useTranslation();
  const stepUp = useStepUp();
  const queryClient = useQueryClient();
  const advance = useMutation(ReleaseService.method.advanceRollout);
  const pause = useMutation(ReleaseService.method.pauseRollout);
  const resume = useMutation(ReleaseService.method.resumeRollout);
  const cancel = useMutation(ReleaseService.method.cancelRollout);
  const [mode, setMode] = useState("25");
  const [percent, setPercent] = useState("");
  const [asking, setAsking] = useState(false);
  const [error, setError] = useState("");
  async function run(f: () => Promise<unknown>) {
    setError("");
    try {
      await f();
      await queryClient.invalidateQueries();
    } catch (err) {
      if (reasonOf(err) !== Reason.stepUpRequired) {
        setError(ConnectError.from(err).rawMessage);
      }
    }
  }
  return (
    <div className="grid gap-2">
      <div className="flex flex-wrap items-end gap-2">
        {rollout.state === RolloutState.RUNNING && rollout.stage !== RolloutStage.ALL && (
          <>
            <label className="grid gap-1 text-sm font-medium">
              {t("updates.nextStage")}
              <Select className="font-normal" value={mode} onChange={(e) => setMode(e.target.value)}>
                <option value="all">{t("updates.allAgents")}</option>
                {[10, 25, 50, 75].filter((p) => p > rollout.percentage).map((p) => <option key={p} value={String(p)}>{p} %</option>)}
                <option value="other">{t("updates.otherPercent")}</option>
              </Select>
            </label>
            {mode === "other" && <Input className="w-24" inputMode="numeric" aria-label={t("updates.percent")} value={percent}
              onChange={(e) => setPercent(e.target.value)} />}
            <Button size="sm" variant="outline" disabled={advance.isPending}
              onClick={() => void run(() => stepUp(() => advance.mutateAsync(
                mode === "all"
                  ? { rolloutId: rollout.id, etag: rollout.etag, next: { case: "all" as const, value: true } }
                  : { rolloutId: rollout.id, etag: rollout.etag, next: { case: "percentage" as const, value: Number(mode === "other" ? percent : mode) } })))}>{t("updates.advance")}</Button>
          </>
        )}
        {rollout.state === RolloutState.RUNNING && (
          <Button size="sm" variant="outline" disabled={pause.isPending}
            onClick={() => void run(() => pause.mutateAsync({ rolloutId: rollout.id, etag: rollout.etag }))}>{t("updates.pause")}</Button>
        )}
        {rollout.state === RolloutState.PAUSED && (
          <Button size="sm" variant="outline" disabled={resume.isPending}
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

// Targets lists each agent of the rollout with its state and why, newest pages included.
function Targets({ rolloutId }: { rolloutId: string }) {
  const { t } = useTranslation();
  const list = useQuery(ReleaseService.method.listRolloutTargets, { rolloutId, pageSize: 500 }, { refetchInterval: 5000 });
  return (
    <Table framed={false}>
      <THead>
        <tr>{["agent", "kind", "state", "reason"].map((c) => <TH key={c}>{t(`updates.targetColumns.${c}`)}</TH>)}</tr>
      </THead>
      <tbody>
        {(list.data?.rolloutTargets ?? []).map((x) => <TargetRow key={x.id} target={x} />)}
      </tbody>
    </Table>
  );
}

function TargetRow({ target }: { target: RolloutTarget }) {
  const { t } = useTranslation();
  const [state, tone] = targets[target.state];
  return (
    <TR>
      <TD className="font-medium">{target.agentName || target.agentId}</TD>
      <TD>{t(`updates.kinds.${target.agentKind === AgentKind.GATEWAY ? "gateway" : "connector"}`)}</TD>
      <TD><Status look={tone}>{t(`updates.targetStates.${state}`)}</Status></TD>
      <TD className="text-muted-foreground">{target.reason || "—"}</TD>
    </TR>
  );
}
