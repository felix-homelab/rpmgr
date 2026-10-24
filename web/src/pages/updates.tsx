// SPDX-License-Identifier: Apache-2.0

import { ConnectError } from "@connectrpc/connect";
import { useMutation, useQuery } from "@connectrpc/connect-query";
import { useQueryClient } from "@tanstack/react-query";
import { CircleCheck, CircleDashed, FileUp, LoaderCircle, RefreshCw, Upload } from "lucide-react";
import { useEffect, useRef, useState, type FormEvent } from "react";
import { useTranslation } from "react-i18next";
import { Alert } from "@/components/public-page";
import { Button } from "@/components/ui/button";
import { Card } from "@/components/ui/card";
import { Table, TD, TH, THead, TR } from "@/components/ui/table";
import { ReleaseCheckOutcome, ReleaseService, ReleaseSource, type Release, type ReleaseCheck } from "@/gen/rpmgr/v1/release_pb";
import { RolloutMode, SettingsService, UpdateChannel } from "@/gen/rpmgr/v1/settings_pb";
import { Reason, reasonOf } from "@/lib/errors";
import { when } from "@/lib/format";
import { InstanceAdminPage, InstanceSettingsSection } from "@/pages/settings";
import { EasyRolloutDialog } from "@/pages/updates-easy";
import { ActiveRollout, RolloutDialog } from "@/pages/updates-rollout";
import { useStepUp } from "@/step-up";

const sources: Record<ReleaseSource, string> = {
  [ReleaseSource.UNSPECIFIED]: "unspecified",
  [ReleaseSource.CHECK]: "check",
  [ReleaseSource.UPLOAD]: "upload",
  [ReleaseSource.IMPORT]: "import",
};

// Updates runs rollouts, easy or staged as the instance setting rollout_mode says, and uploads
// signed releases for air-gapped installations, next to the release check and the update channel
// (docs/09-web-ui.md, "Settings"; docs/04-security.md, "Over-the-air updates"; D121, D129).
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
  // While a release check runs, the list asks again every 2 s, so its releases appear as it ends.
  const list = useQuery(ReleaseService.method.listReleases, { pageSize: 200 },
    { refetchInterval: (q) => (q.state.data?.releaseCheck?.running ? 2000 : false) });
  const active = useQuery(ReleaseService.method.listRollouts, { activeOnly: true });
  // The server fills in the default, easy; until the settings are read, Roll out… waits.
  const settings = useQuery(SettingsService.method.getInstanceSettings, {});
  const mode = settings.data ? settings.data.settings?.rolloutMode || RolloutMode.EASY : undefined;
  const [uploading, setUploading] = useState(false);
  const [rolling, setRolling] = useState<Release>();
  const [checkError, setCheckError] = useState("");
  const running = active.data?.rollouts[0];
  return (
    <>
      <Card title={t("updates.releases")} actions={
        <div className="flex gap-2">
          <CheckNow check={list.data?.releaseCheck} onError={setCheckError} />
          <Button size="sm" variant="outline" onClick={() => setUploading(true)}>{t("updates.upload")}</Button>
        </div>}>
        <CheckState check={list.data?.releaseCheck} />
        {checkError && <Alert>{checkError}</Alert>}
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
                    <Button size="sm" variant="outline" disabled={r.newerThanController || !!running || mode === undefined}
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
      {rolling && (mode === RolloutMode.ADVANCED
        ? <RolloutDialog release={rolling} onClose={() => setRolling(undefined)} />
        : <EasyRolloutDialog release={rolling} onClose={() => setRolling(undefined)} />)}
    </>
  );
}

// CheckNow asks the controller's release check to run at once (#890); the list then follows it.
function CheckNow({ check, onError }: { check?: ReleaseCheck; onError: (message: string) => void }) {
  const { t } = useTranslation();
  const ask = useMutation(ReleaseService.method.checkReleases);
  const queryClient = useQueryClient();
  if (!check || check.outcome === ReleaseCheckOutcome.NONE) return null;
  const busy = check.running || ask.isPending;
  async function run() {
    onError("");
    try {
      await ask.mutateAsync({});
    } catch (err) {
      onError(ConnectError.from(err).rawMessage);
    }
    await queryClient.invalidateQueries();
  }
  return (
    <Button size="sm" variant="outline" disabled={busy} onClick={run}>
      {busy
        ? <LoaderCircle aria-hidden="true" className="animate-spin motion-reduce:animate-none" />
        : <RefreshCw aria-hidden="true" />}
      {t("updates.checkNow")}
    </Button>
  );
}

// CheckState says when the release check last ended and how, or that it runs now.
function CheckState({ check }: { check?: ReleaseCheck }) {
  const { t } = useTranslation();
  if (!check) return null;
  let text: string;
  if (check.running) text = t("updates.checking");
  else if (check.outcome === ReleaseCheckOutcome.NONE) text = t("updates.checkNone");
  else if (check.outcome === ReleaseCheckOutcome.OK) text = t("updates.checkResult.ok", { when: when(check.checkTime) });
  else if (check.outcome === ReleaseCheckOutcome.FAILED) text = t("updates.checkResult.failed", { when: when(check.checkTime), error: check.error });
  else if (check.outcome === ReleaseCheckOutcome.OFF) text = t("updates.checkResult.off", { when: when(check.checkTime) });
  else text = t("updates.checkNever");
  const failed = !check.running && check.outcome === ReleaseCheckOutcome.FAILED;
  return <p role="status" className={`mb-3 text-sm ${failed ? "text-warn" : "text-muted-foreground"}`}>{text}</p>;
}

// uploadFiles are the four signed files of a release upload, with the names a GitHub release gives
// them.
const uploadFiles = [
  ["signingKey", "signing-key.json"],
  ["statementSignature", "signing-key.json.minisig"],
  ["manifest", "manifest.json"],
  ["manifestSignature", "manifest.json.minisig"],
] as const;

type UploadFile = (typeof uploadFiles)[number][0];

// UploadDialog records a release from its four signed files, after a step-up; the artifacts come
// from the release source or `rpmgr release import` on the controller host. Choose files… or a
// drop takes all four at once and sorts them by name; each file also has its own Choose…, for a
// file the browser saved under another name. Upload waits until all four are there and says which
// are missing.
function UploadDialog({ onClose }: { onClose: () => void }) {
  const { t } = useTranslation();
  const dialog = useRef<HTMLDialogElement>(null);
  const all = useRef<HTMLInputElement>(null);
  const one = useRef<Partial<Record<UploadFile, HTMLInputElement | null>>>({});
  const stepUp = useStepUp();
  const upload = useMutation(ReleaseService.method.uploadRelease);
  const queryClient = useQueryClient();
  const [files, setFiles] = useState<Partial<Record<UploadFile, File>>>({});
  const [ignored, setIgnored] = useState<string[]>([]);
  const [dragging, setDragging] = useState(false);
  const [error, setError] = useState("");
  useEffect(() => dialog.current?.showModal(), []);
  const missing = uploadFiles.filter(([key]) => !files[key]?.size).map(([, name]) => name);
  // take sorts files chosen together by their names; a file of another name is listed as ignored.
  function take(list: FileList | null) {
    if (!list?.length) return;
    const next = { ...files };
    const other: string[] = [];
    for (const f of Array.from(list)) {
      const match = uploadFiles.find(([, name]) => name === f.name);
      if (match) next[match[0]] = f;
      else other.push(f.name);
    }
    setFiles(next);
    setIgnored(other);
    setError("");
  }
  async function submit(e: FormEvent) {
    e.preventDefault();
    if (missing.length > 0) return;
    setError("");
    const bytes = async (key: UploadFile) => new Uint8Array(await files[key]!.arrayBuffer());
    try {
      const req = {
        signingKeyStatement: await bytes("signingKey"),
        statementSignature: await bytes("statementSignature"),
        manifest: await bytes("manifest"),
        manifestSignature: await bytes("manifestSignature"),
      };
      await stepUp(() => upload.mutateAsync(req));
      await queryClient.invalidateQueries();
      onClose();
    } catch (err) {
      if (reasonOf(err) !== Reason.stepUpRequired) {
        setError(ConnectError.from(err).rawMessage);
      }
    }
  }
  return (
    <dialog ref={dialog} aria-labelledby="upload-title" aria-describedby="upload-help" onCancel={onClose}
      className="m-auto w-[calc(100%-2rem)] max-w-xl rounded-xl border border-border bg-card shadow-2xl">
      <form onSubmit={submit} noValidate className="flex max-h-[calc(100dvh-4rem)] flex-col">
        <div className="grid gap-4 overflow-y-auto p-6 pb-4">
          <h2 id="upload-title" className="text-lg font-semibold">{t("updates.uploadTitle")}</h2>
          <p id="upload-help" className="text-sm text-muted-foreground">{t("updates.uploadHelp")}</p>
          <div
            onDragOver={(e) => { e.preventDefault(); setDragging(true); }}
            onDragLeave={() => setDragging(false)}
            onDrop={(e) => { e.preventDefault(); setDragging(false); take(e.dataTransfer.files); }}
            className={`grid justify-items-center gap-3 rounded-lg border border-dashed px-4 py-6 text-center text-sm ${dragging ? "border-primary bg-primary/5" : "border-border"}`}>
            <FileUp aria-hidden="true" className="size-6 text-muted-foreground" />
            <span className="text-muted-foreground">{t("updates.dropFiles")}</span>
            <Button variant="outline" onClick={() => all.current?.click()}>{t("updates.chooseFiles")}</Button>
            <input ref={all} type="file" multiple hidden tabIndex={-1} accept=".json,.minisig" aria-label={t("updates.chooseFiles")}
              onChange={(e) => { take(e.target.files); e.target.value = ""; }} />
          </div>
          <ul className="grid gap-2" aria-label={t("updates.signedFiles")}>
            {uploadFiles.map(([key, name]) => {
              const f = files[key];
              const state = !f ? "missing" : f.size === 0 ? "empty" : f.name === name ? "chosen" : "chosenAs";
              const ok = state === "chosen" || state === "chosenAs";
              return (
                <li key={key} className="flex items-center gap-3 rounded-lg border border-border px-3 py-2 text-sm">
                  {ok
                    ? <CircleCheck aria-hidden="true" className="size-4 shrink-0 text-ok" />
                    : <CircleDashed aria-hidden="true" className="size-4 shrink-0 text-muted-foreground" />}
                  <span className="min-w-0 flex-1">
                    <span className="font-mono text-xs">{name}</span>
                    <span className={`block text-xs ${ok ? "text-muted-foreground" : "text-warn"}`}>
                      {t(`updates.fileStates.${state}`, { name: f?.name })}
                    </span>
                  </span>
                  <Button size="sm" variant="outline" aria-label={t("updates.chooseOne", { name })}
                    onClick={() => one.current[key]?.click()}>{t("updates.choose")}</Button>
                  <input ref={(el) => { one.current[key] = el; }} type="file" hidden tabIndex={-1} aria-label={name}
                    onChange={(e) => {
                      const file = e.target.files?.[0];
                      if (file) setFiles({ ...files, [key]: file });
                      setError("");
                      e.target.value = "";
                    }} />
                </li>
              );
            })}
          </ul>
          {ignored.length > 0 && <p className="text-xs text-muted-foreground">{t("updates.ignored", { names: ignored.join(", ") })}</p>}
          {error && <Alert>{error}</Alert>}
        </div>
        <div className="flex flex-wrap items-center justify-end gap-2 border-t border-border px-6 py-4">
          {missing.length > 0 && (
            <p id="upload-missing" className="mr-auto text-xs text-muted-foreground">
              {t("updates.stillMissing", { names: missing.join(", ") })}
            </p>
          )}
          <Button variant="outline" onClick={onClose}>{t("updates.cancel")}</Button>
          <Button type="submit" disabled={missing.length > 0 || upload.isPending}
            aria-describedby={missing.length > 0 ? "upload-missing" : undefined}>
            <Upload aria-hidden="true" />{upload.isPending ? t("updates.uploading") : t("updates.uploadIt")}
          </Button>
        </div>
      </form>
    </dialog>
  );
}
