// SPDX-License-Identifier: Apache-2.0

import { ConnectError } from "@connectrpc/connect";
import { useMutation, useQuery } from "@connectrpc/connect-query";
import { useQueryClient } from "@tanstack/react-query";
import { useEffect, useRef, useState, type FormEvent } from "react";
import { useTranslation } from "react-i18next";
import { Alert } from "@/components/public-page";
import { Button } from "@/components/ui/button";
import { Card } from "@/components/ui/card";
import { Table, TD, TH, THead, TR } from "@/components/ui/table";
import { ReleaseService, ReleaseSource, type Release } from "@/gen/rpmgr/v1/release_pb";
import { UpdateChannel } from "@/gen/rpmgr/v1/settings_pb";
import { Reason, reasonOf } from "@/lib/errors";
import { InstanceAdminPage, InstanceSettingsSection } from "@/pages/settings";
import { ActiveRollout, RolloutDialog } from "@/pages/updates-rollout";
import { useStepUp } from "@/step-up";

const sources: Record<ReleaseSource, string> = {
  [ReleaseSource.UNSPECIFIED]: "unspecified",
  [ReleaseSource.CHECK]: "check",
  [ReleaseSource.UPLOAD]: "upload",
  [ReleaseSource.IMPORT]: "import",
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
