// SPDX-License-Identifier: Apache-2.0

import { useQuery } from "@connectrpc/connect-query";
import { lazy, Suspense, useEffect, useId, useRef, useState } from "react";
import { useTranslation } from "react-i18next";
import { Alert } from "@/components/public-page";
import { Button } from "@/components/ui/button";
import { ManifestService } from "@/gen/rpmgr/v1/manifest_pb";

// CodeMirror is loaded only when a YAML view opens.
const YamlView = lazy(() => import("@/components/yaml-view"));

interface What {
  orgId: string;
  // The resources by ID, or else every resource of these kinds, such as "Route".
  ids?: string[];
  kinds?: string[];
  // The name of the downloaded file, without ".yaml".
  file: string;
}

// ManifestButton opens the YAML of resources in a dialog, to read, copy and download; editing and
// importing come with manifests in Phase 2 (docs/09-web-ui.md, U5).
export function ManifestButton({ label, title, ...what }: What & { label: string; title: string }) {
  const [open, setOpen] = useState(false);
  return (
    <>
      <Button size="sm" variant="outline" onClick={() => setOpen(true)}>{label}</Button>
      {open && <ManifestDialog title={title} what={what} onClose={() => setOpen(false)} />}
    </>
  );
}

function ManifestDialog({ title, what, onClose }: { title: string; what: What; onClose: () => void }) {
  const { t } = useTranslation();
  const id = useId();
  const dialog = useRef<HTMLDialogElement>(null);
  useEffect(() => dialog.current?.showModal(), []);
  const exported = useQuery(ManifestService.method.exportManifests, { orgId: what.orgId, resourceIds: what.ids ?? [], kinds: what.kinds ?? [] });
  const [copied, setCopied] = useState(false);
  const text = exported.data?.yaml ?? "";
  function download() {
    const url = URL.createObjectURL(new Blob([text], { type: "application/yaml" }));
    const a = document.createElement("a");
    a.href = url;
    a.download = `${what.file}.yaml`;
    a.click();
    URL.revokeObjectURL(url);
  }
  return (
    <dialog ref={dialog} aria-labelledby={id} onCancel={onClose}
      className="m-auto w-full max-w-3xl rounded-lg border border-border bg-background p-6 text-foreground backdrop:bg-black/50">
      <div className="grid gap-3">
        <h2 id={id} className="text-lg font-semibold">{title}</h2>
        {exported.error && <Alert>{exported.error.rawMessage}</Alert>}
        {exported.data && (
          <>
            <p className="text-sm text-muted-foreground">{t("manifest.count", { count: exported.data.count })}</p>
            <Suspense fallback={<p className="text-sm">{t("manifest.loading")}</p>}>
              <YamlView text={text} label={title} />
            </Suspense>
          </>
        )}
        <div className="flex flex-wrap gap-2">
          <Button size="sm" variant="outline" disabled={!exported.data} onClick={() => void navigator.clipboard?.writeText(text).then(() => setCopied(true))}>
            {copied ? t("manifest.copied") : t("mfa.copy")}
          </Button>
          <Button size="sm" variant="outline" disabled={!exported.data} onClick={download}>{t("manifest.download")}</Button>
          <Button size="sm" onClick={onClose}>{t("manifest.close")}</Button>
        </div>
      </div>
    </dialog>
  );
}
