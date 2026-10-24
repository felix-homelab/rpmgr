// SPDX-License-Identifier: Apache-2.0

import { ConnectError } from "@connectrpc/connect";
import { useMutation, useQuery } from "@connectrpc/connect-query";
import { useQueryClient } from "@tanstack/react-query";
import { useState, type ChangeEvent } from "react";
import { useTranslation } from "react-i18next";
import { Alert } from "@/components/public-page";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card } from "@/components/ui/card";
import { GatewayPageKind, GatewayService, type GatewayPage } from "@/gen/rpmgr/v1/gateway_pb";
import type { Written } from "@/pages/gateway-actions";

// The pages a group may replace, in the order the card shows them, with their i18n keys.
const kinds: [GatewayPageKind, string][] = [
  [GatewayPageKind.NOT_FOUND, "notFound"], [GatewayPageKind.UNAVAILABLE, "unavailable"], [GatewayPageKind.MAINTENANCE, "maintenance"],
];

// placeholders are what a page of a kind may show; only the maintenance page has a message.
function placeholders(kind: GatewayPageKind): string[] {
  return kind === GatewayPageKind.MAINTENANCE ? ["hostname", "status", "message", "request_id"] : ["hostname", "status", "request_id"];
}

// maxPage is the largest page the API takes, in bytes (docs/03-connections.md, "Timeouts,
// keepalive and backoff"); the form refuses a larger file before it uploads it.
const maxPage = 64 * 1024;

// GatewayPages shows a gateway group's not-found, unavailable and maintenance pages, each built in
// or the group's own, with a preview the controller renders as gateways do (D136), and uploads or
// resets them (docs/09-web-ui.md, "Gateways"; D132). Only the group's owner org may change them.
export function GatewayPages({ groupId, onDone }: { groupId: string; onDone: (w: Written) => void }) {
  const { t } = useTranslation();
  const pages = useQuery(GatewayService.method.listGatewayPages, { gatewayGroupId: groupId });
  return (
    <Card title={t("gwPages.title")}>
      <p className="text-sm text-muted-foreground">{t("gwPages.intro")}</p>
      <ul className="-mx-5 divide-y divide-border border-y border-border">
        {kinds.map(([kind, key]) => (
          <PageRow key={key} groupId={groupId} kind={kind} name={key} page={pages.data?.gatewayPages.find((p) => p.kind === kind)} onDone={onDone} />
        ))}
      </ul>
    </Card>
  );
}

function PageRow({ groupId, kind, name, page, onDone }: {
  groupId: string; kind: GatewayPageKind; name: string; page?: GatewayPage; onDone: (w: Written) => void;
}) {
  const { t } = useTranslation();
  const queryClient = useQueryClient();
  const set = useMutation(GatewayService.method.setGatewayPage);
  const remove = useMutation(GatewayService.method.deleteGatewayPage);
  const link = useMutation(GatewayService.method.previewGatewayPage);
  const [asking, setAsking] = useState(false);
  const [preview, setPreview] = useState<string>(); // the preview's link while it shows
  async function togglePreview() {
    setError("");
    if (preview) {
      setPreview(undefined);
      return;
    }
    try {
      setPreview((await link.mutateAsync({ gatewayGroupId: groupId, kind })).url);
    } catch (err) {
      setError(ConnectError.from(err).rawMessage);
    }
  }
  const [error, setError] = useState("");
  const title = t(`gwPages.kinds.${name}`);
  async function upload(e: ChangeEvent<HTMLInputElement>) {
    const file = e.target.files?.[0];
    e.target.value = "";
    setError("");
    if (!file) {
      return;
    }
    if (file.size > maxPage) {
      setError(t("gwPages.tooLarge", { size: file.size }));
      return;
    }
    try {
      const res = await set.mutateAsync({ gatewayPage: { gatewayGroupId: groupId, kind, html: await file.text() } });
      await queryClient.invalidateQueries();
      setPreview(undefined); // its link shows the page it was made for, which changed
      onDone({ revision: res.revision, status: res.applyStatus });
    } catch (err) {
      setError(ConnectError.from(err).rawMessage);
    }
  }
  async function reset() {
    setError("");
    try {
      const res = await remove.mutateAsync({ gatewayGroupId: groupId, kind });
      setAsking(false);
      await queryClient.invalidateQueries();
      setPreview(undefined); // its link shows the page it was made for, which changed
      onDone({ revision: res.revision, status: res.applyStatus });
    } catch (err) {
      setError(ConnectError.from(err).rawMessage);
    }
  }
  return (
    <li className="grid gap-2 px-5 py-3" aria-label={title}>
      <div className="flex flex-wrap items-center justify-between gap-2">
        <span className="flex items-center gap-2 font-medium">
          {title}<Badge tone={page ? "accent" : "neutral"}>{t(page ? "gwPages.own" : "gwPages.builtIn")}</Badge>
        </span>
        <span className="flex flex-wrap items-center gap-2">
          <Button size="sm" variant="outline" aria-expanded={!!preview} disabled={link.isPending} onClick={() => void togglePreview()}>
            {t(preview ? "gwPages.hide" : "gwPages.preview")}
          </Button>
          <label className="inline-flex h-8 cursor-pointer items-center rounded-md border border-border bg-background px-3 text-sm font-medium hover:bg-muted focus-within:ring-2 focus-within:ring-ring">
            {t("gwPages.upload")}
            <input type="file" accept=".html,.htm,text/html" className="sr-only" disabled={set.isPending} onChange={(e) => void upload(e)} />
          </label>
          {page && (asking ? (
            <>
              <span>{t("gwPages.ask", { page: title })}</span>
              <Button size="sm" variant="destructive" disabled={remove.isPending} onClick={() => void reset()}>{t("gwPages.reset")}</Button>
              <Button size="sm" variant="outline" onClick={() => setAsking(false)}>{t("stepUp.cancel")}</Button>
            </>
          ) : <Button size="sm" variant="outline" onClick={() => setAsking(true)}>{t("gwPages.resetAsk")}</Button>)}
        </span>
      </div>
      <p className="text-xs text-muted-foreground">
        {t("gwPages.placeholders")}{" "}
        {placeholders(kind).map((p, i) => <span key={p}>{i > 0 && ", "}<code>{`{{${p}}}`}</code></span>)}
      </p>
      {preview && (
        // The controller renders the page as gateways send it, under its own CSP and a sandbox; the
        // frame's empty sandbox adds that it runs no script, submits no form and has no origin of ours.
        <iframe title={t("gwPages.previewOf", { page: title })} sandbox="" src={preview} className="h-72 w-full rounded-lg border border-border bg-white" />
      )}
      {error && <Alert>{error}</Alert>}
    </li>
  );
}
