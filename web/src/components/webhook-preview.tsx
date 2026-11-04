// SPDX-License-Identifier: Apache-2.0

import { ConnectError } from "@connectrpc/connect";
import { useQuery } from "@tanstack/react-query";
import { useEffect, useState } from "react";
import { useTranslation } from "react-i18next";
import { labelClass } from "@/components/field";
import { Alert } from "@/components/public-page";
import { Select } from "@/components/ui/input";
import type { WebhookFormat } from "@/gen/rpmgr/v1/webhook_pb";
import type { Api, Options } from "@/pages/webhooks";

// How long the form must rest before the preview asks again, so that typing is not a request per key.
export const previewDelay = 400;

// WebhookPreview shows the message a chat endpoint would post, as the server makes it for the format
// and options typed so far: the server's code is what delivers, so a preview is never another layout.
// It is loaded when the form first asks for it.
export function WebhookPreview({ api, format, options }: { api: Api; format: WebhookFormat; options: Options }) {
  const { t } = useTranslation();
  const [sample, setSample] = useState("alert.fire");
  const key = JSON.stringify([format, options]);
  const [settled, setSettled] = useState(key);
  useEffect(() => {
    const timer = setTimeout(() => setSettled(key), previewDelay);
    return () => clearTimeout(timer);
  }, [key]);
  const q = useQuery({ queryKey: ["webhook-preview", api.orgId ?? "instance", settled], queryFn: () => api.preview({ format, ...options }), placeholderData: (previous) => previous });
  const shown = q.data?.find((p) => p.eventType === sample) ?? q.data?.[0];
  return (
    <div role="region" aria-label={t("webhooks.previewTitle")} className="grid gap-2 rounded-lg border border-border p-3">
      <div className="flex items-center gap-2">
        <label htmlFor="webhook-preview-sample" className={labelClass()}>{t("webhooks.previewSample")}</label>
        <Select id="webhook-preview-sample" value={sample} onChange={(e) => setSample(e.target.value)}>
          {["alert.fire", "alert.resolve", "route.update"].map((k) => <option key={k} value={k}>{t(`webhooks.previewSamples.${k}`)}</option>)}
        </Select>
      </div>
      {q.error && <Alert>{t("webhooks.previewFailed", { message: ConnectError.from(q.error).rawMessage })}</Alert>}
      {shown && <pre aria-label={shown.eventType} className="max-h-96 overflow-auto rounded-md bg-muted p-3 text-xs">{shown.body}</pre>}
    </div>
  );
}
