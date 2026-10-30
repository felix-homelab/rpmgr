// SPDX-License-Identifier: Apache-2.0

import { ConnectError } from "@connectrpc/connect";
import { useQuery } from "@connectrpc/connect-query";
import { Link } from "@tanstack/react-router";
import { BellOff, TriangleAlert } from "lucide-react";
import { useTranslation } from "react-i18next";
import { EmptyState } from "@/components/empty-state";
import { Alert } from "@/components/public-page";
import { Card } from "@/components/ui/card";
import { StatusService, type Alert as FiringAlert } from "@/gen/rpmgr/v1/status_pb";
import { InstanceWebhookService, WebhookDisabledReason, WebhookService } from "@/gen/rpmgr/v1/webhook_pb";
import { largestPage } from "@/lib/list-all";
import { when } from "@/lib/format";
import { writers } from "@/pages/webhooks";
import { i18n } from "@/i18n";

// The alert job looks every 30 s (docs/03-connections.md, "Timeouts, keepalive and backoff"), so
// the lists look again at about that pace.
const lookAgain = 30_000;

// Alerts lists the alerts that fire now, the org's and, for the Instance Admin, the instance's
// (docs/09-web-ui.md, "Overview"). An alert that resolves leaves the list at the next look.
export function Alerts({ orgId, instanceAdmin }: { orgId: string; instanceAdmin: boolean }) {
  const { t } = useTranslation();
  const org = useQuery(StatusService.method.listAlerts, { orgId, pageSize: largestPage }, { refetchInterval: lookAgain });
  const inst = useQuery(StatusService.method.listInstanceAlerts, { pageSize: largestPage }, { enabled: instanceAdmin, refetchInterval: lookAgain });
  const orgAlerts = org.data?.alerts ?? [];
  const instAlerts = instanceAdmin ? inst.data?.alerts ?? [] : [];
  const loaded = org.data !== undefined && (!instanceAdmin || inst.data !== undefined);
  const error = org.error ?? inst.error;
  return (
    <Card title={t("alerts.title")} description={t("alerts.intro")}>
      {error && <Alert>{t("alerts.failed", { message: ConnectError.from(error).rawMessage })}</Alert>}
      {loaded && orgAlerts.length === 0 && instAlerts.length === 0 && <EmptyState icon={BellOff}>{t("alerts.none")}</EmptyState>}
      {orgAlerts.length > 0 && <AlertList title={instanceAdmin ? t("alerts.org") : t("alerts.title")} alerts={orgAlerts} />}
      {instAlerts.length > 0 && <AlertList title={t("alerts.instance")} alerts={instAlerts} />}
    </Card>
  );
}

// kindName is the words for an alert kind; a kind this UI does not know is shown as it is.
function kindName(kind: string): string {
  const key = `alerts.kinds.${kind}`;
  return i18n.exists(key) ? i18n.t(key) : kind;
}

// subjectOf is the alert's subject, a link where its page is known.
function subjectOf(a: FiringAlert) {
  const name = a.subjectName || a.subjectId;
  if (a.subjectType === "route") {
    return <Link to="/routes/$routeId" params={{ routeId: a.subjectId }} className="font-medium hover:underline">{name}</Link>;
  }
  if (a.subjectType === "connector") {
    return <Link to="/connectors/$connectorId" params={{ connectorId: a.subjectId }} className="font-medium hover:underline">{name}</Link>;
  }
  return <span className="font-medium">{name}</span>;
}

function AlertList({ title, alerts }: { title: string; alerts: FiringAlert[] }) {
  const { t } = useTranslation();
  return (
    <div className="grid gap-2">
      <h3 className="text-sm font-medium">{title}</h3>
      <ul aria-label={title} className="grid divide-y divide-border text-sm">
        {alerts.map((a) => (
          <li key={a.id} className="grid grid-cols-[auto_1fr] items-baseline gap-x-3 gap-y-0.5 py-2">
            <TriangleAlert aria-hidden="true" className="size-4 translate-y-0.5 text-warn" />
            <span className="flex flex-wrap items-baseline gap-x-2">
              <span>{kindName(a.kind)}</span>
              {subjectOf(a)}
              <span className="text-muted-foreground">{t("alerts.since", { when: when(a.since) })}</span>
            </span>
          </li>
        ))}
      </ul>
    </div>
  );
}

// DisabledWebhooks tells an Owner or Admin of an endpoint the controller disabled because it kept
// failing (D143), and leads to the Webhooks page to enable it again; the Instance Admin is told of
// the instance's endpoints too. The notice is gone once the endpoint is enabled.
export function DisabledWebhooks({ orgId, role, instanceAdmin }: { orgId: string; role: string; instanceAdmin: boolean }) {
  const { t } = useTranslation();
  const mayRead = writers.includes(role);
  const org = useQuery(WebhookService.method.listWebhooks, { orgId, pageSize: largestPage }, { enabled: mayRead, refetchInterval: lookAgain });
  const inst = useQuery(InstanceWebhookService.method.listInstanceWebhooks, { pageSize: largestPage }, { enabled: instanceAdmin, refetchInterval: lookAgain });
  const off = (list?: { enabled: boolean; disabledReason: WebhookDisabledReason; url: string; id: string }[]) =>
    (list ?? []).filter((w) => !w.enabled && w.disabledReason === WebhookDisabledReason.FAILING);
  const items = [
    ...off(mayRead ? org.data?.webhooks : undefined).map((w) => ({ ...w, to: "/webhooks" as const })),
    ...off(instanceAdmin ? inst.data?.webhooks : undefined).map((w) => ({ ...w, to: "/settings/webhooks" as const })),
  ];
  if (items.length === 0) {
    return null;
  }
  return (
    <ul aria-label={t("alerts.disabledTitle")} className="grid gap-2">
      {items.map((w) => (
        <li key={w.id}>
          <div role="alert" className="flex flex-wrap items-center gap-x-3 gap-y-1 rounded-xl border border-destructive/30 bg-destructive/8 p-4 text-sm text-destructive">
            <TriangleAlert aria-hidden="true" className="size-4 shrink-0" />
            <span>{t("alerts.disabled", { url: w.url })}</span>
            <Link to={w.to} className="font-medium underline">{t("alerts.enableAgain")}</Link>
          </div>
        </li>
      ))}
    </ul>
  );
}
