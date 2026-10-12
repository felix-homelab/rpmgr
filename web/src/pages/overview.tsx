// SPDX-License-Identifier: Apache-2.0

import { timestampMs } from "@bufbuild/protobuf/wkt";
import { useQuery } from "@connectrpc/connect-query";
import { Link, type LinkOptions } from "@tanstack/react-router";
import { useState } from "react";
import { useTranslation } from "react-i18next";
import { PageHeader } from "@/components/page-header";
import { Alert } from "@/components/public-page";
import { Status, type Look } from "@/components/status";
import { bytes, filled, hourMs, totals, TrafficChart, TrafficStats } from "@/components/traffic";
import { Card } from "@/components/ui/card";
import { AuthService } from "@/gen/rpmgr/v1/auth_pb";
import { CertificateStatus } from "@/gen/rpmgr/v1/certificate_pb";
import { DomainStatus } from "@/gen/rpmgr/v1/domain_pb";
import { MetricsService } from "@/gen/rpmgr/v1/metrics_pb";
import { RouteState } from "@/gen/rpmgr/v1/route_pb";
import { i18n } from "@/i18n";
import { soon, useCertificates } from "@/pages/certificates";
import { useDomains } from "@/pages/domains";
import { Health } from "@/pages/overview-health";
import { useConnectors, useGateways, useRoutes } from "@/routes-data";
import { useOrg } from "@/session";

// Overview is the org at a glance (docs/09-web-ui.md, "Overview"): a figure per area, the traffic
// of the last 24 hours and what needs attention.
export function Overview() {
  const { t } = useTranslation();
  const session = useQuery(AuthService.method.getSession, {});
  const org = useOrg();
  return (
    <div className="grid gap-6">
      <PageHeader title={t("overview.title")}
        description={session.data && t("overview.signedIn", { name: session.data.displayName || session.data.email })} />
      {org && (
        <>
          <Summary orgId={org.orgId} />
          <div className="grid items-start gap-6 xl:grid-cols-3">
            <Traffic orgId={org.orgId} className="xl:col-span-2" />
            <Health orgId={org.orgId} />
          </div>
        </>
      )}
    </div>
  );
}

// Summary is a row of figures, one per area, each leading to its page: how many of the area's
// resources are well, of how many, and what needs attention.
function Summary({ orgId }: { orgId: string }) {
  const { t } = useTranslation();
  const [now] = useState(() => Date.now());
  const routes = useRoutes(orgId).data;
  const connectors = useConnectors(orgId).data?.filter((c) => !c.decommissionTime);
  const gateways = useGateways(orgId).data?.filter((g) => !g.decommissionTime);
  const certificates = useCertificates(orgId).data;
  const domains = useDomains(orgId).data;

  // Disabled routes are left out, as in "Needs attention".
  const enabled = routes?.filter((r) => r.status?.state !== RouteState.DISABLED);
  const agents = gateways && connectors && [...gateways.map((g) => !!g.status?.connected), ...connectors.map((c) => !!c.session?.connected)];
  const bad = {
    routes: enabled?.filter((r) => r.status?.state !== RouteState.READY || r.status.rejections.length > 0).length,
    agents: agents?.filter((up) => !up).length,
    certificates: certificates?.filter((c) => c.status === CertificateStatus.FAILED || (c.notAfter && timestampMs(c.notAfter) - now < soon)).length,
    domains: domains?.filter((d) => d.status !== DomainStatus.VERIFIED).length,
  };
  const tiles: [keyof typeof bad, LinkOptions, number | undefined][] = [
    ["routes", { to: "/routes", search: {} }, enabled?.length],
    ["agents", { to: "/connectors", search: {} }, agents?.length],
    ["certificates", { to: "/domains" }, certificates?.length],
    ["domains", { to: "/domains" }, domains?.length],
  ];
  return (
    <ul aria-label={t("summary.title")} className="grid gap-4 sm:grid-cols-2 xl:grid-cols-4">
      {tiles.map(([key, link, total]) => {
        const n = bad[key] ?? 0;
        const state: [Look, string] | undefined = total === undefined ? undefined
          : total === 0 ? ["off", t(`summary.${key}None`)] : n > 0 ? ["warn", t(`summary.${key}Bad`, { count: n })] : ["ok", t(`summary.${key}Good`)];
        return <Tile key={key} label={t(`summary.${key}`)} link={link} value={total === undefined ? undefined : [total - n, total]} state={state} />;
      })}
    </ul>
  );
}

function Tile({ label, link, value, state }: { label: string; link: LinkOptions; value?: [number, number]; state?: [Look, string] }) {
  const { t } = useTranslation();
  const n = (v: number) => v.toLocaleString(i18n.language);
  return (
    <li>
      <Link {...link} className="grid h-full content-start gap-3 rounded-xl border border-border bg-card p-5 shadow-xs transition-colors hover:border-input">
        <span className="text-sm font-medium text-muted-foreground">{label}</span>
        <span className="flex items-baseline gap-1.5">
          <span className="text-3xl font-semibold tracking-tight">{value ? n(value[0]) : "–"}</span>
          {value && value[1] > 0 && <span className="text-sm text-muted-foreground">{t("summary.of", { total: n(value[1]) })}</span>}
        </span>
        {state && <Status look={state[0]}>{state[1]}</Status>}
      </Link>
    </li>
  );
}

// Traffic summarises the org's last 24 hours: their totals, the hours and the busiest routes
// (docs/09-web-ui.md, "Overview").
function Traffic({ orgId, className }: { orgId: string; className?: string }) {
  const { t } = useTranslation();
  const overview = useQuery(MetricsService.method.getOverview, { orgId });
  const routes = useRoutes(orgId);
  const name = (id: string) => routes.data?.find((r) => r.id === id)?.name ?? id;
  const o = overview.data;
  // The total's start is the first of the 24 hours.
  const first = o?.total?.start ? timestampMs(o.total.start) : undefined;
  return (
    <Card title={t("traffic.day")} className={className}>
      {overview.error && <Alert>{overview.error.rawMessage}</Alert>}
      {o && (
        <>
          <TrafficStats t={totals(o.total ? [o.total] : [])} />
          <TrafficChart buckets={first === undefined ? o.hours : filled(o.hours, first, first + 24 * hourMs, hourMs)} />
          <div className="grid gap-1 border-t border-border pt-4">
            <h3 className="text-sm font-medium">{t("traffic.busiest")}</h3>
            {o.busiestRoutes.length === 0 ? (
              <p className="text-sm text-muted-foreground">{t("traffic.none")}</p>
            ) : (
              <ol aria-label={t("traffic.busiest")} className="grid divide-y divide-border text-sm">
                {o.busiestRoutes.map((r) => (
                  <li key={r.routeId} className="flex flex-wrap items-center justify-between gap-x-4 py-2">
                    <Link to="/routes/$routeId" params={{ routeId: r.routeId }} className="font-medium hover:underline">{name(r.routeId)}</Link>
                    <span className="text-muted-foreground tabular-nums">
                      {t("traffic.inOut", { in: bytes(r.total?.bytesIn ?? 0n), out: bytes(r.total?.bytesOut ?? 0n) })}
                    </span>
                  </li>
                ))}
              </ol>
            )}
          </div>
        </>
      )}
    </Card>
  );
}
