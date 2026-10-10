// SPDX-License-Identifier: Apache-2.0

import { timestampMs } from "@bufbuild/protobuf/wkt";
import { useQuery } from "@connectrpc/connect-query";
import { Link } from "@tanstack/react-router";
import { useTranslation } from "react-i18next";
import { Alert } from "@/components/public-page";
import { bytes, filled, hourMs, totals, TotalsLine, TrafficChart } from "@/components/traffic";
import { AuthService } from "@/gen/rpmgr/v1/auth_pb";
import { MetricsService } from "@/gen/rpmgr/v1/metrics_pb";
import { Health } from "@/pages/overview-health";
import { useRoutes } from "@/routes-data";
import { useOrg } from "@/session";

export function Overview() {
  const { t } = useTranslation();
  const session = useQuery(AuthService.method.getSession, {});
  const org = useOrg();
  return (
    <div className="grid gap-8">
      <section aria-labelledby="overview-title">
        <h1 id="overview-title" className="text-2xl font-semibold">
          {t("overview.title")}
        </h1>
        {session.data && (
          <p className="mt-2 text-muted-foreground">
            {t("overview.signedIn", { name: session.data.displayName || session.data.email })}
          </p>
        )}
      </section>
      {org && <Health orgId={org.orgId} />}
      {org && <Traffic orgId={org.orgId} />}
    </div>
  );
}

// Traffic summarises the org's last 24 hours: the hours, their totals and the busiest routes
// (docs/09-web-ui.md, "Overview").
function Traffic({ orgId }: { orgId: string }) {
  const { t } = useTranslation();
  const overview = useQuery(MetricsService.method.getOverview, { orgId });
  const routes = useRoutes(orgId);
  const name = (id: string) => routes.data?.find((r) => r.id === id)?.name ?? id;
  const o = overview.data;
  // The total's start is the first of the 24 hours.
  const first = o?.total?.start ? timestampMs(o.total.start) : undefined;
  return (
    <section aria-labelledby="traffic-title" className="grid gap-3">
      <h2 id="traffic-title" className="text-lg font-semibold">{t("traffic.day")}</h2>
      {overview.error && <Alert>{overview.error.rawMessage}</Alert>}
      {o && (
        <>
          <TotalsLine t={totals(o.total ? [o.total] : [])} />
          <TrafficChart buckets={first === undefined ? o.hours : filled(o.hours, first, first + 24 * hourMs, hourMs)} />
          <h3 className="font-medium">{t("traffic.busiest")}</h3>
          {o.busiestRoutes.length === 0 ? (
            <p className="text-sm text-muted-foreground">{t("traffic.none")}</p>
          ) : (
            <ol aria-label={t("traffic.busiest")} className="grid gap-1 text-sm">
              {o.busiestRoutes.map((r) => (
                <li key={r.routeId}>
                  <Link to="/routes/$routeId" params={{ routeId: r.routeId }} className="underline">{name(r.routeId)}</Link>
                  <span className="ml-2 text-muted-foreground">
                    {t("traffic.inOut", { in: bytes(r.total?.bytesIn ?? 0n), out: bytes(r.total?.bytesOut ?? 0n) })}
                  </span>
                </li>
              ))}
            </ol>
          )}
        </>
      )}
    </section>
  );
}
