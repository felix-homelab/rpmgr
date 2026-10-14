// SPDX-License-Identifier: Apache-2.0

import { timestampMs } from "@bufbuild/protobuf/wkt";
import { useQuery } from "@connectrpc/connect-query";
import { Link } from "@tanstack/react-router";
import { CircleCheck, TriangleAlert } from "lucide-react";
import { useState, type ReactNode } from "react";
import { useTranslation } from "react-i18next";
import { RouteStateChip } from "@/components/route-state";
import { Card } from "@/components/ui/card";
import { CertificateStatus } from "@/gen/rpmgr/v1/certificate_pb";
import { DomainStatus } from "@/gen/rpmgr/v1/domain_pb";
import { RouteState } from "@/gen/rpmgr/v1/route_pb";
import { TokenService } from "@/gen/rpmgr/v1/token_pb";
import { when } from "@/lib/format";
import { soon, useCertificates } from "@/pages/certificates";
import { DomainStatusLabel, useDomains } from "@/pages/domains";
import { useConnectors, useGateways, useRoutes } from "@/routes-data";

// Health lists what in the org needs attention: agents without a control session, routes that do
// not serve fully, failed or expiring certificates, unverified domains, and the user's expiring API
// tokens (docs/09-web-ui.md, "Overview").
export function Health({ orgId }: { orgId: string }) {
  const { t } = useTranslation();
  return (
    <Card title={t("health.title")} className="gap-1 pb-1">
      <div className="-mx-5 divide-y divide-border">
        <Agents orgId={orgId} />
        <Routes orgId={orgId} />
        <Certificates orgId={orgId} />
        <Domains orgId={orgId} />
        <Tokens orgId={orgId} />
      </div>
    </Card>
  );
}

// Area is one area of the health card: what needs attention in it, marked, or that nothing does.
function Area({ id, title, summary, fine, children }: { id: string; title: string; summary?: string; fine: string; children: ReactNode[] }) {
  const Icon = children.length === 0 ? CircleCheck : TriangleAlert;
  return (
    <section aria-labelledby={id} className="grid grid-cols-[auto_1fr] gap-x-3 gap-y-1.5 px-5 py-4 text-sm">
      <Icon aria-hidden="true" className={`mt-0.5 size-4 ${children.length === 0 ? "text-ok" : "text-warn"}`} />
      <h3 id={id} className="font-medium">{title}</h3>
      <div className="col-start-2 grid gap-1.5">
        {summary && <p className="text-muted-foreground">{summary}</p>}
        {children.length === 0 ? <p className="text-muted-foreground">{fine}</p> : <ul aria-label={title} className="grid gap-1.5">{children}</ul>}
      </div>
    </section>
  );
}

function Agents({ orgId }: { orgId: string }) {
  const { t } = useTranslation();
  // A disabled connector or a drained gateway is not expected to be connected (D81).
  const connectors = (useConnectors(orgId).data ?? []).filter((c) => !c.decommissionTime && c.enabled);
  const gateways = (useGateways(orgId).data ?? []).filter((g) => !g.decommissionTime && g.enabled);
  const seen = (ts: Parameters<typeof when>[0]) => (ts ? t("health.lastSeen", { when: when(ts) }) : t("health.neverSeen"));
  const items = [
    ...gateways.filter((g) => !g.status?.connected).map((g) => (
      <li key={g.id}>
        <Link to="/gateways/$groupId" params={{ groupId: g.gatewayGroupId }} className="font-medium hover:underline">{g.name}</Link>
        <span className="ml-2 text-muted-foreground">{g.status?.enrolled ? seen(g.status.lastSeenTime) : t("health.notEnrolled")}</span>
      </li>
    )),
    ...connectors.filter((c) => !c.session?.connected).map((c) => (
      <li key={c.id}>
        <Link to="/connectors/$connectorId" params={{ connectorId: c.id }} className="font-medium hover:underline">{c.name}</Link>
        <span className="ml-2 text-muted-foreground">{seen(c.session?.lastSeenTime)}</span>
      </li>
    )),
  ];
  const count = (all: { connected: boolean }[]) => ({ connected: all.filter((a) => a.connected).length, total: all.length });
  const summary = [
    t("health.gateways", count(gateways.map((g) => ({ connected: !!g.status?.connected })))),
    t("health.connectors", count(connectors.map((c) => ({ connected: !!c.session?.connected })))),
  ].join(" · ");
  return <Area id="health-agents" title={t("health.agents")} summary={summary} fine={t("health.agentsFine")}>{items}</Area>;
}

function Routes({ orgId }: { orgId: string }) {
  const { t } = useTranslation();
  const routes = useRoutes(orgId).data ?? [];
  const items = routes
    .filter((r) => r.status && (![RouteState.READY, RouteState.DISABLED].includes(r.status.state) || r.status.rejections.length > 0))
    .map((r) => (
      <li key={r.id} className="flex flex-wrap items-center gap-2">
        <Link to="/routes/$routeId" params={{ routeId: r.id }} className="font-medium hover:underline">{r.name}</Link>
        <RouteStateChip state={r.status!.state} />
        {r.status!.rejections.length > 0 && <span className="text-muted-foreground">{t("health.rejected", { count: r.status!.rejections.length })}</span>}
      </li>
    ));
  return <Area id="health-routes" title={t("health.routes")} fine={t("health.routesFine", { count: routes.length })}>{items}</Area>;
}

function Certificates({ orgId }: { orgId: string }) {
  const { t } = useTranslation();
  const [now] = useState(() => Date.now());
  const certs = useCertificates(orgId).data ?? [];
  const items = certs
    .filter((c) => c.status === CertificateStatus.FAILED || (c.notAfter && timestampMs(c.notAfter) - now < soon))
    .map((c) => (
      <li key={c.id}>
        <Link to="/domains" className="font-medium hover:underline">{c.sans[0] ?? c.id}</Link>
        <span className="ml-2 text-muted-foreground">
          {c.status === CertificateStatus.FAILED ? t("health.certFailed", { error: c.lastError }) : t("health.expires", { when: when(c.notAfter) })}
        </span>
      </li>
    ));
  return <Area id="health-certs" title={t("health.certificates")} fine={t("health.certsFine")}>{items}</Area>;
}

function Domains({ orgId }: { orgId: string }) {
  const { t } = useTranslation();
  const items = (useDomains(orgId).data ?? []).filter((d) => d.status !== DomainStatus.VERIFIED).map((d) => (
    <li key={d.id}>
      <Link to="/domains" className="font-medium hover:underline">{d.wildcard ? `*.${d.fqdn}` : d.fqdn}</Link>
      <span className="ml-2"><DomainStatusLabel status={d.status} /></span>
    </li>
  ));
  return <Area id="health-domains" title={t("health.domains")} fine={t("health.domainsFine")}>{items}</Area>;
}

function Tokens({ orgId }: { orgId: string }) {
  const { t } = useTranslation();
  const [now] = useState(() => Date.now());
  const tokens = useQuery(TokenService.method.listAPITokens, { orgId }).data?.apiTokens ?? [];
  const items = tokens.filter((k) => k.expireTime && timestampMs(k.expireTime) - now < soon).map((k) => (
    <li key={k.id}>
      <Link to="/account" className="font-medium hover:underline">{k.name}</Link>
      <span className="ml-2 text-muted-foreground">{t(timestampMs(k.expireTime!) < now ? "health.expired" : "health.expires", { when: when(k.expireTime) })}</span>
    </li>
  ));
  return <Area id="health-tokens" title={t("health.tokens")} fine={t("health.tokensFine")}>{items}</Area>;
}
