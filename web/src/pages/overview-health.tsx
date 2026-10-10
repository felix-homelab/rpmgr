// SPDX-License-Identifier: Apache-2.0

import { timestampMs } from "@bufbuild/protobuf/wkt";
import { useQuery } from "@connectrpc/connect-query";
import { Link } from "@tanstack/react-router";
import { useState, type ReactNode } from "react";
import { useTranslation } from "react-i18next";
import { RouteStateChip } from "@/components/route-state";
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
    <section aria-labelledby="health-title" className="grid gap-3">
      <h2 id="health-title" className="text-lg font-semibold">{t("health.title")}</h2>
      <div className="grid gap-4 md:grid-cols-2">
        <Agents orgId={orgId} />
        <Routes orgId={orgId} />
        <Certificates orgId={orgId} />
        <Domains orgId={orgId} />
        <Tokens orgId={orgId} />
      </div>
    </section>
  );
}

// Card is one area of the health section: what needs attention in it, or that nothing does.
function Card({ id, title, summary, fine, children }: { id: string; title: string; summary?: string; fine: string; children: ReactNode[] }) {
  return (
    <section aria-labelledby={id} className="grid content-start gap-2 rounded-md border border-border p-3 text-sm">
      <h3 id={id} className="font-medium">{title}</h3>
      {summary && <p>{summary}</p>}
      {children.length === 0 ? <p className="text-muted-foreground">{fine}</p> : <ul aria-label={title} className="grid gap-1">{children}</ul>}
    </section>
  );
}

function Agents({ orgId }: { orgId: string }) {
  const { t } = useTranslation();
  const connectors = (useConnectors(orgId).data ?? []).filter((c) => !c.decommissionTime);
  const gateways = (useGateways(orgId).data ?? []).filter((g) => !g.decommissionTime);
  const seen = (ts: Parameters<typeof when>[0]) => (ts ? t("health.lastSeen", { when: when(ts) }) : t("health.neverSeen"));
  const items = [
    ...gateways.filter((g) => !g.status?.connected).map((g) => (
      <li key={g.id}>
        <Link to="/gateways/$groupId" params={{ groupId: g.gatewayGroupId }} className="underline">{g.name}</Link>
        <span className="ml-2 text-muted-foreground">{g.status?.enrolled ? seen(g.status.lastSeenTime) : t("health.notEnrolled")}</span>
      </li>
    )),
    ...connectors.filter((c) => !c.session?.connected).map((c) => (
      <li key={c.id}>
        <Link to="/connectors/$connectorId" params={{ connectorId: c.id }} className="underline">{c.name}</Link>
        <span className="ml-2 text-muted-foreground">{seen(c.session?.lastSeenTime)}</span>
      </li>
    )),
  ];
  const count = (all: { connected: boolean }[]) => ({ connected: all.filter((a) => a.connected).length, total: all.length });
  const summary = [
    t("health.gateways", count(gateways.map((g) => ({ connected: !!g.status?.connected })))),
    t("health.connectors", count(connectors.map((c) => ({ connected: !!c.session?.connected })))),
  ].join(" · ");
  return <Card id="health-agents" title={t("health.agents")} summary={summary} fine={t("health.agentsFine")}>{items}</Card>;
}

function Routes({ orgId }: { orgId: string }) {
  const { t } = useTranslation();
  const routes = useRoutes(orgId).data ?? [];
  const items = routes
    .filter((r) => r.status && (![RouteState.READY, RouteState.DISABLED].includes(r.status.state) || r.status.rejections.length > 0))
    .map((r) => (
      <li key={r.id} className="flex flex-wrap items-center gap-2">
        <Link to="/routes/$routeId" params={{ routeId: r.id }} className="underline">{r.name}</Link>
        <RouteStateChip state={r.status!.state} />
        {r.status!.rejections.length > 0 && <span className="text-muted-foreground">{t("health.rejected", { count: r.status!.rejections.length })}</span>}
      </li>
    ));
  return <Card id="health-routes" title={t("health.routes")} fine={t("health.routesFine", { count: routes.length })}>{items}</Card>;
}

function Certificates({ orgId }: { orgId: string }) {
  const { t } = useTranslation();
  const [now] = useState(() => Date.now());
  const certs = useCertificates(orgId).data ?? [];
  const items = certs
    .filter((c) => c.status === CertificateStatus.FAILED || (c.notAfter && timestampMs(c.notAfter) - now < soon))
    .map((c) => (
      <li key={c.id}>
        <Link to="/domains" className="underline">{c.sans[0] ?? c.id}</Link>
        <span className="ml-2 text-muted-foreground">
          {c.status === CertificateStatus.FAILED ? t("health.certFailed", { error: c.lastError }) : t("health.expires", { when: when(c.notAfter) })}
        </span>
      </li>
    ));
  return <Card id="health-certs" title={t("health.certificates")} fine={t("health.certsFine")}>{items}</Card>;
}

function Domains({ orgId }: { orgId: string }) {
  const { t } = useTranslation();
  const items = (useDomains(orgId).data ?? []).filter((d) => d.status !== DomainStatus.VERIFIED).map((d) => (
    <li key={d.id}>
      <Link to="/domains" className="underline">{d.wildcard ? `*.${d.fqdn}` : d.fqdn}</Link>
      <span className="ml-2"><DomainStatusLabel status={d.status} /></span>
    </li>
  ));
  return <Card id="health-domains" title={t("health.domains")} fine={t("health.domainsFine")}>{items}</Card>;
}

function Tokens({ orgId }: { orgId: string }) {
  const { t } = useTranslation();
  const [now] = useState(() => Date.now());
  const tokens = useQuery(TokenService.method.listAPITokens, { orgId }).data?.apiTokens ?? [];
  const items = tokens.filter((k) => k.expireTime && timestampMs(k.expireTime) - now < soon).map((k) => (
    <li key={k.id}>
      <Link to="/account" className="underline">{k.name}</Link>
      <span className="ml-2 text-muted-foreground">{t(timestampMs(k.expireTime!) < now ? "health.expired" : "health.expires", { when: when(k.expireTime) })}</span>
    </li>
  ));
  return <Card id="health-tokens" title={t("health.tokens")} fine={t("health.tokensFine")}>{items}</Card>;
}
