// SPDX-License-Identifier: Apache-2.0

import { getRouteApi, Link, useNavigate } from "@tanstack/react-router";
import { Plus, Route as RouteIcon, Search } from "lucide-react";
import { useTranslation } from "react-i18next";
import { EmptyState } from "@/components/empty-state";
import { ManifestButton } from "@/components/manifest";
import { PageHeader } from "@/components/page-header";
import { RouteStateChip, routeStateKey, routeStateKeys } from "@/components/route-state";
import { Button } from "@/components/ui/button";
import { Input, Select } from "@/components/ui/input";
import { Table, TD, TH, THead, TR } from "@/components/ui/table";
import { RouteState, type Route } from "@/gen/rpmgr/v1/route_pb";
import { useOrg } from "@/session";
import { blockedTargets, routeAddress, routeType, routeTypes, useGroupHostnames, useGroupNames, useRoutes } from "@/routes-data";

export const pageSize = 25;

const route = getRouteApi("/app/routes");

// RoutesSearch is the list's state in the URL (docs/09-web-ui.md, U9).
export interface RoutesSearch {
  q?: string;
  type?: string;
  state?: string;
  group?: string;
  page?: number;
}

export function validateRoutesSearch(s: Record<string, unknown>): RoutesSearch {
  const str = (v: unknown) => (typeof v === "string" && v !== "" ? v : undefined);
  const page = Number(s.page);
  return { q: str(s.q), type: str(s.type), state: str(s.state), group: str(s.group), page: Number.isInteger(page) && page > 1 ? page : undefined };
}

// Routes lists the org's routes (docs/09-web-ui.md, "Routes list"): filtered by text, type, state
// and gateway group, sorted by name, a page at a time; each with its observed state.
export function Routes() {
  const { t } = useTranslation();
  const search = route.useSearch();
  const navigate = useNavigate({ from: "/routes" });
  const org = useOrg();
  const routes = useRoutes(org?.orgId);
  const groups = useGroupNames(org?.orgId);
  const hosts = useGroupHostnames(org?.orgId);
  const address = (r: Route) => routeAddress(r, hosts.data?.get(r.gatewayGroupId));
  const set = (patch: Partial<RoutesSearch>) => void navigate({ search: (s: RoutesSearch) => ({ ...s, ...patch, page: patch.page }), replace: true });

  const q = search.q?.toLowerCase() ?? "";
  const shown = (routes.data ?? [])
    .filter((r) => !q || r.name.includes(q) || address(r).some((a) => a.toLowerCase().includes(q)))
    .filter((r) => !search.type || routeType(r) === search.type)
    .filter((r) => !search.state || routeStateKey(r.status?.state ?? RouteState.UNSPECIFIED) === search.state)
    .filter((r) => !search.group || r.gatewayGroupId === search.group)
    .sort((a, b) => a.name.localeCompare(b.name));
  const pages = Math.max(1, Math.ceil(shown.length / pageSize));
  const page = Math.min(search.page ?? 1, pages);
  const rows = shown.slice((page - 1) * pageSize, page * pageSize);

  return (
    <section aria-labelledby="routes-title" className="grid gap-6">
      <PageHeader id="routes-title" title={t("routes.title")} description={t("routes.intro")} actions={<>
        {org && <ManifestButton label={t("manifest.export")} title={t("manifest.ofKind", { what: t("routes.title") })} orgId={org.orgId} kinds={["Route"]} file="routes" />}
        <Button asChild size="sm"><Link to="/routes/new"><Plus aria-hidden="true" />{t("routes.create")}</Link></Button>
      </>} />
      <div className="flex flex-wrap items-end gap-3" role="search">
        <label className="grid gap-1.5 text-xs font-medium text-muted-foreground">
          {t("routes.search")}
          <span className="relative">
            <Search aria-hidden="true" className="pointer-events-none absolute top-1/2 left-3 size-4 -translate-y-1/2" />
            <Input type="search" className="w-72 pl-9 text-foreground" value={search.q ?? ""} onChange={(e) => set({ q: e.target.value || undefined })} />
          </span>
        </label>
        <Filter label={t("routes.type")} value={search.type} onChange={(type) => set({ type })}
          options={routeTypes.map((v) => [v, t(`routeType.${v}`)])} />
        <Filter label={t("routes.state")} value={search.state} onChange={(state) => set({ state })}
          options={routeStateKeys.filter((k) => k !== "unknown").map((k) => [k, t(`routeState.${k}`)])} />
        <Filter label={t("routes.group")} value={search.group} onChange={(group) => set({ group })}
          options={[...(groups.data ?? new Map<string, string>())].map(([id, name]) => [id, name])} />
      </div>
      {routes.isPending ? (
        <p className="text-sm text-muted-foreground">{t("stepUp.loading")}</p>
      ) : routes.data?.length === 0 ? (
        <EmptyState icon={RouteIcon} action={<Button asChild size="sm"><Link to="/routes/new">{t("routes.create")}</Link></Button>}>{t("routes.none")}</EmptyState>
      ) : rows.length === 0 ? (
        <EmptyState action={<Button size="sm" variant="outline" onClick={() => void navigate({ search: {}, replace: true })}>{t("routes.clear")}</Button>}>
          {t("routes.noMatch")}
        </EmptyState>
      ) : (
        <Table>
          <THead>
            <tr>
              {["name", "type", "group", "targets", "state"].map((c) => <TH key={c}>{t(`routes.columns.${c}`)}</TH>)}
            </tr>
          </THead>
          <tbody>
            {rows.map((r) => (
              <TR key={r.id}>
                <TD>
                  <Link to="/routes/$routeId" params={{ routeId: r.id }} className="font-medium hover:underline">{r.name}</Link>
                  {address(r).map((a) => <div key={a} className="text-muted-foreground">{a}</div>)}
                </TD>
                <TD>{t(`routeType.${routeType(r) || "unknown"}`)}</TD>
                <TD>{groups.data?.get(r.gatewayGroupId) ?? r.gatewayGroupId}</TD>
                <TD>
                  {t("routes.ready", { ready: r.status?.targetsReady ?? 0, total: r.status?.targetsTotal ?? 0 })}
                  {blockedTargets(r) > 0 && <div className="text-warn">{t("routes.blocked", { count: blockedTargets(r) })}</div>}
                </TD>
                <TD>
                  <RouteStateChip state={r.status?.state ?? RouteState.UNSPECIFIED} />
                  {(r.status?.rejections.length ?? 0) > 0 && (
                    <div className="mt-1 text-destructive">{t("routes.rejected", { count: r.status?.rejections.length })}</div>
                  )}
                </TD>
              </TR>
            ))}
          </tbody>
        </Table>
      )}
      {rows.length > 0 && (
        <nav aria-label={t("routes.pages")} className="flex items-center gap-2 text-sm">
          <span className="mr-auto text-muted-foreground">
            {t("routes.count", { from: (page - 1) * pageSize + 1, to: (page - 1) * pageSize + rows.length, total: shown.length })}
          </span>
          <Button size="sm" variant="outline" disabled={page <= 1} onClick={() => set({ page: page - 1 > 1 ? page - 1 : undefined })}>{t("routes.previous")}</Button>
          <Button size="sm" variant="outline" disabled={page >= pages} onClick={() => set({ page: page + 1 })}>{t("routes.next")}</Button>
        </nav>
      )}
    </section>
  );
}

function Filter({ label, value, options, onChange }: { label: string; value?: string; options: [string, string][]; onChange: (v?: string) => void }) {
  const { t } = useTranslation();
  return (
    <label className="grid gap-1.5 text-xs font-medium text-muted-foreground">
      {label}
      <Select className="min-w-36 text-foreground" value={value ?? ""} onChange={(e) => onChange(e.target.value || undefined)}>
        <option value="">{t("routes.all")}</option>
        {options.map(([v, l]) => <option key={v} value={v}>{l}</option>)}
      </Select>
    </label>
  );
}
