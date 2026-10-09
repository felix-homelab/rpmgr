// SPDX-License-Identifier: Apache-2.0

import { getRouteApi, Link, useNavigate } from "@tanstack/react-router";
import { useTranslation } from "react-i18next";
import { ManifestButton } from "@/components/manifest";
import { RouteStateChip, routeStateKey, routeStateKeys } from "@/components/route-state";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { RouteState } from "@/gen/rpmgr/v1/route_pb";
import { useOrg } from "@/session";
import { blockedTargets, routeAddress, routeType, routeTypes, useGroupNames, useRoutes } from "@/routes-data";

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
  const set = (patch: Partial<RoutesSearch>) => void navigate({ search: (s: RoutesSearch) => ({ ...s, ...patch, page: patch.page }), replace: true });

  const q = search.q?.toLowerCase() ?? "";
  const shown = (routes.data ?? [])
    .filter((r) => !q || r.name.includes(q) || routeAddress(r).some((a) => a.toLowerCase().includes(q)))
    .filter((r) => !search.type || routeType(r) === search.type)
    .filter((r) => !search.state || routeStateKey(r.status?.state ?? RouteState.UNSPECIFIED) === search.state)
    .filter((r) => !search.group || r.gatewayGroupId === search.group)
    .sort((a, b) => a.name.localeCompare(b.name));
  const pages = Math.max(1, Math.ceil(shown.length / pageSize));
  const page = Math.min(search.page ?? 1, pages);
  const rows = shown.slice((page - 1) * pageSize, page * pageSize);

  return (
    <section aria-labelledby="routes-title" className="grid gap-4">
      <div className="flex items-center gap-4">
        <h1 id="routes-title" className="text-2xl font-semibold">{t("routes.title")}</h1>
        <Button asChild size="sm" className="ml-auto"><Link to="/routes/new">{t("routes.create")}</Link></Button>
        {org && <ManifestButton label={t("manifest.export")} title={t("manifest.ofKind", { what: t("routes.title") })} orgId={org.orgId} kinds={["Route"]} file="routes" />}
      </div>
      <div className="flex flex-wrap items-end gap-3" role="search">
        <label className="grid gap-1 text-sm">
          {t("routes.search")}
          <Input type="search" className="w-64" value={search.q ?? ""} onChange={(e) => set({ q: e.target.value || undefined })} />
        </label>
        <Filter label={t("routes.type")} value={search.type} onChange={(type) => set({ type })}
          options={routeTypes.map((v) => [v, t(`routeType.${v}`)])} />
        <Filter label={t("routes.state")} value={search.state} onChange={(state) => set({ state })}
          options={routeStateKeys.filter((k) => k !== "unknown").map((k) => [k, t(`routeState.${k}`)])} />
        <Filter label={t("routes.group")} value={search.group} onChange={(group) => set({ group })}
          options={[...(groups.data ?? new Map<string, string>())].map(([id, name]) => [id, name])} />
      </div>
      {routes.isPending ? (
        <p>{t("stepUp.loading")}</p>
      ) : (
        <table className="w-full text-left text-sm">
          <thead className="text-muted-foreground">
            <tr>
              {["name", "type", "group", "targets", "state"].map((c) => (
                <th key={c} scope="col" className="py-1 font-medium">{t(`routes.columns.${c}`)}</th>
              ))}
            </tr>
          </thead>
          <tbody>
            {rows.map((r) => (
              <tr key={r.id} className="border-t border-border align-top">
                <td className="py-2">
                  <Link to="/routes/$routeId" params={{ routeId: r.id }} className="font-medium underline-offset-2 hover:underline">{r.name}</Link>
                  {routeAddress(r).map((a) => <div key={a} className="text-muted-foreground">{a}</div>)}
                </td>
                <td className="py-2">{t(`routeType.${routeType(r) || "unknown"}`)}</td>
                <td className="py-2">{groups.data?.get(r.gatewayGroupId) ?? r.gatewayGroupId}</td>
                <td className="py-2">
                  {t("routes.ready", { ready: r.status?.targetsReady ?? 0, total: r.status?.targetsTotal ?? 0 })}
                  {blockedTargets(r) > 0 && <div className="text-warn">{t("routes.blocked", { count: blockedTargets(r) })}</div>}
                </td>
                <td className="py-2">
                  <RouteStateChip state={r.status?.state ?? RouteState.UNSPECIFIED} />
                  {(r.status?.rejections.length ?? 0) > 0 && (
                    <div className="text-destructive">{t("routes.rejected", { count: r.status?.rejections.length })}</div>
                  )}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
      <nav aria-label={t("routes.pages")} className="flex items-center gap-3 text-sm">
        <span>{t("routes.count", { from: shown.length ? (page - 1) * pageSize + 1 : 0, to: (page - 1) * pageSize + rows.length, total: shown.length })}</span>
        <Button size="sm" variant="outline" disabled={page <= 1} onClick={() => set({ page: page - 1 > 1 ? page - 1 : undefined })}>{t("routes.previous")}</Button>
        <Button size="sm" variant="outline" disabled={page >= pages} onClick={() => set({ page: page + 1 })}>{t("routes.next")}</Button>
      </nav>
    </section>
  );
}

function Filter({ label, value, options, onChange }: { label: string; value?: string; options: [string, string][]; onChange: (v?: string) => void }) {
  const { t } = useTranslation();
  return (
    <label className="grid gap-1 text-sm">
      {label}
      <select className="h-9 rounded-md border border-border bg-background px-2" value={value ?? ""} onChange={(e) => onChange(e.target.value || undefined)}>
        <option value="">{t("routes.all")}</option>
        {options.map(([v, l]) => <option key={v} value={v}>{l}</option>)}
      </select>
    </label>
  );
}
