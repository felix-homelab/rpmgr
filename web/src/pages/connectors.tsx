// SPDX-License-Identifier: Apache-2.0

import { getRouteApi, Link, useNavigate } from "@tanstack/react-router";
import { useState } from "react";
import { useTranslation } from "react-i18next";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import type { Connector } from "@/gen/rpmgr/v1/connector_pb";
import { when } from "@/lib/format";
import { EnrollDialog } from "@/pages/enroll";
import { EnrollmentTokens } from "@/pages/enrollment-tokens";
import { useConnectors } from "@/routes-data";
import { useOrg } from "@/session";

const route = getRouteApi("/app/connectors");

export interface ConnectorsSearch {
  q?: string;
  session?: "connected" | "offline";
}

export function validateConnectorsSearch(s: Record<string, unknown>): ConnectorsSearch {
  return {
    q: typeof s.q === "string" && s.q !== "" ? s.q : undefined,
    session: s.session === "connected" || s.session === "offline" ? s.session : undefined,
  };
}

// SessionChip says whether a connector's control session is up, with an icon and text (U8).
export function SessionChip({ connector }: { connector: Connector }) {
  const { t } = useTranslation();
  const up = connector.session?.connected ?? false;
  return (
    <span className={up ? "text-ok" : "text-muted-foreground"}>
      <span aria-hidden="true">{up ? "●" : "○"} </span>
      {t(up ? "connectors.connected" : "connectors.offline")}
    </span>
  );
}

// Connectors lists the org's connectors in service (docs/09-web-ui.md, "Information
// architecture"): filtered by name or label and by session, sorted by name, with the filters in
// the URL (U9).
export function Connectors() {
  const { t } = useTranslation();
  const search = route.useSearch();
  const navigate = useNavigate({ from: "/connectors" });
  const org = useOrg();
  const list = useConnectors(org?.orgId);
  const [enrolling, setEnrolling] = useState(false);
  const set = (patch: Partial<ConnectorsSearch>) => void navigate({ search: (s: ConnectorsSearch) => ({ ...s, ...patch }), replace: true });
  const q = search.q?.toLowerCase() ?? "";
  const rows = (list.data ?? [])
    .filter((c) => !q || c.name.includes(q) || Object.entries(c.labels).some(([k, v]) => `${k}=${v}`.includes(q)))
    .filter((c) => !search.session || (c.session?.connected ?? false) === (search.session === "connected"))
    .sort((a, b) => a.name.localeCompare(b.name));
  return (
    <section aria-labelledby="connectors-title" className="grid gap-4">
      <div className="flex items-center gap-4">
        <h1 id="connectors-title" className="text-2xl font-semibold">{t("connectors.title")}</h1>
        <Button size="sm" className="ml-auto" disabled={!org} onClick={() => setEnrolling(true)}>{t("enroll.open")}</Button>
      </div>
      {enrolling && org && <EnrollDialog orgId={org.orgId} known={new Set((list.data ?? []).map((c) => c.id))} onClose={() => setEnrolling(false)} />}
      <div className="flex flex-wrap items-end gap-3" role="search">
        <label className="grid gap-1 text-sm">
          {t("routes.search")}
          <Input type="search" className="w-64" value={search.q ?? ""} onChange={(e) => set({ q: e.target.value || undefined })} />
        </label>
        <label className="grid gap-1 text-sm">
          {t("connectors.session")}
          <select className="h-9 rounded-md border border-border bg-background px-2" value={search.session ?? ""}
            onChange={(e) => set({ session: (e.target.value || undefined) as ConnectorsSearch["session"] })}>
            <option value="">{t("routes.all")}</option>
            <option value="connected">{t("connectors.connected")}</option>
            <option value="offline">{t("connectors.offline")}</option>
          </select>
        </label>
      </div>
      {list.isPending ? <p>{t("stepUp.loading")}</p> : (
        <table className="w-full text-left text-sm">
          <thead className="text-muted-foreground">
            <tr>{["name", "session", "version", "lastSeen", "labels"].map((c) => <th key={c} scope="col" className="py-1 font-medium">{t(`connectors.columns.${c}`)}</th>)}</tr>
          </thead>
          <tbody>
            {rows.map((c) => (
              <tr key={c.id} className="border-t border-border align-top">
                <td className="py-2">
                  <Link to="/connectors/$connectorId" params={{ connectorId: c.id }} className="font-medium underline-offset-2 hover:underline">{c.name}</Link>
                  {!c.enabled && <span className="ml-2 text-muted-foreground">({t("route.disabled")})</span>}
                  {c.ephemeral && <span className="ml-2 text-muted-foreground">({t("connectors.ephemeral")})</span>}
                </td>
                <td className="py-2"><SessionChip connector={c} /></td>
                <td className="py-2">{c.session?.version}</td>
                <td className="py-2">{when(c.session?.lastSeenTime)}</td>
                <td className="py-2">{Object.entries(c.labels).map(([k, v]) => `${k}=${v}`).join(", ")}</td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
      {list.data && rows.length === 0 && <p className="text-sm">{t("connectors.none")}</p>}
      {org && <EnrollmentTokens orgId={org.orgId} />}
    </section>
  );
}
