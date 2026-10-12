// SPDX-License-Identifier: Apache-2.0

import { getRouteApi, Link, useNavigate } from "@tanstack/react-router";
import { Cable, Plus, Search } from "lucide-react";
import { useTranslation } from "react-i18next";
import { EmptyState } from "@/components/empty-state";
import { ManifestButton } from "@/components/manifest";
import { PageHeader } from "@/components/page-header";
import { Status } from "@/components/status";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Input, Select } from "@/components/ui/input";
import { Table, TD, TH, THead, TR } from "@/components/ui/table";
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
  // Whether the enroll dialog is open, so the command palette can open it.
  enroll?: true;
}

export function validateConnectorsSearch(s: Record<string, unknown>): ConnectorsSearch {
  return {
    q: typeof s.q === "string" && s.q !== "" ? s.q : undefined,
    session: s.session === "connected" || s.session === "offline" ? s.session : undefined,
    enroll: s.enroll === true || s.enroll === "true" ? true : undefined,
  };
}

// SessionChip says whether a connector's control session is up, with an icon and text (U8).
export function SessionChip({ connector }: { connector: Connector }) {
  const { t } = useTranslation();
  const up = connector.session?.connected ?? false;
  return <Status look={up ? "ok" : "off"}>{t(up ? "connectors.connected" : "connectors.offline")}</Status>;
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
  const set = (patch: Partial<ConnectorsSearch>) => void navigate({ search: (s: ConnectorsSearch) => ({ ...s, ...patch }), replace: true });
  const q = search.q?.toLowerCase() ?? "";
  const rows = (list.data ?? [])
    .filter((c) => !q || c.name.includes(q) || Object.entries(c.labels).some(([k, v]) => `${k}=${v}`.includes(q)))
    .filter((c) => !search.session || (c.session?.connected ?? false) === (search.session === "connected"))
    .sort((a, b) => a.name.localeCompare(b.name));
  return (
    <section aria-labelledby="connectors-title" className="grid gap-6">
      <PageHeader id="connectors-title" title={t("connectors.title")} description={t("connectors.intro")} actions={<>
        {org && <ManifestButton label={t("manifest.export")} title={t("manifest.ofKind", { what: t("connectors.title") })} orgId={org.orgId} kinds={["Connector"]} file="connectors" />}
        <Button size="sm" disabled={!org} onClick={() => set({ enroll: true })}><Plus aria-hidden="true" />{t("enroll.open")}</Button>
      </>} />
      {/* The dialog tells new connectors from the known ones, so it waits for the list. */}
      {search.enroll && org && list.data && <EnrollDialog orgId={org.orgId} known={new Set(list.data.map((c) => c.id))} onClose={() => set({ enroll: undefined })} />}
      <div className="flex flex-wrap items-end gap-3" role="search">
        <label className="grid gap-1.5 text-xs font-medium text-muted-foreground">
          {t("routes.search")}
          <span className="relative">
            <Search aria-hidden="true" className="pointer-events-none absolute top-1/2 left-3 size-4 -translate-y-1/2" />
            <Input type="search" className="w-72 pl-9 text-foreground" value={search.q ?? ""} onChange={(e) => set({ q: e.target.value || undefined })} />
          </span>
        </label>
        <label className="grid gap-1.5 text-xs font-medium text-muted-foreground">
          {t("connectors.session")}
          <Select className="min-w-36 text-foreground" value={search.session ?? ""}
            onChange={(e) => set({ session: (e.target.value || undefined) as ConnectorsSearch["session"] })}>
            <option value="">{t("routes.all")}</option>
            <option value="connected">{t("connectors.connected")}</option>
            <option value="offline">{t("connectors.offline")}</option>
          </Select>
        </label>
      </div>
      {list.isPending ? <p className="text-sm text-muted-foreground">{t("stepUp.loading")}</p> : list.data?.length === 0 ? (
        <EmptyState icon={Cable} action={<Button size="sm" disabled={!org} onClick={() => set({ enroll: true })}>{t("enroll.open")}</Button>}>
          {t("connectors.noneYet")}
        </EmptyState>
      ) : rows.length === 0 ? (
        <EmptyState action={<Button size="sm" variant="outline" onClick={() => set({ q: undefined, session: undefined })}>{t("routes.clear")}</Button>}>
          {t("connectors.none")}
        </EmptyState>
      ) : (
        <Table>
          <THead>
            <tr>{["name", "session", "version", "lastSeen", "labels"].map((c) => <TH key={c}>{t(`connectors.columns.${c}`)}</TH>)}</tr>
          </THead>
          <tbody>
            {rows.map((c) => (
              <TR key={c.id}>
                <TD>
                  <span className="flex flex-wrap items-center gap-2">
                    <Link to="/connectors/$connectorId" params={{ connectorId: c.id }} className="font-medium hover:underline">{c.name}</Link>
                    {!c.enabled && <Badge>{t("route.disabled")}</Badge>}
                    {c.ephemeral && <Badge>{t("connectors.ephemeral")}</Badge>}
                  </span>
                </TD>
                <TD><SessionChip connector={c} /></TD>
                <TD>{c.session?.version}</TD>
                <TD>{when(c.session?.lastSeenTime)}</TD>
                <TD className="text-muted-foreground">{Object.entries(c.labels).map(([k, v]) => `${k}=${v}`).join(", ")}</TD>
              </TR>
            ))}
          </tbody>
        </Table>
      )}
      {org && <EnrollmentTokens orgId={org.orgId} />}
    </section>
  );
}
