// SPDX-License-Identifier: Apache-2.0

import { createClient } from "@connectrpc/connect";
import { useMutation, useQuery as useConnectQuery, useTransport } from "@connectrpc/connect-query";
import { useInfiniteQuery } from "@tanstack/react-query";
import { getRouteApi, useNavigate } from "@tanstack/react-router";
import { CircleCheck, CircleX, ScrollText } from "lucide-react";
import { useState } from "react";
import { useTranslation } from "react-i18next";
import { EmptyState } from "@/components/empty-state";
import { PageHeader } from "@/components/page-header";
import { Alert } from "@/components/public-page";
import { Status, type Look } from "@/components/status";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { AuditService, type AuditEntry, type AuditVerification } from "@/gen/rpmgr/v1/audit_pb";
import { AuthService } from "@/gen/rpmgr/v1/auth_pb";
import { OrgService } from "@/gen/rpmgr/v1/org_pb";
import { when } from "@/lib/format";
import { useOrg } from "@/session";

const route = getRouteApi("/app/audit");

// The look of each result an entry records.
const results: Record<string, Look> = { success: "ok", failure: "failed", denied: "alert" };

export interface AuditSearch {
  log?: "instance";
  action?: string;
  actor?: string;
}

export function validateAuditSearch(s: Record<string, unknown>): AuditSearch {
  const str = (v: unknown) => (typeof v === "string" && v !== "" ? v : undefined);
  return { log: s.log === "instance" ? "instance" : undefined, action: str(s.action), actor: str(s.actor) };
}

// Audit shows the org's audit log, or the instance's to the Instance Admin, newest first, filtered by
// action and actor with the filters in the URL (U9), and verifies its hash chain on request
// (docs/09-web-ui.md, "Information architecture"; docs/04-security.md, "Audit log").
export function Audit() {
  const { t } = useTranslation();
  const search = route.useSearch();
  const navigate = useNavigate({ from: "/audit" });
  const org = useOrg();
  const transport = useTransport();
  const session = useConnectQuery(AuthService.method.getSession, {});
  const members = useConnectQuery(OrgService.method.listMembers, { orgId: org?.orgId ?? "" }, { enabled: !!org });
  const instance = search.log === "instance";
  const set = (patch: Partial<AuditSearch>) => void navigate({ search: (s: AuditSearch) => ({ ...s, ...patch }), replace: true });
  const entries = useInfiniteQuery({
    queryKey: ["audit", instance ? "instance" : org?.orgId, search.action, search.actor],
    enabled: instance || !!org,
    initialPageParam: "",
    getNextPageParam: (last: { next: string }) => last.next || undefined,
    queryFn: async ({ pageParam }) => {
      const api = createClient(AuditService, transport);
      const filter = { pageSize: 100, pageToken: pageParam, action: search.action ?? "", actorId: search.actor ?? "" };
      const r = instance ? await api.listInstanceAuditEntries(filter) : await api.listAuditEntries({ ...filter, orgId: org?.orgId });
      return { items: r.entries, next: r.nextPageToken };
    },
  });
  const name = (id: string) => members.data?.members.find((m) => m.userId === id)?.displayName || id;
  const [filters, setFilters] = useState({ action: search.action ?? "", actor: search.actor ?? "" });
  const shown = (entries.data?.pages ?? []).flatMap((p) => p.items);
  const label = "grid gap-1.5 text-xs font-medium text-muted-foreground";
  return (
    <section aria-labelledby="audit-title" className="grid gap-6">
      <PageHeader id="audit-title" title={t(instance ? "audit.instanceTitle" : "audit.title")} description={t("audit.intro")}
        actions={session.data?.instanceAdmin && (
          <div className="flex rounded-lg border border-border bg-card p-0.5 text-sm" role="group" aria-label={t("audit.which")}>
            <Button size="sm" variant={instance ? "ghost" : "secondary"} aria-pressed={!instance} onClick={() => set({ log: undefined })}>{t("audit.orgLog")}</Button>
            <Button size="sm" variant={instance ? "secondary" : "ghost"} aria-pressed={instance} onClick={() => set({ log: "instance" })}>{t("audit.instanceLog")}</Button>
          </div>
        )} />
      <div className="flex flex-wrap items-end justify-between gap-3">
        <form role="search" className="flex flex-wrap items-end gap-3"
          onSubmit={(e) => (e.preventDefault(), set({ action: filters.action.trim() || undefined, actor: filters.actor.trim() || undefined }))}>
          <label className={label}>{t("audit.action")}<Input className="w-72 text-foreground" value={filters.action} onChange={(e) => setFilters({ ...filters, action: e.target.value })} /></label>
          <label className={label}>{t("audit.actor")}<Input className="w-48 text-foreground" value={filters.actor} onChange={(e) => setFilters({ ...filters, actor: e.target.value })} /></label>
          <Button type="submit" variant="outline">{t("audit.filter")}</Button>
        </form>
        <Verify key={instance ? "instance" : "org"} orgId={org?.orgId ?? ""} instance={instance} />
      </div>
      {shown.length > 0 && (
        <ol className="divide-y divide-border rounded-xl border border-border bg-card shadow-xs">
          {shown.map((e) => <Entry key={e.id} entry={e} actor={name(e.actorId)} />)}
        </ol>
      )}
      {entries.data?.pages[0]?.items.length === 0 && <EmptyState icon={ScrollText}>{t("audit.none")}</EmptyState>}
      {entries.hasNextPage && (
        <Button variant="outline" size="sm" className="justify-self-start" disabled={entries.isFetchingNextPage} onClick={() => void entries.fetchNextPage()}>
          {t("audit.more")}
        </Button>
      )}
    </section>
  );
}

// Entry is one audit entry; its details, with the redacted request, open below it.
function Entry({ entry: e, actor }: { entry: AuditEntry; actor: string }) {
  const { t } = useTranslation();
  return (
    <li className="px-5 py-3 text-sm">
      <details>
        <summary className="flex cursor-pointer flex-wrap items-center gap-x-4 gap-y-1">
          <span className="text-muted-foreground tabular-nums">{when(e.time)}</span>
          <span className="font-medium break-all">{e.action}</span>
          <span className="text-muted-foreground">{e.targetType && `${e.targetType} ${e.targetId}`}</span>
          <span>{actor || t(`audit.actorTypes.${e.actorType}`, { defaultValue: e.actorType })}</span>
          <Status look={results[e.result] ?? "unknown"}>{t(`audit.results.${e.result}`, { defaultValue: e.result })}</Status>
        </summary>
        <dl className="mt-3 grid grid-cols-[max-content_1fr] gap-x-4 gap-y-1">
          {([["seq", String(e.seq)], ["actorType", e.actorType], ["credential", e.credentialId], ["authMethod", e.authMethod], ["ip", e.ip],
            ["userAgent", e.userAgent], ["requestId", e.requestId], ["reason", e.reason]] as const).filter(([, v]) => v).map(([k, v]) => (
            <div key={k} className="contents"><dt className="text-muted-foreground">{t(`audit.fields.${k}`)}</dt><dd className="break-all">{v}</dd></div>
          ))}
        </dl>
        {/* The request is one line of JSON, often long: it wraps, so that it never widens the page. */}
        {e.diff && <pre className="mt-3 rounded-lg bg-muted p-3 font-mono text-xs whitespace-pre-wrap wrap-anywhere">{e.diff}</pre>}
      </details>
    </li>
  );
}

// Verify checks the log's hash chain from its last checkpoint and says whether it is intact.
function Verify({ orgId, instance }: { orgId: string; instance: boolean }) {
  const { t } = useTranslation();
  const org = useMutation(AuditService.method.verifyAuditChain);
  const inst = useMutation(AuditService.method.verifyInstanceAuditChain);
  const [result, setResult] = useState<AuditVerification>();
  const [error, setError] = useState("");
  async function go() {
    setError("");
    try {
      const r = instance ? await inst.mutateAsync({}) : await org.mutateAsync({ orgId });
      setResult(r.verification);
    } catch (err) {
      setError(String((err as Error).message));
    }
  }
  return (
    <div className="grid w-full gap-2 text-sm sm:w-auto sm:max-w-md sm:justify-items-end">
      <Button variant="outline" disabled={org.isPending || inst.isPending} onClick={() => void go()}>{t("audit.verify")}</Button>
      {result && (
        <p role="status" className={`flex items-start gap-2 ${result.intact ? "text-ok" : "text-destructive"}`}>
          {result.intact ? <CircleCheck aria-hidden="true" className="mt-0.5 size-4 shrink-0" /> : <CircleX aria-hidden="true" className="mt-0.5 size-4 shrink-0" />}
          <span>{result.intact
            ? t("audit.intact", { seq: String(result.headSeq) }) + (result.lastCheckpoint ? ` ${t("audit.checkpoint", { seq: String(result.lastCheckpoint.seq), when: when(result.lastCheckpoint.time) })}` : "")
            : t("audit.broken", { seq: String(result.brokenAt), problem: result.problem })}</span>
        </p>
      )}
      {error && <Alert>{error}</Alert>}
    </div>
  );
}
