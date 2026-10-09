// SPDX-License-Identifier: Apache-2.0

import { createClient } from "@connectrpc/connect";
import { useMutation, useQuery as useConnectQuery, useTransport } from "@connectrpc/connect-query";
import { useInfiniteQuery } from "@tanstack/react-query";
import { getRouteApi, useNavigate } from "@tanstack/react-router";
import { useState } from "react";
import { useTranslation } from "react-i18next";
import { Alert } from "@/components/public-page";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { AuditService, type AuditEntry, type AuditVerification } from "@/gen/rpmgr/v1/audit_pb";
import { AuthService } from "@/gen/rpmgr/v1/auth_pb";
import { OrgService } from "@/gen/rpmgr/v1/org_pb";
import { when } from "@/lib/format";
import { useOrg } from "@/session";

const route = getRouteApi("/app/audit");

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
  return (
    <section aria-labelledby="audit-title" className="grid gap-4">
      <h1 id="audit-title" className="text-2xl font-semibold">{t(instance ? "audit.instanceTitle" : "audit.title")}</h1>
      {session.data?.instanceAdmin && (
        <div className="flex gap-2 text-sm" role="group" aria-label={t("audit.which")}>
          <Button size="sm" variant={instance ? "outline" : "default"} aria-pressed={!instance} onClick={() => set({ log: undefined })}>{t("audit.orgLog")}</Button>
          <Button size="sm" variant={instance ? "default" : "outline"} aria-pressed={instance} onClick={() => set({ log: "instance" })}>{t("audit.instanceLog")}</Button>
        </div>
      )}
      <Verify key={instance ? "instance" : "org"} orgId={org?.orgId ?? ""} instance={instance} />
      <form role="search" className="flex flex-wrap items-end gap-2"
        onSubmit={(e) => (e.preventDefault(), set({ action: filters.action.trim() || undefined, actor: filters.actor.trim() || undefined }))}>
        <label className="grid gap-1 text-sm">{t("audit.action")}<Input className="w-72" value={filters.action} onChange={(e) => setFilters({ ...filters, action: e.target.value })} /></label>
        <label className="grid gap-1 text-sm">{t("audit.actor")}<Input className="w-48" value={filters.actor} onChange={(e) => setFilters({ ...filters, actor: e.target.value })} /></label>
        <Button type="submit" size="sm" variant="outline">{t("audit.filter")}</Button>
      </form>
      <ol className="grid gap-1">
        {(entries.data?.pages ?? []).flatMap((p) => p.items).map((e) => <Entry key={e.id} entry={e} actor={name(e.actorId)} />)}
      </ol>
      {entries.data?.pages[0]?.items.length === 0 && <p className="text-sm">{t("audit.none")}</p>}
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
  const tone = e.result === "success" ? "text-ok" : "text-destructive";
  return (
    <li className="rounded-md border border-border px-3 py-2 text-sm">
      <details>
        <summary className="flex cursor-pointer flex-wrap gap-x-3">
          <span className="text-muted-foreground">{when(e.time)}</span>
          <span className="font-medium">{e.action}</span>
          <span>{e.targetType && `${e.targetType} ${e.targetId}`}</span>
          <span>{actor || t(`audit.actorTypes.${e.actorType}`, { defaultValue: e.actorType })}</span>
          <span className={tone}>{t(`audit.results.${e.result}`, { defaultValue: e.result })}</span>
        </summary>
        <dl className="mt-2 grid grid-cols-[max-content_1fr] gap-x-4 gap-y-0.5">
          {([["seq", String(e.seq)], ["actorType", e.actorType], ["credential", e.credentialId], ["authMethod", e.authMethod], ["ip", e.ip],
            ["userAgent", e.userAgent], ["requestId", e.requestId], ["reason", e.reason]] as const).filter(([, v]) => v).map(([k, v]) => (
            <div key={k} className="contents"><dt className="text-muted-foreground">{t(`audit.fields.${k}`)}</dt><dd className="break-all">{v}</dd></div>
          ))}
        </dl>
        {e.diff && <pre className="mt-2 overflow-x-auto rounded bg-muted p-2 font-mono text-xs">{e.diff}</pre>}
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
    <div className="grid gap-1 text-sm">
      <Button size="sm" variant="outline" className="justify-self-start" disabled={org.isPending || inst.isPending} onClick={() => void go()}>{t("audit.verify")}</Button>
      {result && (
        <p role="status" className={result.intact ? "text-ok" : "text-destructive"}>
          <span aria-hidden="true">{result.intact ? "✓ " : "✕ "}</span>
          {result.intact
            ? t("audit.intact", { seq: String(result.headSeq) }) + (result.lastCheckpoint ? ` ${t("audit.checkpoint", { seq: String(result.lastCheckpoint.seq), when: when(result.lastCheckpoint.time) })}` : "")
            : t("audit.broken", { seq: String(result.brokenAt), problem: result.problem })}
        </p>
      )}
      {error && <Alert>{error}</Alert>}
    </div>
  );
}
