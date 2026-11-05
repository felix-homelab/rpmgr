// SPDX-License-Identifier: Apache-2.0

import { create } from "@bufbuild/protobuf";
import { createClient } from "@connectrpc/connect";
import { useMutation, useTransport } from "@connectrpc/connect-query";
import { useQuery, useQueryClient } from "@tanstack/react-query";
import { Globe, Plus } from "lucide-react";
import { useState, type FormEvent } from "react";
import { useTranslation } from "react-i18next";
import { EmptyState } from "@/components/empty-state";
import { Field } from "@/components/field";
import { PageHeader } from "@/components/page-header";
import { Alert } from "@/components/public-page";
import { panel, Row, RowList } from "@/components/row-list";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card } from "@/components/ui/card";
import { Select } from "@/components/ui/input";
import { DnsNameSchema, DnsNameService, type DnsName } from "@/gen/rpmgr/v1/dns_pb";
import { apiError, serverProblems, type Problems } from "@/lib/api-error";
import { largestPage, listAll } from "@/lib/list-all";
import { useGroupNames, useGroups } from "@/routes-data";
import { useOrg } from "@/session";

// useDnsNames reads all of the org's explicit DNS names.
function useDnsNames(orgId: string | undefined) {
  const transport = useTransport();
  return useQuery({
    queryKey: ["dns-names", orgId],
    enabled: !!orgId,
    queryFn: () => listAll(async (pageToken) => {
      const r = await createClient(DnsNameService, transport).listDnsNames({ orgId, pageSize: largestPage, pageToken });
      return { items: r.dnsNames, next: r.nextPageToken };
    }),
  });
}

// wildcardRule is what a name may be: a host name, or a wildcard whose first label is only `*`.
// It checks what the form can before sending; the API decides the rest (docs/15-dns.md, "Concepts").
export function nameProblem(fqdn: string): "empty" | "wildcard" | undefined {
  if (fqdn === "") {
    return "empty";
  }
  return fqdn.includes("*") && !/^\*\.[^*]+$/.test(fqdn) ? "wildcard" : undefined;
}

// DnsNamesPage lists the org's explicit DNS names, each pointing at a gateway group without a
// route, and creates and deletes them (docs/09-web-ui.md, "Domains & certificates"). Any member may
// read them; Owners and Admins change them.
export function DnsNamesPage() {
  const { t } = useTranslation();
  const org = useOrg();
  const names = useDnsNames(org?.orgId);
  const groups = useGroupNames(org?.orgId);
  const admin = org?.role === "owner" || org?.role === "admin";
  const [creating, setCreating] = useState(false);
  return (
    <div className="grid gap-6">
      <PageHeader title={t("dnsNames.title")} description={t("dnsNames.intro")} />
      <Card title={t("dnsNames.names")} actions={admin && <Button size="sm" onClick={() => setCreating(true)}><Plus aria-hidden="true" />{t("dnsNames.add")}</Button>}>
        {names.isError && <Alert>{apiError(t, names.error)}</Alert>}
        {creating && org && <NameForm orgId={org.orgId} onDone={() => setCreating(false)} />}
        {names.data?.length === 0 ? <EmptyState icon={Globe}>{t("dnsNames.none")}</EmptyState> : (
          <RowList>
            {[...(names.data ?? [])].sort((a, b) => a.fqdn.localeCompare(b.fqdn)).map((n) => (
              <NameRow key={n.id} name={n} group={groups.data?.get(n.gatewayGroupId) ?? n.gatewayGroupId} admin={admin} />
            ))}
          </RowList>
        )}
      </Card>
    </div>
  );
}

// NameRow is one name, its group and TTL, and for an Owner or Admin its deletion, after a
// confirmation that names it (U7). The records published for it go with it.
function NameRow({ name: n, group, admin }: { name: DnsName; group: string; admin: boolean }) {
  const { t } = useTranslation();
  const queryClient = useQueryClient();
  const remove = useMutation(DnsNameService.method.deleteDnsName);
  const [asking, setAsking] = useState(false);
  const [error, setError] = useState("");
  async function del() {
    setError("");
    try {
      await remove.mutateAsync({ dnsNameId: n.id, etag: n.etag });
      await queryClient.invalidateQueries();
    } catch (err) {
      setError(apiError(t, err));
    }
  }
  return (
    <Row>
      <div className="flex flex-wrap items-center justify-between gap-x-4 gap-y-2">
        <div className="flex flex-wrap items-center gap-x-3 gap-y-1">
          <span className="font-mono font-medium">{n.fqdn}</span>
          {n.fqdn.startsWith("*.") && <Badge tone="accent">{t("dnsNames.wildcard")}</Badge>}
          <span className="text-muted-foreground">{t("dnsNames.pointsAt", { group })}</span>
          <span className="text-muted-foreground">{n.ttl === 0 ? t("dnsNames.defaultTtl") : t("dnsNames.ttl", { seconds: n.ttl })}</span>
        </div>
        {admin && (asking ? (
          <div className="flex flex-wrap items-center gap-2">
            <span>{t("dnsNames.askDelete", { name: n.fqdn })}</span>
            <Button size="sm" variant="destructive" disabled={remove.isPending} onClick={() => void del()}>{t("dnsNames.deleteConfirm")}</Button>
            <Button size="sm" variant="outline" onClick={() => setAsking(false)}>{t("stepUp.cancel")}</Button>
          </div>
        ) : <Button size="sm" variant="outline" onClick={() => setAsking(true)}>{t("dnsNames.delete")}</Button>)}
      </div>
      {error && <Alert>{error}</Alert>}
    </Row>
  );
}

// NameForm creates a name for a gateway group. A wildcard name has `*` as its whole first label.
function NameForm({ orgId, onDone }: { orgId: string; onDone: () => void }) {
  const { t } = useTranslation();
  const queryClient = useQueryClient();
  const groups = useGroups(orgId);
  const make = useMutation(DnsNameService.method.createDnsName);
  const [requestId] = useState(() => crypto.randomUUID());
  const [form, setForm] = useState({ fqdn: "", group: "", ttl: "" });
  const [error, setError] = useState("");
  const [problems, setProblems] = useState<Problems>({});
  async function save(e: FormEvent) {
    e.preventDefault();
    setError("");
    const fqdn = form.fqdn.trim().toLowerCase().replace(/\.$/, "");
    const ttl = form.ttl.trim() === "" ? 0 : Number(form.ttl);
    const found: Problems = {};
    const bad = nameProblem(fqdn);
    if (bad) {
      found.fqdn = t(`dnsNames.problem.${bad}`);
    }
    if (!(form.group || groups.data?.length === 1)) {
      found.gateway_group_id = t("dnsNames.problem.group");
    }
    if (!Number.isInteger(ttl) || ttl < 0) {
      found.ttl = t("dnsNames.problem.ttl");
    }
    setProblems(found);
    if (Object.keys(found).length > 0) {
      return;
    }
    try {
      await make.mutateAsync({ orgId, requestId, dnsName: create(DnsNameSchema, { fqdn, gatewayGroupId: form.group || groups.data?.[0]?.id, ttl }) });
      await queryClient.invalidateQueries();
      onDone();
    } catch (err) {
      setProblems(serverProblems(t, err));
      setError(apiError(t, err, ["fqdn", "gateway_group_id", "ttl"]));
    }
  }
  const group = form.group || (groups.data?.length === 1 ? groups.data[0]!.id : "");
  return (
    <form onSubmit={save} aria-label={t("dnsNames.addTitle")} className={panel} noValidate>
      <Field label={t("dnsNames.fqdn")} className="max-w-md" required maxLength={253} hint={t("dnsNames.fqdnHint")} error={problems.fqdn}
        value={form.fqdn} onChange={(e) => setForm({ ...form, fqdn: e.target.value })} />
      <div className="grid max-w-md gap-1.5">
        <label htmlFor="dns-name-group" className="required-mark text-sm font-medium">{t("dnsNames.group")}</label>
        <Select id="dns-name-group" required value={group} onChange={(e) => setForm({ ...form, group: e.target.value })}>
          <option value="">{t("dnsNames.chooseGroup")}</option>
          {(groups.data ?? []).map((g) => <option key={g.id} value={g.id}>{g.name}</option>)}
        </Select>
        {problems.gateway_group_id && <p className="text-xs text-destructive">{problems.gateway_group_id}</p>}
      </div>
      <Field label={t("dnsNames.ttlLabel")} className="max-w-md" inputMode="numeric" hint={t("dnsNames.ttlHint")} error={problems.ttl}
        value={form.ttl} onChange={(e) => setForm({ ...form, ttl: e.target.value })} />
      {error && <Alert>{error}</Alert>}
      <div className="flex gap-2">
        <Button type="submit" disabled={make.isPending}>{t("dnsNames.create")}</Button>
        <Button variant="outline" onClick={onDone}>{t("stepUp.cancel")}</Button>
      </div>
    </form>
  );
}
