// SPDX-License-Identifier: Apache-2.0

import { clone, create } from "@bufbuild/protobuf";
import { Code, ConnectError } from "@connectrpc/connect";
import { useMutation } from "@connectrpc/connect-query";
import { useQueryClient } from "@tanstack/react-query";
import { getRouteApi, Link, useNavigate } from "@tanstack/react-router";
import { ChevronLeft, Plus, Server } from "lucide-react";
import { useState, type FormEvent } from "react";
import { useTranslation } from "react-i18next";
import { ApplyStatusView, useLiveApplyStatus } from "@/components/apply-status";
import { EmptyState } from "@/components/empty-state";
import { Field } from "@/components/field";
import { LinesField, trimmed } from "@/components/lines-field";
import { ManifestButton } from "@/components/manifest";
import { PageHeader } from "@/components/page-header";
import { Alert } from "@/components/public-page";
import { Status } from "@/components/status";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card } from "@/components/ui/card";
import { Table, TD, TH, THead, TR } from "@/components/ui/table";
import { GatewayGroupSchema, GatewayService, type Gateway, type GatewayGroup } from "@/gen/rpmgr/v1/gateway_pb";
import { when } from "@/lib/format";
import { GatewayActions, GatewayForm, type Written } from "@/pages/gateway-actions";
import { PortPools } from "@/pages/port-pools";
import { useAgentNames, useGateways, useGroups } from "@/routes-data";
import { useOrg } from "@/session";

// The fields of a gateway group the API changes (internal/apisvc groupFields).
const groupMask = ["name", "region", "public_hostnames", "trusted_proxy_cidrs"];

// GatewayChip says whether a gateway has enrolled and holds a control session, and whether it is
// drained (docs/09-web-ui.md, U8).
export function GatewayChip({ gateway: g }: { gateway: Gateway }) {
  const { t } = useTranslation();
  const [look, key] = !g.status?.enrolled ? ["pending", "notEnrolled"] as const : g.status.connected ? ["ok", "connected"] as const : ["off", "offline"] as const;
  return (
    <span className="flex flex-wrap gap-1.5">
      <Status look={look}>{t(`gateways.state.${key}`)}</Status>
      {!g.enabled && <Badge tone="warn">{t("gateways.drained")}</Badge>}
    </span>
  );
}

// Gateways lists the org's gateway groups with their gateways (docs/09-web-ui.md, "Information
// architecture") and creates a group.
export function Gateways() {
  const { t } = useTranslation();
  const org = useOrg();
  const groups = useGroups(org?.orgId);
  const gateways = useGateways(org?.orgId);
  const [adding, setAdding] = useState(false);
  return (
    <section aria-labelledby="gateways-title" className="grid gap-6">
      <PageHeader id="gateways-title" title={t("gateways.title")} description={t("gateways.intro")} actions={<>
        {org && <ManifestButton label={t("manifest.export")} title={t("manifest.ofKind", { what: t("gateways.title") })} orgId={org.orgId}
          kinds={["GatewayGroup", "Gateway", "PortPool"]} file="gateways" />}
        <Button size="sm" onClick={() => setAdding(true)} disabled={!org}><Plus aria-hidden="true" />{t("gateways.newGroup")}</Button>
      </>} />
      {adding && org && <Card><GroupForm orgId={org.orgId} onCancel={() => setAdding(false)} /></Card>}
      {groups.isPending ? <p className="text-sm text-muted-foreground">{t("stepUp.loading")}</p> : groups.data?.length === 0 ? (
        !adding && <EmptyState icon={Server} action={<Button size="sm" disabled={!org} onClick={() => setAdding(true)}>{t("gateways.newGroup")}</Button>}>
          {t("gateways.noGroups")}
        </EmptyState>
      ) : (
        <Table>
          <THead>
            <tr>{["name", "region", "hostnames", "gateways"].map((c) => <TH key={c}>{t(`gateways.columns.${c}`)}</TH>)}</tr>
          </THead>
          <tbody>
            {[...(groups.data ?? [])].sort((a, b) => a.name.localeCompare(b.name)).map((g) => {
              const of = (gateways.data ?? []).filter((gw) => gw.gatewayGroupId === g.id);
              return (
                <TR key={g.id}>
                  <TD><Link to="/gateways/$groupId" params={{ groupId: g.id }} className="font-medium hover:underline">{g.name}</Link></TD>
                  <TD>{g.region}</TD>
                  <TD className="text-muted-foreground">{g.publicHostnames.join(", ")}</TD>
                  <TD>{t("gateways.count", { connected: of.filter((gw) => gw.status?.connected).length, total: of.length })}</TD>
                </TR>
              );
            })}
          </tbody>
        </Table>
      )}
    </section>
  );
}

// GroupForm creates a gateway group, or with group changes one: the group as read with the form's
// fields, their mask and its etag (U1).
export function GroupForm({ orgId, group, onCancel }: { orgId: string; group?: GatewayGroup; onCancel?: () => void }) {
  const { t } = useTranslation();
  const queryClient = useQueryClient();
  const navigate = useNavigate();
  const createGroup = useMutation(GatewayService.method.createGatewayGroup);
  const update = useMutation(GatewayService.method.updateGatewayGroup);
  const [requestId] = useState(() => crypto.randomUUID());
  const [form, setForm] = useState({
    name: group?.name ?? "", region: group?.region ?? "", hostnames: group?.publicHostnames ?? [], cidrs: group?.trustedProxyCidrs ?? [],
  });
  const [message, setMessage] = useState<{ tone: "info" | "error"; text: string }>();
  async function save(e: FormEvent) {
    e.preventDefault();
    setMessage(undefined);
    const next = group ? clone(GatewayGroupSchema, group) : create(GatewayGroupSchema);
    Object.assign(next, { name: form.name.trim(), region: form.region.trim(), publicHostnames: trimmed(form.hostnames), trustedProxyCidrs: trimmed(form.cidrs) });
    try {
      if (group) {
        await update.mutateAsync({ gatewayGroup: next, updateMask: { paths: groupMask }, etag: group.etag });
        setMessage({ tone: "info", text: t("account.saved") });
      } else {
        const res = await createGroup.mutateAsync({ orgId, gatewayGroup: next, requestId });
        await navigate({ to: "/gateways/$groupId", params: { groupId: res.gatewayGroup?.id ?? "" } });
      }
      await queryClient.invalidateQueries();
    } catch (err) {
      const e = ConnectError.from(err);
      setMessage({ tone: "error", text: e.code === Code.FailedPrecondition && group ? t("connectors.changed") : e.code === Code.InvalidArgument || e.code === Code.AlreadyExists ? e.rawMessage : t("link.failed", { message: e.rawMessage }) });
    }
  }
  return (
    <form onSubmit={save} aria-label={t(group ? "gateways.settings" : "gateways.newGroup")} className="grid max-w-xl gap-4" noValidate>
      <Field label={t("routeForm.fields.name")} value={form.name} onChange={(e) => setForm({ ...form, name: e.target.value })} />
      <Field label={t("gateways.columns.region")} value={form.region} onChange={(e) => setForm({ ...form, region: e.target.value })} />
      <LinesField label={t("gateways.columns.hostnames")} hint={t("gateways.hostnamesHint")} value={form.hostnames} onChange={(hostnames) => setForm({ ...form, hostnames })} />
      <LinesField label={t("gateways.cidrs")} hint={t("gateways.cidrsHint")} value={form.cidrs} onChange={(cidrs) => setForm({ ...form, cidrs })} />
      {message && <Alert tone={message.tone}>{message.text}</Alert>}
      <div className="flex gap-2">
        <Button type="submit" disabled={createGroup.isPending || update.isPending}>{t(group ? "routeForm.save" : "gateways.create")}</Button>
        {onCancel && <Button variant="outline" onClick={onCancel}>{t("stepUp.cancel")}</Button>}
      </div>
    </form>
  );
}

const page = getRouteApi("/app/gateways/$groupId");

// GatewayGroupPage shows a group's gateways with their status, and its settings.
export function GatewayGroupPage() {
  const { t } = useTranslation();
  const { groupId } = page.useParams();
  const org = useOrg();
  const groups = useGroups(org?.orgId);
  const gateways = useGateways(org?.orgId);
  const group = groups.data?.find((g) => g.id === groupId);
  const names = useAgentNames(org?.orgId);
  const queryClient = useQueryClient();
  const [editing, setEditing] = useState<string>(); // a gateway's ID, or "new"
  const [write, setWrite] = useState<Written>();
  const live = useLiveApplyStatus(org?.orgId ?? "", write?.revision, write?.status);
  const done = async (w: Written) => {
    setEditing(undefined);
    setWrite(w);
    await queryClient.invalidateQueries();
  };
  if (!group || !org) {
    return <p className="text-sm text-muted-foreground">{groups.isPending ? t("stepUp.loading") : t("gateways.notFound")}</p>;
  }
  const members = (gateways.data ?? []).filter((g) => g.gatewayGroupId === group.id).sort((a, b) => a.slot - b.slot);
  return (
    <div className="grid gap-6">
      <div className="grid gap-2">
        <Link to="/gateways" className="inline-flex w-fit items-center gap-1 text-sm text-muted-foreground hover:text-foreground">
          <ChevronLeft aria-hidden="true" className="size-4" />{t("gateways.back")}
        </Link>
        <PageHeader title={t("gateways.groupTitle", { name: group.name })} description={group.region || undefined}
          actions={<ManifestButton label={t("manifest.yaml")} title={t("manifest.of", { name: group.name })} orgId={org.orgId} ids={[group.id, ...members.map((g) => g.id)]} file={group.name} />} />
      </div>
      {live && <ApplyStatusView status={live} revision={write?.revision} name={(id) => names.data?.get(id) || id} />}
      <Card title={t("gateways.members")}>
        {members.length === 0 ? <p className="text-sm text-muted-foreground">{t("gateways.noGateways")}</p> : (
          <Table framed={false}>
            <THead>
              <tr>{["name", "slot", "endpoints", "state", "version", "lastSeen", "actions"].map((c) => <TH key={c}>{t(`gateways.gw.${c}`)}</TH>)}</tr>
            </THead>
            <tbody>
              {members.map((g) => (
                <TR key={g.id}>
                  <TD className="font-medium">{g.name}</TD>
                  <TD>{g.slot}</TD>
                  <TD className="font-mono text-xs">{g.tunnelEndpoints.join(", ")}</TD>
                  <TD><GatewayChip gateway={g} /></TD>
                  <TD>{g.status?.version}</TD>
                  <TD>{when(g.status?.lastSeenTime)}</TD>
                  <TD><GatewayActions orgId={org.orgId} gateway={g} onEdit={() => setEditing(g.id)} onDone={(w) => void done(w)} /></TD>
                </TR>
              ))}
            </tbody>
          </Table>
        )}
        {editing ? (
          <GatewayForm key={editing} orgId={org.orgId} groupId={group.id} gateway={members.find((g) => g.id === editing)}
            onDone={(w) => void done(w)} onCancel={() => setEditing(undefined)} />
        ) : (
          <Button size="sm" variant="outline" className="justify-self-start" onClick={() => setEditing("new")}><Plus aria-hidden="true" />{t("gwActions.addButton")}</Button>
        )}
      </Card>
      <PortPools orgId={org.orgId} groupId={group.id} />
      <Card title={t("gateways.settings")}>
        <GroupForm key={group.etag} orgId={org.orgId} group={group} />
      </Card>
    </div>
  );
}
