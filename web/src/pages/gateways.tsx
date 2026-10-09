// SPDX-License-Identifier: Apache-2.0

import { clone, create } from "@bufbuild/protobuf";
import { Code, ConnectError } from "@connectrpc/connect";
import { useMutation } from "@connectrpc/connect-query";
import { useQueryClient } from "@tanstack/react-query";
import { getRouteApi, Link, useNavigate } from "@tanstack/react-router";
import { useState, type FormEvent } from "react";
import { useTranslation } from "react-i18next";
import { ApplyStatusView, useLiveApplyStatus } from "@/components/apply-status";
import { Field } from "@/components/field";
import { LinesField, trimmed } from "@/components/lines-field";
import { Alert } from "@/components/public-page";
import { Button } from "@/components/ui/button";
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
  const [icon, key, tone] = !g.status?.enrolled ? ["◌", "notEnrolled", "text-muted-foreground"]
    : g.status.connected ? ["●", "connected", "text-ok"] : ["○", "offline", "text-muted-foreground"];
  return (
    <span className={tone}>
      <span aria-hidden="true">{icon} </span>{t(`gateways.state.${key}`)}{!g.enabled && ` · ${t("gateways.drained")}`}
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
    <section aria-labelledby="gateways-title" className="grid gap-4">
      <div className="flex items-center gap-4">
        <h1 id="gateways-title" className="text-2xl font-semibold">{t("gateways.title")}</h1>
        <Button size="sm" className="ml-auto" onClick={() => setAdding(true)} disabled={!org}>{t("gateways.newGroup")}</Button>
      </div>
      {adding && org && <GroupForm orgId={org.orgId} onCancel={() => setAdding(false)} />}
      {groups.isPending ? <p>{t("stepUp.loading")}</p> : (
        <table className="w-full text-left text-sm">
          <thead className="text-muted-foreground">
            <tr>{["name", "region", "hostnames", "gateways"].map((c) => <th key={c} scope="col" className="py-1 font-medium">{t(`gateways.columns.${c}`)}</th>)}</tr>
          </thead>
          <tbody>
            {[...(groups.data ?? [])].sort((a, b) => a.name.localeCompare(b.name)).map((g) => {
              const of = (gateways.data ?? []).filter((gw) => gw.gatewayGroupId === g.id);
              return (
                <tr key={g.id} className="border-t border-border align-top">
                  <td className="py-2"><Link to="/gateways/$groupId" params={{ groupId: g.id }} className="font-medium underline-offset-2 hover:underline">{g.name}</Link></td>
                  <td className="py-2">{g.region}</td>
                  <td className="py-2">{g.publicHostnames.join(", ")}</td>
                  <td className="py-2">{t("gateways.count", { connected: of.filter((gw) => gw.status?.connected).length, total: of.length })}</td>
                </tr>
              );
            })}
          </tbody>
        </table>
      )}
      {groups.data?.length === 0 && <p className="text-sm">{t("gateways.noGroups")}</p>}
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
    <form onSubmit={save} aria-label={t(group ? "gateways.settings" : "gateways.newGroup")} className="grid max-w-xl gap-3 rounded-md border border-border p-3" noValidate>
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
    return <p>{groups.isPending ? t("stepUp.loading") : t("gateways.notFound")}</p>;
  }
  const members = (gateways.data ?? []).filter((g) => g.gatewayGroupId === group.id).sort((a, b) => a.slot - b.slot);
  return (
    <div className="grid max-w-4xl gap-6">
      <h1 className="text-2xl font-semibold">{t("gateways.groupTitle", { name: group.name })}</h1>
      {live && <ApplyStatusView status={live} revision={write?.revision} name={(id) => names.data?.get(id) || id} />}
      <section aria-labelledby="members-title" className="grid gap-2">
        <h2 id="members-title" className="text-lg font-semibold">{t("gateways.members")}</h2>
        <table className="w-full text-left text-sm">
          <thead className="text-muted-foreground">
            <tr>{["name", "slot", "endpoints", "state", "version", "lastSeen", "actions"].map((c) => <th key={c} scope="col" className="py-1 font-medium">{t(`gateways.gw.${c}`)}</th>)}</tr>
          </thead>
          <tbody>
            {members.map((g) => (
              <tr key={g.id} className="border-t border-border align-top">
                <td className="py-2 font-medium">{g.name}</td>
                <td className="py-2">{g.slot}</td>
                <td className="py-2 font-mono">{g.tunnelEndpoints.join(", ")}</td>
                <td className="py-2"><GatewayChip gateway={g} /></td>
                <td className="py-2">{g.status?.version}</td>
                <td className="py-2">{when(g.status?.lastSeenTime)}</td>
                <td className="py-2"><GatewayActions orgId={org.orgId} gateway={g} onEdit={() => setEditing(g.id)} onDone={(w) => void done(w)} /></td>
              </tr>
            ))}
          </tbody>
        </table>
        {members.length === 0 && <p className="text-sm">{t("gateways.noGateways")}</p>}
        {editing ? (
          <GatewayForm key={editing} orgId={org.orgId} groupId={group.id} gateway={members.find((g) => g.id === editing)}
            onDone={(w) => void done(w)} onCancel={() => setEditing(undefined)} />
        ) : (
          <Button size="sm" variant="outline" className="justify-self-start" onClick={() => setEditing("new")}>{t("gwActions.addButton")}</Button>
        )}
      </section>
      <PortPools orgId={org.orgId} groupId={group.id} />
      <section aria-labelledby="group-settings-title" className="grid gap-2">
        <h2 id="group-settings-title" className="text-lg font-semibold">{t("gateways.settings")}</h2>
        <GroupForm key={group.etag} orgId={org.orgId} group={group} />
      </section>
    </div>
  );
}
