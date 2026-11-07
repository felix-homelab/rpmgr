// SPDX-License-Identifier: Apache-2.0

import { useMutation, useQuery } from "@connectrpc/connect-query";
import { useQueryClient } from "@tanstack/react-query";
import { getRouteApi, Link, useNavigate } from "@tanstack/react-router";
import { ChevronLeft } from "lucide-react";
import { useState } from "react";
import type { TFunction } from "i18next";
import { useTranslation } from "react-i18next";
import { Ask } from "@/components/ask";
import { PageHeader } from "@/components/page-header";
import { Alert } from "@/components/public-page";
import { panel } from "@/components/row-list";
import { Status, type Look } from "@/components/status";
import { Button } from "@/components/ui/button";
import { Card } from "@/components/ui/card";
import { Table, TD, TH, THead, TR } from "@/components/ui/table";
import { DnsZoneService, ZoneDelegationState, ZoneProviderStatus, ZoneSyncState, type DnsZone, type PlanRecord, type ZonePlan } from "@/gen/rpmgr/v1/dns_pb";
import { apiError } from "@/lib/api-error";
import { Reason, reasonOf } from "@/lib/errors";
import { when } from "@/lib/format";
import { AdoptButton, RecordContent, ZoneRecords } from "@/pages/dns-records";
import { useOrg } from "@/session";
import { useStepUp } from "@/step-up";

const zoneRoute = getRouteApi("/app/dns/$zoneId");

// isAdmin says whether the role may use the zone's methods, which need infrastructure.write: Owners
// and Admins. Any other member may list the records rpmgr owns and nothing else.
export const isAdmin = (role?: string) => role === "owner" || role === "admin";

const syncLooks: Record<ZoneSyncState, [Look, string]> = {
  [ZoneSyncState.UNSPECIFIED]: ["unknown", "unknown"],
  [ZoneSyncState.ACTIVE]: ["ok", "active"],
  [ZoneSyncState.HELD]: ["warn", "held"],
  [ZoneSyncState.DISABLED]: ["off", "disabled"],
};

// short shortens a plan hash for the heading, as in the mock-up of docs/09-web-ui.md.
export const short = (hash: string) => (hash.length > 8 ? `${hash.slice(0, 4)}…${hash.slice(-2)}` : hash);

// DnsZonePage is a managed zone (docs/09-web-ui.md, "Managed DNS zone"): its state, the plan that a
// pass would carry out and, for a held zone, its approval, and its records. Owners and Admins see
// everything; another member sees only the records rpmgr owns.
export function DnsZonePage() {
  const { t } = useTranslation();
  const { zoneId } = zoneRoute.useParams();
  const org = useOrg();
  const admin = isAdmin(org?.role);
  const got = useQuery(DnsZoneService.method.getZone, { dnsZoneId: zoneId }, { enabled: admin });
  const zone = got.data?.dnsZone;
  const queryClient = useQueryClient();
  const [error, setError] = useState("");
  const [note, setNote] = useState("");
  const stepUp = useStepUp();
  const enable = useMutation(DnsZoneService.method.enableZone);
  const sync = useMutation(DnsZoneService.method.syncZone);
  async function run(action: () => Promise<unknown>, done?: string) {
    setError("");
    setNote("");
    try {
      await action();
      setNote(done ?? "");
      await queryClient.invalidateQueries();
    } catch (err) {
      if (reasonOf(err) !== Reason.stepUpRequired) {
        setError(apiError(t, err));
      }
    }
  }
  const [look, key] = zone ? syncLooks[zone.syncState] : (["unknown", "unknown"] as const);
  return (
    <div className="grid gap-6">
      <Link to="/dns" className="inline-flex w-fit items-center gap-1 text-sm text-muted-foreground hover:text-foreground">
        <ChevronLeft aria-hidden="true" className="size-4" />{t("dnsZone.back")}
      </Link>
      <PageHeader title={t("dnsZone.title", { name: zone?.name ?? t("dnsZone.zone") })} description={admin ? undefined : t("dnsZone.ownedOnly")}
        actions={zone && (
          <>
            <Status look={look}>{t(`dns.sync.${key}`)}</Status>
            {zone.removalPending && <Status look="warn">{t("dnsZone.removalPending")}</Status>}
            {zone.syncState === ZoneSyncState.DISABLED && !zone.removalPending && (
              <Button size="sm" disabled={enable.isPending} onClick={() => void run(() => stepUp(() => enable.mutateAsync({ dnsZoneId: zone.id })), t("dnsZone.enabled"))}>{t("dnsZone.enable")}</Button>
            )}
            <Button size="sm" variant="outline" disabled={sync.isPending || zone.syncState === ZoneSyncState.DISABLED}
              onClick={() => void run(() => sync.mutateAsync({ dnsZoneId: zone.id }), t("dnsZone.syncAsked"))}>{t("dnsZone.sync")}</Button>
          </>
        )} />
      {got.isError && <Alert>{apiError(t, got.error)}</Alert>}
      {error && <Alert>{error}</Alert>}
      {note && <p role="status">{note}</p>}
      {zone && <DelegationWarning zone={zone} />}
      {zone && <ZoneState zone={zone} />}
      {zone && zone.syncState !== ZoneSyncState.DISABLED && <PlanCard zone={zone} />}
      <ZoneRecords zoneId={zoneId} admin={admin} />
      {zone && !zone.removalPending && <RemoveCard zone={zone} />}
    </div>
  );
}

// delegationOf says in words that the domain is delegated away from the provider, the words the
// claim check uses (docs/15-dns.md, "Delegation"): what the public DNS names, and what to set at the
// registrar. Empty if the delegation is fine or not known.
function delegationOf(t: TFunction, z: DnsZone): string {
  if (z.delegationState !== ZoneDelegationState.MISMATCH) {
    return "";
  }
  return t("dnsZone.delegation", { name: z.name, public: z.delegationNameservers.join(", "), assigned: z.assignedNameservers.join(", ") });
}

// DelegationWarning warns, before a plan is approved and after, that what the zone publishes is not
// served: the domain is delegated to other nameservers than the ones the provider assigned.
function DelegationWarning({ zone }: { zone: DnsZone }) {
  const { t } = useTranslation();
  const text = delegationOf(t, zone);
  return text ? <Alert>{text}</Alert> : null;
}

// ZoneState shows what the zone's gates are and what its provider answered.
function ZoneState({ zone: z }: { zone: DnsZone }) {
  const { t } = useTranslation();
  const yes = (v: boolean) => t(v ? "dnsZone.on" : "dnsZone.off");
  return (
    <Card title={t("dnsZone.gates")}>
      <p>{t("dnsZone.gatesLine", { routes: yes(z.publishRouteHostnames), proxied: yes(z.allowProxied), wildcards: yes(z.allowWildcards), threshold: z.deleteThreshold })}</p>
      <div className="flex flex-wrap gap-x-3 text-muted-foreground">
        {z.heldReason && z.syncState === ZoneSyncState.HELD && <span>{t("dns.heldReason", { reason: t(`dns.held.${z.heldReason}`, { defaultValue: z.heldReason }) })}</span>}
        {z.lastSyncedTime && <span>{t("dns.synced", { when: when(z.lastSyncedTime) })}</span>}
        {z.assignedNameservers.length > 0 && <span>{t("dnsZone.assigned", { servers: z.assignedNameservers.join(", ") })}</span>}
        {z.delegationState === ZoneDelegationState.OK && <span>{t("dnsZone.delegationOk")}</span>}
      </div>
      {z.providerStatus === ZoneProviderStatus.PERMISSION_DENIED && <p className="text-destructive">{t("dns.permissionDenied", { name: z.name })}</p>}
    </Card>
  );
}

const hintOf = (kind: string) => `dnsZone.conflict.${kind}`;

// RecordRows lists the records of a part of the plan, one row each, behind the part's sign.
function RecordRows({ sign, label, records }: { sign: string; label: string; records: PlanRecord[] }) {
  return records.map((r, i) => (
    <TR key={`${sign}${r.id}${r.name}${r.type}${i}`}>
      <TD><span aria-hidden="true" className="font-mono">{sign}</span><span className="sr-only">{label}</span></TD>
      <TD>{r.type}</TD>
      <TD className="font-mono break-all">{r.name}</TD>
      <TD><RecordContent content={r.content} proxied={r.proxied} /></TD>
    </TR>
  ));
}

const empty = (p: ZonePlan) => p.creates.length + p.updates.length + p.deletes.length + p.conflicts.length + p.orphans.length + p.adoptedChanged.length + p.shadows.length + p.lost.length === 0;

// PlanCard is the plan of the zone, read live now: what a pass would create, change and delete, the
// conflicts, which U4 says how to resolve, and the orphans. A held zone's plan is approved here; the
// approval is bound to the plan's hash, so that if the plan changed since it was shown the new plan
// replaces it and the approval has to be repeated.
function PlanCard({ zone }: { zone: DnsZone }) {
  const { t } = useTranslation();
  const stepUp = useStepUp();
  const queryClient = useQueryClient();
  const plan = useQuery(DnsZoneService.method.planZoneSync, { dnsZoneId: zone.id });
  const approve = useMutation(DnsZoneService.method.approveZonePlan);
  const [error, setError] = useState("");
  const p = plan.data?.plan;
  async function ok() {
    setError("");
    try {
      await stepUp(() => approve.mutateAsync({ dnsZoneId: zone.id, planHash: p?.hash ?? "" }));
    } catch (err) {
      if (reasonOf(err) === Reason.planChanged) {
        setError(t("dnsZone.planChanged"));
      } else if (reasonOf(err) !== Reason.stepUpRequired) {
        setError(apiError(t, err));
      }
    }
    await queryClient.invalidateQueries();
  }
  return (
    <Card title={p ? t("dnsZone.plan", { hash: short(p.hash) }) : t("dnsZone.planTitle")} description={zone.syncState === ZoneSyncState.HELD ? t("dnsZone.planHeld") : zone.pendingPlanHash ? t("dnsZone.planApproved") : t("dnsZone.planLive")}
      actions={zone.syncState === ZoneSyncState.HELD && p && (
        <Ask label={t("dnsZone.approve")} question={[t("dnsZone.approveAsk", { hash: short(p.hash), name: zone.name }), delegationOf(t, zone)].filter(Boolean).join(" ")} confirm={t("dnsZone.approveConfirm")} busy={approve.isPending} onConfirm={ok} />
      )}>
      {plan.isError && <Alert>{apiError(t, plan.error)}</Alert>}
      {error && <Alert>{error}</Alert>}
      {p && empty(p) && <p>{t("dnsZone.planEmpty")}</p>}
      {p && !empty(p) && (
        <Table framed={false}>
          <THead><TR><TH>{t("dnsZone.change")}</TH><TH>{t("dnsZone.type")}</TH><TH>{t("dnsZone.name")}</TH><TH>{t("dnsZone.content")}</TH></TR></THead>
          <tbody>
            <RecordRows sign="+" label={t("dnsZone.creates")} records={p.creates} />
            <RecordRows sign="~" label={t("dnsZone.updates")} records={p.updates} />
            <RecordRows sign="−" label={t("dnsZone.deletes")} records={p.deletes} />
            <RecordRows sign="?" label={t("dnsZone.orphans")} records={p.orphans} />
            <RecordRows sign="≠" label={t("dnsZone.adoptedChanged")} records={p.adoptedChanged} />
          </tbody>
        </Table>
      )}
      {p?.conflicts.map((c) => (
        <div key={c.name + c.kind} className={panel}>
          <p><span className="font-medium">{c.name}</span> <Status look="warn">{t("dnsZone.conflictBadge")}</Status></p>
          <ul className="grid gap-2 font-mono text-sm">{c.records.map((r) => (
            <li key={r.id + r.type + r.content} className="flex flex-wrap items-center gap-2">
              <span className="min-w-0 break-all">{r.type} {r.content}</span>
              {c.kind === "foreign_address" && r.id && <AdoptButton zoneId={zone.id} record={{ ...r, providerRecordId: r.id }} onError={setError} />}
            </li>
          ))}</ul>
          <p>{t(hintOf(c.kind), { defaultValue: t("dnsZone.conflict.other", { kind: c.kind }) })}</p>
        </div>
      ))}
      {p && p.orphans.length > 0 && <p>{t("dnsZone.orphansHint")}</p>}
      {p && p.adoptedChanged.length > 0 && <p>{t("dnsZone.adoptedChangedHint")}</p>}
      {p?.shadows.map((n) => <p key={n}>{t("dnsZone.shadow", { name: n })}</p>)}
      {p && p.lost.length > 0 && <p>{t("dnsZone.lost", { count: p.lost.length })}</p>}
    </Card>
  );
}

// RemoveCard stops managing the zone: the records stay at the provider, or, after a plan that lists
// them, rpmgr deletes the ones it owns. Either needs a step-up. The deletion is carried out by the
// DNS job, so the zone then shows removal pending.
function RemoveCard({ zone }: { zone: DnsZone }) {
  const { t } = useTranslation();
  const stepUp = useStepUp();
  const queryClient = useQueryClient();
  const navigate = useNavigate();
  const remove = useMutation(DnsZoneService.method.removeZone);
  const [open, setOpen] = useState(false);
  const [wipe, setWipe] = useState(false);
  const [error, setError] = useState("");
  const plan = useQuery(DnsZoneService.method.planZoneSync, { dnsZoneId: zone.id, deleteRecords: true }, { enabled: open && wipe });
  const hash = plan.data?.plan?.hash ?? "";
  async function go() {
    setError("");
    try {
      await stepUp(() => remove.mutateAsync({ dnsZoneId: zone.id, etag: zone.etag, deleteRecords: wipe, planHash: wipe ? hash : "" }));
      if (wipe) {
        setOpen(false);
        await queryClient.invalidateQueries();
      } else {
        await navigate({ to: "/dns" });
      }
    } catch (err) {
      if (reasonOf(err) === Reason.planChanged) {
        setError(t("dnsZone.planChanged"));
        await queryClient.invalidateQueries();
      } else if (reasonOf(err) !== Reason.stepUpRequired) {
        setError(apiError(t, err));
      }
    }
  }
  return (
    <Card title={t("dnsZone.remove")}>
      {!open ? <div><Button size="sm" variant="outline" onClick={() => setOpen(true)}>{t("dnsZone.removeOpen")}</Button></div> : (
        <div className={panel}>
          <label className="flex items-center gap-2"><input type="radio" name="wipe" checked={!wipe} onChange={() => setWipe(false)} />{t("dnsZone.keepRecords")}</label>
          <label className="flex items-center gap-2"><input type="radio" name="wipe" checked={wipe} onChange={() => setWipe(true)} />{t("dnsZone.deleteRecords")}</label>
          {wipe && plan.data?.plan && (
            <div>
              <p>{t("dnsZone.deletePlan", { count: plan.data.plan.deletes.length, hash: short(hash) })}</p>
              <ul className="font-mono text-sm break-all">{plan.data.plan.deletes.map((r) => <li key={r.id}>{r.type} {r.name} {r.content}</li>)}</ul>
            </div>
          )}
          {wipe && plan.isError && <Alert>{apiError(t, plan.error)}</Alert>}
          {error && <Alert>{error}</Alert>}
          <div className="flex flex-wrap items-center gap-2">
            <Ask label={t("dnsZone.removeNow")} destructive question={t(wipe ? "dnsZone.removeWipeAsk" : "dnsZone.removeKeepAsk", { name: zone.name })} confirm={t("dnsZone.removeConfirm")}
              disabled={wipe && !hash} busy={remove.isPending} onConfirm={go} />
            <Button size="sm" variant="outline" onClick={() => { setOpen(false); setWipe(false); setError(""); }}>{t("stepUp.cancel")}</Button>
          </div>
        </div>
      )}
    </Card>
  );
}
