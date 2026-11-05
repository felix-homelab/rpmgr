// SPDX-License-Identifier: Apache-2.0

import { create } from "@bufbuild/protobuf";
import { createClient } from "@connectrpc/connect";
import { useMutation, useTransport } from "@connectrpc/connect-query";
import { useQuery, useQueryClient } from "@tanstack/react-query";
import { Cloud, Plus } from "lucide-react";
import { Link } from "@tanstack/react-router";
import { useState, type FormEvent } from "react";
import { useTranslation } from "react-i18next";
import { EmptyState } from "@/components/empty-state";
import { Field } from "@/components/field";
import { PageHeader } from "@/components/page-header";
import { Alert } from "@/components/public-page";
import { panel, Row, RowList } from "@/components/row-list";
import { Status, type Look } from "@/components/status";
import { Button } from "@/components/ui/button";
import { Card } from "@/components/ui/card";
import {
  CloudflareProviderSchema, DnsProviderSchema, DnsProviderService, DnsZoneService, ProviderStatus, ZoneProviderStatus, ZoneSyncState,
  type DnsProvider, type DnsZone, type ProviderZone,
} from "@/gen/rpmgr/v1/dns_pb";
import { apiError, serverProblems, type Problems } from "@/lib/api-error";
import { Reason, reasonOf } from "@/lib/errors";
import { when } from "@/lib/format";
import { largestPage, listAll } from "@/lib/list-all";
import { useOrg } from "@/session";
import { useStepUp } from "@/step-up";

// useProviders reads all of the org's DNS providers, and useZones its managed zones.
function useProviders(orgId: string | undefined) {
  const transport = useTransport();
  return useQuery({
    queryKey: ["dns-providers", orgId],
    enabled: !!orgId,
    queryFn: () => listAll(async (pageToken) => {
      const r = await createClient(DnsProviderService, transport).listDnsProviders({ orgId, pageSize: largestPage, pageToken });
      return { items: r.dnsProviders, next: r.nextPageToken };
    }),
  });
}

function useZones(orgId: string | undefined) {
  const transport = useTransport();
  return useQuery({
    queryKey: ["dns-zones", orgId],
    enabled: !!orgId,
    queryFn: () => listAll(async (pageToken) => {
      const r = await createClient(DnsZoneService, transport).listZones({ orgId, pageSize: largestPage, pageToken });
      return { items: r.dnsZones, next: r.nextPageToken };
    }),
  });
}

// DnsPage is the DNS providers and the zones imported from them (docs/09-web-ui.md, "Managed DNS
// zone"; docs/15-dns.md). The controller mounts the services with the slice that makes DNS
// reachable, and the sidebar links here then.
export function DnsPage() {
  const { t } = useTranslation();
  const org = useOrg();
  const providers = useProviders(org?.orgId);
  const zones = useZones(org?.orgId);
  const [connecting, setConnecting] = useState(false);
  return (
    <div className="grid gap-6">
      <PageHeader title={t("dns.title")} description={t("dns.intro")} actions={<Link to="/dns-names" className="text-sm underline">{t("dns.namesLink")}</Link>} />
      <Card title={t("dns.providers")} actions={
        <Button size="sm" disabled={!org} onClick={() => setConnecting(true)}><Plus aria-hidden="true" />{t("dns.connect")}</Button>
      }>
        {connecting && org && <ConnectForm orgId={org.orgId} onDone={() => setConnecting(false)} />}
        {providers.data?.length === 0 ? <EmptyState icon={Cloud}>{t("dns.noProviders")}</EmptyState> : (
          <RowList>
            {[...(providers.data ?? [])].sort((a, b) => a.name.localeCompare(b.name)).map((p) => (
              <ProviderRow key={p.id} provider={p} imported={zones.data ?? []} />
            ))}
          </RowList>
        )}
      </Card>
      <Card title={t("dns.zones")}>
        {zones.data?.length === 0 ? <EmptyState icon={Cloud}>{t("dns.noZones")}</EmptyState> : (
          <RowList>
            {[...(zones.data ?? [])].sort((a, b) => a.name.localeCompare(b.name)).map((z) => <ZoneRow key={z.id} zone={z} />)}
          </RowList>
        )}
      </Card>
    </div>
  );
}

// TokenField is the provider's API token: write-only, so it starts empty, is never filled in from
// what the API returns, and is hidden while typed (docs/04-security.md, "Secrets at rest and in logs").
function TokenField({ value, onChange, error }: { value: string; onChange: (v: string) => void; error?: string }) {
  const { t } = useTranslation();
  return (
    <Field label={t("dns.token")} type="password" autoComplete="new-password" required maxLength={4096} hint={t("dns.tokenHint")}
      error={error} value={value} onChange={(e) => onChange(e.target.value)} />
  );
}

// ConnectForm connects a Cloudflare account with a step-up.
function ConnectForm({ orgId, onDone }: { orgId: string; onDone: () => void }) {
  const { t } = useTranslation();
  const stepUp = useStepUp();
  const connect = useMutation(DnsProviderService.method.connectDnsProvider);
  const queryClient = useQueryClient();
  const [form, setForm] = useState({ name: "", accountId: "", token: "" });
  const [error, setError] = useState("");
  const [problems, setProblems] = useState<Problems>({});
  async function save(e: FormEvent) {
    e.preventDefault();
    setProblems({});
    setError("");
    if (form.token.trim() === "") {
      setProblems({ token: t("dns.tokenNeeded") });
      return;
    }
    try {
      await stepUp(() => connect.mutateAsync({ orgId, dnsProvider: create(DnsProviderSchema, {
        name: form.name.trim(),
        kind: { case: "cloudflare", value: create(CloudflareProviderSchema, { apiToken: form.token.trim(), accountId: form.accountId.trim() }) },
      }) }));
      setForm({ name: "", accountId: "", token: "" });
      await queryClient.invalidateQueries();
      onDone();
    } catch (err) {
      if (reasonOf(err) !== Reason.stepUpRequired) {
        setProblems(serverProblems(t, err));
        setError(apiError(t, err, ["name"]));
      }
    }
  }
  return (
    <form onSubmit={save} aria-label={t("dns.connectTitle")} className={panel} noValidate>
      <Field label={t("dns.name")} className="max-w-md" required maxLength={64} error={problems.name} value={form.name} onChange={(e) => setForm({ ...form, name: e.target.value })} />
      <Field label={t("dns.account")} className="max-w-md" maxLength={64} hint={t("dns.accountHint")} value={form.accountId} onChange={(e) => setForm({ ...form, accountId: e.target.value })} />
      <div className="max-w-md"><TokenField value={form.token} error={problems.token} onChange={(token) => setForm({ ...form, token })} /></div>
      {error && <Alert>{error}</Alert>}
      <div className="flex gap-2">
        <Button type="submit" disabled={connect.isPending}>{t("dns.connectSubmit")}</Button>
        <Button variant="outline" onClick={onDone}>{t("stepUp.cancel")}</Button>
      </div>
    </form>
  );
}

const providerLooks: Record<ProviderStatus, [Look, string]> = {
  [ProviderStatus.UNSPECIFIED]: ["unknown", "unknown"],
  [ProviderStatus.OK]: ["ok", "ok"],
  [ProviderStatus.INVALID]: ["failed", "invalid"],
};

type Panel = "rotate" | "zones" | "delete" | undefined;

// ProviderRow shows a provider, whose token the row never shows, and its actions: rotate the
// token, offer the zones to import, and delete after a confirmation that names it (U7).
function ProviderRow({ provider: p, imported }: { provider: DnsProvider; imported: DnsZone[] }) {
  const { t } = useTranslation();
  const stepUp = useStepUp();
  const queryClient = useQueryClient();
  const remove = useMutation(DnsProviderService.method.deleteDnsProvider);
  const [open, setOpen] = useState<Panel>();
  const [error, setError] = useState("");
  const [look, key] = providerLooks[p.status];
  async function del() {
    setError("");
    try {
      await stepUp(() => remove.mutateAsync({ dnsProviderId: p.id, etag: p.etag }));
      await queryClient.invalidateQueries();
    } catch (err) {
      if (reasonOf(err) !== Reason.stepUpRequired) {
        setError(apiError(t, err));
      }
    }
  }
  return (
    <Row>
      <div className="flex flex-wrap items-start justify-between gap-x-4 gap-y-2">
        <div className="grid gap-1">
          <div className="flex flex-wrap items-center gap-2">
            <span className="font-medium">{p.name}</span>
            <Status look={look}>{t(`dns.providerStatus.${key}`)}</Status>
            {p.tokenExpiring && <Status look="warn">{t("dns.expiring")}</Status>}
          </div>
          <div className="flex flex-wrap gap-x-3 text-muted-foreground">
            <span>{t("dns.cloudflare")}</span>
            {p.tokenExpiresAt && <span>{t("dns.expires", { when: when(p.tokenExpiresAt) })}</span>}
            {p.lastCheckTime && <span>{t("dns.checked", { when: when(p.lastCheckTime) })}</span>}
          </div>
        </div>
        <div className="flex flex-wrap items-center gap-2">
          <Button size="sm" variant="outline" aria-expanded={open === "zones"} onClick={() => setOpen(open === "zones" ? undefined : "zones")}>{t("dns.importZones")}</Button>
          <Button size="sm" variant="outline" aria-expanded={open === "rotate"} onClick={() => setOpen(open === "rotate" ? undefined : "rotate")}>{t("dns.rotate")}</Button>
          {open === "delete" ? (
            <>
              <span>{t("dns.askDelete", { name: p.name })}</span>
              <Button size="sm" variant="destructive" disabled={remove.isPending} onClick={() => void del()}>{t("targetForm.remove")}</Button>
              <Button size="sm" variant="outline" onClick={() => setOpen(undefined)}>{t("stepUp.cancel")}</Button>
            </>
          ) : (
            <Button size="sm" variant="outline" onClick={() => setOpen("delete")}>{t("targetForm.removeAsk")}</Button>
          )}
        </div>
      </div>
      {p.lastError && <p className="text-destructive">{p.lastError}</p>}
      {open === "rotate" && <RotateForm provider={p} onDone={() => setOpen(undefined)} />}
      {open === "zones" && <ProviderZones provider={p} imported={imported} />}
      {error && <Alert>{error}</Alert>}
    </Row>
  );
}

// RotateForm replaces a provider's token with a step-up; the zones and records stay.
function RotateForm({ provider: p, onDone }: { provider: DnsProvider; onDone: () => void }) {
  const { t } = useTranslation();
  const stepUp = useStepUp();
  const update = useMutation(DnsProviderService.method.updateDnsProvider);
  const queryClient = useQueryClient();
  const [token, setToken] = useState("");
  const [error, setError] = useState("");
  const [problems, setProblems] = useState<Problems>({});
  async function save(e: FormEvent) {
    e.preventDefault();
    setProblems({});
    setError("");
    if (token.trim() === "") {
      setProblems({ token: t("dns.tokenNeeded") });
      return;
    }
    try {
      const account = p.kind.case === "cloudflare" ? p.kind.value.accountId : "";
      await stepUp(() => update.mutateAsync({
        dnsProvider: create(DnsProviderSchema, { id: p.id, kind: { case: "cloudflare", value: create(CloudflareProviderSchema, { apiToken: token.trim(), accountId: account }) } }),
        updateMask: { paths: ["cloudflare.api_token"] }, etag: p.etag,
      }));
      setToken("");
      await queryClient.invalidateQueries();
      onDone();
    } catch (err) {
      if (reasonOf(err) !== Reason.stepUpRequired) {
        setError(apiError(t, err));
      }
    }
  }
  return (
    <form onSubmit={save} aria-label={t("dns.rotateTitle", { name: p.name })} className={panel} noValidate>
      <div className="max-w-md"><TokenField value={token} error={problems.token} onChange={setToken} /></div>
      {error && <Alert>{error}</Alert>}
      <div className="flex gap-2">
        <Button type="submit" disabled={update.isPending}>{t("dns.rotateSubmit")}</Button>
        <Button variant="outline" onClick={onDone}>{t("stepUp.cancel")}</Button>
      </div>
    </form>
  );
}

// importable says why a provider's zone cannot be imported, or nothing if it can: only an active,
// full zone, not yet imported (docs/15-dns.md, "Connecting, importing and disconnecting").
function whyNot(z: ProviderZone, imported: DnsZone[]): "imported" | "status" | "type" | undefined {
  if (imported.some((m) => m.providerZoneId === z.id)) {
    return "imported";
  }
  if (z.status !== "active") {
    return "status";
  }
  return z.type === "full" ? undefined : "type";
}

// ProviderZones lists what the provider offers and imports a zone, held, with its apex claim.
function ProviderZones({ provider: p, imported }: { provider: DnsProvider; imported: DnsZone[] }) {
  const { t } = useTranslation();
  const transport = useTransport();
  const queryClient = useQueryClient();
  const zones = useQuery({
    queryKey: ["dns-provider-zones", p.id],
    queryFn: async () => (await createClient(DnsProviderService, transport).listProviderZones({ dnsProviderId: p.id })).zones,
  });
  const importZone = useMutation(DnsZoneService.method.importZone);
  const [error, setError] = useState("");
  const [done, setDone] = useState("");
  async function run(z: ProviderZone) {
    setError("");
    setDone("");
    try {
      await importZone.mutateAsync({ dnsProviderId: p.id, providerZoneId: z.id });
      setDone(z.name);
      await queryClient.invalidateQueries();
    } catch (err) {
      setError(apiError(t, err));
    }
  }
  return (
    <div className={panel}>
      {zones.isError && <Alert>{apiError(t, zones.error)}</Alert>}
      {zones.data?.length === 0 && <p>{t("dns.providerNoZones")}</p>}
      <ul className="grid gap-2">
        {(zones.data ?? []).map((z) => {
          const why = whyNot(z, imported);
          return (
            <li key={z.id} className="flex flex-wrap items-center justify-between gap-2">
              <span><span className="font-medium">{z.name}</span> <span className="text-muted-foreground">{why ? t(`dns.why.${why}`, { status: z.status, type: z.type }) : t("dns.canImport")}</span></span>
              <Button size="sm" variant="outline" disabled={!!why || importZone.isPending} aria-label={t("dns.importZone", { name: z.name })} onClick={() => void run(z)}>{t("dns.import")}</Button>
            </li>
          );
        })}
      </ul>
      {done && <p role="status">{t("dns.imported", { name: done })}</p>}
      {error && <Alert>{error}</Alert>}
    </div>
  );
}

const syncLooks: Record<ZoneSyncState, [Look, string]> = {
  [ZoneSyncState.UNSPECIFIED]: ["unknown", "unknown"],
  [ZoneSyncState.ACTIVE]: ["ok", "active"],
  [ZoneSyncState.HELD]: ["warn", "held"],
  [ZoneSyncState.DISABLED]: ["off", "disabled"],
};

const accessLooks: Record<ZoneProviderStatus, [Look, string]> = {
  [ZoneProviderStatus.UNSPECIFIED]: ["unknown", "unknown"],
  [ZoneProviderStatus.OK]: ["ok", "ok"],
  [ZoneProviderStatus.PERMISSION_DENIED]: ["failed", "permissionDenied"],
  [ZoneProviderStatus.UNREACHABLE]: ["warn", "unreachable"],
  [ZoneProviderStatus.RATE_LIMITED]: ["warn", "rateLimited"],
};

// ZoneRow shows a managed zone: held or active, and what the provider answered for it, so that a
// token without permission for this zone shows on the zone (docs/15-dns.md). Removing it keeps the
// records at the provider.
function ZoneRow({ zone: z }: { zone: DnsZone }) {
  const { t } = useTranslation();
  const queryClient = useQueryClient();
  const remove = useMutation(DnsZoneService.method.removeZone);
  const [asking, setAsking] = useState(false);
  const [error, setError] = useState("");
  const [sync, syncKey] = syncLooks[z.syncState];
  const [access, accessKey] = accessLooks[z.providerStatus];
  async function del() {
    setError("");
    try {
      await remove.mutateAsync({ dnsZoneId: z.id, etag: z.etag });
      await queryClient.invalidateQueries();
    } catch (err) {
      setError(apiError(t, err));
    }
  }
  return (
    <Row>
      <div className="flex flex-wrap items-start justify-between gap-x-4 gap-y-2">
        <div className="grid gap-1">
          <div className="flex flex-wrap items-center gap-2">
            <Link to="/dns/$zoneId" params={{ zoneId: z.id }} className="font-medium hover:underline">{z.name}</Link>
            <Status look={sync}>{t(`dns.sync.${syncKey}`)}</Status>
            {z.removalPending && <Status look="warn">{t("dnsZone.removalPending")}</Status>}
            <Status look={access}>{t(`dns.access.${accessKey}`)}</Status>
          </div>
          <div className="flex flex-wrap gap-x-3 text-muted-foreground">
            {z.heldReason && <span>{t("dns.heldReason", { reason: t(`dns.held.${z.heldReason}`, { defaultValue: z.heldReason }) })}</span>}
            {z.lastSyncedTime && <span>{t("dns.synced", { when: when(z.lastSyncedTime) })}</span>}
          </div>
        </div>
        <div className="flex flex-wrap items-center gap-2">
          {asking ? (
            <>
              <span>{t("dns.askRemove", { name: z.name })}</span>
              <Button size="sm" variant="destructive" disabled={remove.isPending} onClick={() => void del()}>{t("targetForm.remove")}</Button>
              <Button size="sm" variant="outline" onClick={() => setAsking(false)}>{t("stepUp.cancel")}</Button>
            </>
          ) : (
            <Button size="sm" variant="outline" onClick={() => setAsking(true)}>{t("targetForm.removeAsk")}</Button>
          )}
        </div>
      </div>
      {z.providerStatus === ZoneProviderStatus.PERMISSION_DENIED && <p className="text-destructive">{t("dns.permissionDenied", { name: z.name })}</p>}
      {error && <Alert>{error}</Alert>}
    </Row>
  );
}
