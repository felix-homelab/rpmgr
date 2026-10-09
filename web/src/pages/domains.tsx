// SPDX-License-Identifier: Apache-2.0

import { create } from "@bufbuild/protobuf";
import { Code, ConnectError, createClient } from "@connectrpc/connect";
import { useMutation, useQuery as useConnectQuery, useTransport } from "@connectrpc/connect-query";
import { useQuery, useQueryClient } from "@tanstack/react-query";
import { useState, type FormEvent } from "react";
import { useTranslation } from "react-i18next";
import { Command } from "@/components/one-time-token";
import { Alert } from "@/components/public-page";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { AuthService } from "@/gen/rpmgr/v1/auth_pb";
import { DomainMethod, DomainSchema, DomainService, DomainStatus, type Domain } from "@/gen/rpmgr/v1/domain_pb";
import { Reason, reasonOf } from "@/lib/errors";
import { when } from "@/lib/format";
import { largestPage, listAll } from "@/lib/list-all";
import { useOrg } from "@/session";
import { useStepUp } from "@/step-up";

const looks: Record<DomainStatus, [string, string, string]> = {
  [DomainStatus.UNSPECIFIED]: ["?", "unknown", ""],
  [DomainStatus.PENDING]: ["⧗", "pending", "text-muted-foreground"],
  [DomainStatus.PENDING_APPROVAL]: ["⧗", "pendingApproval", "text-muted-foreground"],
  [DomainStatus.VERIFIED]: ["✓", "verified", "text-ok"],
  [DomainStatus.FAILED]: ["✕", "failed", "text-destructive"],
};

// Domains lists the org's domain claims and the proof each pending one waits for, claims a domain,
// checks a claim now, deletes one, and lets the Instance Admin mark one trusted
// (docs/09-web-ui.md, "Information architecture"; docs/15-dns.md).
export function Domains() {
  const { t } = useTranslation();
  const org = useOrg();
  const transport = useTransport();
  const list = useQuery({
    queryKey: ["domains", org?.orgId],
    enabled: !!org,
    queryFn: () => listAll(async (pageToken) => {
      const r = await createClient(DomainService, transport).listDomains({ orgId: org?.orgId, pageSize: largestPage, pageToken });
      return { items: r.domains, next: r.nextPageToken };
    }),
  });
  const session = useConnectQuery(AuthService.method.getSession, {});
  const [claiming, setClaiming] = useState(false);
  return (
    <section aria-labelledby="domains-title" className="grid gap-3">
      <div className="flex items-center gap-4">
        <h2 id="domains-title" className="text-lg font-semibold">{t("domains.title")}</h2>
        <Button size="sm" className="ml-auto" disabled={!org} onClick={() => setClaiming(true)}>{t("domains.claim")}</Button>
      </div>
      {claiming && org && <ClaimForm orgId={org.orgId} onDone={() => setClaiming(false)} />}
      <ul className="grid gap-2">
        {[...(list.data ?? [])].sort((a, b) => a.fqdn.localeCompare(b.fqdn)).map((d) => (
          <DomainRow key={d.id} domain={d} instanceAdmin={session.data?.instanceAdmin ?? false} />
        ))}
      </ul>
      {list.data?.length === 0 && <p className="text-sm">{t("domains.none")}</p>}
    </section>
  );
}

function ClaimForm({ orgId, onDone }: { orgId: string; onDone: () => void }) {
  const { t } = useTranslation();
  const claim = useMutation(DomainService.method.createDomain);
  const queryClient = useQueryClient();
  const [requestId] = useState(() => crypto.randomUUID());
  const [form, setForm] = useState({ fqdn: "", wildcard: false, method: String(DomainMethod.DNS_TXT) });
  const [error, setError] = useState("");
  async function save(e: FormEvent) {
    e.preventDefault();
    try {
      await claim.mutateAsync({ orgId, requestId, domain: create(DomainSchema, {
        fqdn: form.fqdn.trim().toLowerCase().replace(/\.$/, ""), wildcard: form.wildcard, method: Number(form.method),
      }) });
      await queryClient.invalidateQueries();
      onDone();
    } catch (err) {
      const e = ConnectError.from(err);
      setError(e.code === Code.AlreadyExists || e.code === Code.InvalidArgument || e.code === Code.FailedPrecondition ? e.rawMessage : t("link.failed", { message: e.rawMessage }));
    }
  }
  return (
    <form onSubmit={save} aria-label={t("domains.claimTitle")} className="grid max-w-xl gap-3 rounded-md border border-border p-3" noValidate>
      <label className="grid gap-1 text-sm font-medium">{t("domains.fqdn")}<Input value={form.fqdn} onChange={(e) => setForm({ ...form, fqdn: e.target.value })} /></label>
      <label className="flex items-center gap-2 text-sm"><input type="checkbox" checked={form.wildcard} onChange={(e) => setForm({ ...form, wildcard: e.target.checked })} />{t("domains.wildcard")}</label>
      <fieldset className="grid gap-1.5">
        <legend className="text-sm font-medium">{t("domains.method")}</legend>
        {[[DomainMethod.DNS_TXT, "txt"], [DomainMethod.HTTP, "http"]].map(([m, k]) => (
          <label key={k} className="flex items-center gap-2 text-sm">
            <input type="radio" name="method" checked={form.method === String(m)} onChange={() => setForm({ ...form, method: String(m) })} />
            {t(`domains.methods.${k}`)}
          </label>
        ))}
      </fieldset>
      {error && <Alert>{error}</Alert>}
      <div className="flex gap-2">
        <Button type="submit" disabled={claim.isPending}>{t("domains.claimSubmit")}</Button>
        <Button variant="outline" onClick={onDone}>{t("stepUp.cancel")}</Button>
      </div>
    </form>
  );
}

// DomainRow shows a claim, the record or token a pending one waits for (U4), and its actions.
function DomainRow({ domain: d, instanceAdmin }: { domain: Domain; instanceAdmin: boolean }) {
  const { t } = useTranslation();
  const queryClient = useQueryClient();
  const stepUp = useStepUp();
  const verify = useMutation(DomainService.method.verifyDomain);
  const remove = useMutation(DomainService.method.deleteDomain);
  const trust = useMutation(DomainService.method.markDomainTrusted);
  const [asking, setAsking] = useState(false);
  const [error, setError] = useState("");
  const [icon, key, tone] = looks[d.status];
  const name = (d.wildcard ? "*." : "") + d.fqdn;
  async function act(run: () => Promise<unknown>) {
    setError("");
    try {
      await run();
      await queryClient.invalidateQueries();
    } catch (err) {
      if (reasonOf(err) !== Reason.stepUpRequired) {
        setError(ConnectError.from(err).rawMessage);
      }
    }
  }
  const pending = d.status === DomainStatus.PENDING || d.status === DomainStatus.FAILED;
  return (
    <li className="grid gap-2 rounded-md border border-border p-3 text-sm">
      <div className="flex flex-wrap items-center gap-3">
        <span className="font-medium">{name}</span>
        <span className={tone}><span aria-hidden="true">{icon} </span>{t(`domains.status.${key}`)}</span>
        <span className="text-muted-foreground">{t(`domains.methodName.${DomainMethod[d.method]}`, { defaultValue: DomainMethod[d.method] })}</span>
        {d.lastCheckTime && <span className="text-muted-foreground">{t("domains.checked", { when: when(d.lastCheckTime) })}</span>}
      </div>
      {d.lastError && <p className="text-destructive">{d.lastError}</p>}
      {pending && d.challenge && (d.method === DomainMethod.HTTP ? (
        <div className="grid gap-1">
          <p>{t("domains.httpHow", { url: d.challenge.httpUrl })}</p>
          <Command command={d.challenge.value} label={t("domains.value")} />
        </div>
      ) : (
        <div className="grid gap-1">
          <p>{t("domains.txtHow")}</p>
          <Command command={d.challenge.txtName} label={t("domains.txtName")} />
          <Command command={d.challenge.value} label={t("domains.value")} />
        </div>
      ))}
      <div className="flex flex-wrap gap-2">
        {pending && <Button size="sm" variant="outline" disabled={verify.isPending} onClick={() => void act(() => verify.mutateAsync({ domainId: d.id }))}>{t("domains.check")}</Button>}
        {instanceAdmin && d.status !== DomainStatus.VERIFIED && (
          <Button size="sm" variant="outline" onClick={() => void act(() => stepUp(() => trust.mutateAsync({ domainId: d.id })))}>{t("domains.trust")}</Button>
        )}
        {asking ? (
          <>
            <span>{t("domains.ask", { name })}</span>
            <Button size="sm" variant="destructive" onClick={() => void act(() => remove.mutateAsync({ domainId: d.id, etag: d.etag }))}>{t("targetForm.remove")}</Button>
            <Button size="sm" variant="outline" onClick={() => setAsking(false)}>{t("stepUp.cancel")}</Button>
          </>
        ) : (
          <Button size="sm" variant="outline" onClick={() => setAsking(true)}>{t("targetForm.removeAsk")}</Button>
        )}
      </div>
      {error && <Alert>{error}</Alert>}
    </li>
  );
}
