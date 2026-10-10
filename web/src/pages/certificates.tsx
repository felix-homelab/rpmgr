// SPDX-License-Identifier: Apache-2.0

import { clone, create } from "@bufbuild/protobuf";
import { timestampDate } from "@bufbuild/protobuf/wkt";
import { ConnectError, createClient } from "@connectrpc/connect";
import { useMutation, useTransport } from "@connectrpc/connect-query";
import { useQuery, useQueryClient } from "@tanstack/react-query";
import { useState, type FormEvent } from "react";
import { useTranslation } from "react-i18next";
import { ManifestButton } from "@/components/manifest";
import { PemField } from "@/components/pem-field";
import { Alert } from "@/components/public-page";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import {
  CABundleSchema, CertificateService, CertificateSource, CertificateStatus, type CABundle, type Certificate,
} from "@/gen/rpmgr/v1/certificate_pb";
import { when } from "@/lib/format";
import { largestPage, listAll } from "@/lib/list-all";
import { useRoutes } from "@/routes-data";
import { useOrg } from "@/session";

// soon is when a certificate's or a token's expiry is near enough to point out: 21 days.
export const soon = 21 * 86400_000;

function useList<T>(key: string, orgId: string | undefined, page: (token: string) => Promise<{ items: T[]; next: string }>) {
  return useQuery({ queryKey: [key, orgId], enabled: !!orgId, queryFn: () => listAll(page) });
}

// useCertificates reads all of the org's certificates.
export function useCertificates(orgId: string | undefined) {
  const transport = useTransport();
  return useList("certificates", orgId, async (pageToken) => {
    const r = await createClient(CertificateService, transport).listCertificates({ orgId, pageSize: largestPage, pageToken });
    return { items: r.certificates, next: r.nextPageToken };
  });
}

// Certificates lists the org's certificates, from ACME or uploaded, with their names, expiry and the
// routes that use them; uploads one, renews an ACME one, and deletes one (docs/09-web-ui.md,
// "Information architecture").
export function Certificates() {
  const { t } = useTranslation();
  const org = useOrg();
  const list = useCertificates(org?.orgId);
  const routes = useRoutes(org?.orgId);
  const [uploading, setUploading] = useState(false);
  const routeName = (id: string) => routes.data?.find((r) => r.id === id)?.name ?? id;
  return (
    <section aria-labelledby="certs-title" className="grid gap-3">
      <div className="flex items-center gap-4">
        <h2 id="certs-title" className="text-lg font-semibold">{t("certs.title")}</h2>
        <Button size="sm" className="ml-auto" disabled={!org} onClick={() => setUploading(true)}>{t("certs.upload")}</Button>
      </div>
      {uploading && org && <UploadForm orgId={org.orgId} onDone={() => setUploading(false)} />}
      <ul className="grid gap-2">
        {(list.data ?? []).map((c) => <CertificateRow key={c.id} cert={c} routeName={routeName} />)}
      </ul>
      {list.data?.length === 0 && <p className="text-sm">{t("certs.none")}</p>}
    </section>
  );
}

// UploadForm uploads a certificate chain and its key; the key is cleared from the page once sent.
function UploadForm({ orgId, onDone }: { orgId: string; onDone: () => void }) {
  const { t } = useTranslation();
  const upload = useMutation(CertificateService.method.uploadCertificate);
  const queryClient = useQueryClient();
  const [requestId] = useState(() => crypto.randomUUID());
  const [chain, setChain] = useState("");
  const [key, setKey] = useState("");
  const [error, setError] = useState("");
  async function save(e: FormEvent) {
    e.preventDefault();
    setError("");
    try {
      await upload.mutateAsync({ orgId, chainPem: chain, privateKeyPem: key, requestId });
      setKey("");
      await queryClient.invalidateQueries();
      onDone();
    } catch (err) {
      setError(ConnectError.from(err).rawMessage);
    }
  }
  return (
    <form onSubmit={save} aria-label={t("certs.uploadTitle")} className="grid gap-3 rounded-md border border-border p-3" noValidate>
      <PemField label={t("certs.chain")} value={chain} onChange={setChain} />
      <PemField label={t("certs.key")} value={key} onChange={setKey} secret />
      {error && <Alert>{error}</Alert>}
      <div className="flex gap-2">
        <Button type="submit" disabled={upload.isPending || !chain || !key}>{t("certs.uploadSubmit")}</Button>
        <Button variant="outline" onClick={() => (setKey(""), onDone())}>{t("stepUp.cancel")}</Button>
      </div>
    </form>
  );
}

function CertificateRow({ cert: c, routeName }: { cert: Certificate; routeName: (id: string) => string }) {
  const { t } = useTranslation();
  const queryClient = useQueryClient();
  const renew = useMutation(CertificateService.method.renewCertificate);
  const remove = useMutation(CertificateService.method.deleteCertificate);
  const [asking, setAsking] = useState(false);
  const [message, setMessage] = useState<{ tone: "info" | "error"; text: string }>();
  const expires = c.notAfter ? timestampDate(c.notAfter) : undefined;
  const [now] = useState(() => Date.now()); // when the page showed the row
  const ending = expires !== undefined && expires.getTime() - now < soon;
  const name = c.sans[0] ?? c.id;
  async function act(run: () => Promise<{ text: string } | void>) {
    setMessage(undefined);
    try {
      const r = await run();
      if (r) {
        setMessage({ tone: "info", text: r.text });
      }
      await queryClient.invalidateQueries();
    } catch (err) {
      setMessage({ tone: "error", text: ConnectError.from(err).rawMessage });
    }
  }
  return (
    <li className="grid gap-1 rounded-md border border-border p-3 text-sm">
      <div className="flex flex-wrap items-center gap-3">
        <span className="font-medium">{c.sans.join(", ")}</span>
        <span className="text-muted-foreground">{t(c.source === CertificateSource.ACME ? "certs.acme" : "certs.uploaded")}</span>
        <span className={c.status === CertificateStatus.FAILED ? "text-destructive" : c.status === CertificateStatus.ACTIVE ? "text-ok" : "text-muted-foreground"}>
          {t(`certs.status.${CertificateStatus[c.status]}`)}
        </span>
      </div>
      {expires && <div className={ending ? "text-warn" : "text-muted-foreground"}>{t(ending ? "certs.endingSoon" : "certs.expires", { when: when(c.notAfter) })} · {c.issuer}</div>}
      {c.lastError && <div className="text-destructive">{c.lastError}</div>}
      {c.routeIds.length > 0 && <div className="text-muted-foreground">{t("certs.usedBy", { routes: c.routeIds.map(routeName).join(", ") })}</div>}
      <div className="flex flex-wrap items-center gap-2">
        {c.source === CertificateSource.ACME && (
          <Button size="sm" variant="outline" disabled={renew.isPending}
            onClick={() => void act(async () => ({ text: t((await renew.mutateAsync({ certificateId: c.id })).started ? "certs.renewing" : "certs.renewQueued") }))}>
            {t("certs.renew")}
          </Button>
        )}
        {asking ? (
          <>
            <span>{t("certs.ask", { name })}</span>
            <Button size="sm" variant="destructive" onClick={() => void act(async () => void (await remove.mutateAsync({ certificateId: c.id, etag: c.etag })))}>{t("targetForm.remove")}</Button>
            <Button size="sm" variant="outline" onClick={() => setAsking(false)}>{t("stepUp.cancel")}</Button>
          </>
        ) : (
          <Button size="sm" variant="outline" onClick={() => setAsking(true)}>{t("targetForm.removeAsk")}</Button>
        )}
      </div>
      {message && <Alert tone={message.tone}>{message.text}</Alert>}
    </li>
  );
}

// CABundles lists the org's CA bundles, which HTTPS targets verify their upstreams with, and
// creates, changes and deletes them.
export function CABundles() {
  const { t } = useTranslation();
  const org = useOrg();
  const transport = useTransport();
  const api = createClient(CertificateService, transport);
  const list = useList("ca-bundles", org?.orgId, async (pageToken) => {
    const r = await api.listCABundles({ orgId: org?.orgId, pageSize: largestPage, pageToken });
    return { items: r.caBundles, next: r.nextPageToken };
  });
  const [editing, setEditing] = useState<string>(); // a bundle's ID, or "new"
  return (
    <section aria-labelledby="bundles-title" className="grid gap-3">
      <div className="flex items-center gap-4">
        <h2 id="bundles-title" className="text-lg font-semibold">{t("bundles.title")}</h2>
        <Button size="sm" className="ml-auto" disabled={!org} onClick={() => setEditing("new")}>{t("bundles.add")}</Button>
        {org && <ManifestButton label={t("manifest.export")} title={t("manifest.ofKind", { what: t("bundles.title") })} orgId={org.orgId} kinds={["CABundle"]} file="ca-bundles" />}
      </div>
      {editing && org && (
        <BundleForm key={editing} orgId={org.orgId} bundle={list.data?.find((b) => b.id === editing)} onDone={() => setEditing(undefined)} />
      )}
      <ul className="grid gap-2">
        {(list.data ?? []).map((b) => <BundleRow key={b.id} bundle={b} onEdit={() => setEditing(b.id)} />)}
      </ul>
      {list.data?.length === 0 && <p className="text-sm">{t("bundles.none")}</p>}
    </section>
  );
}

function BundleForm({ orgId, bundle, onDone }: { orgId: string; bundle?: CABundle; onDone: () => void }) {
  const { t } = useTranslation();
  const add = useMutation(CertificateService.method.createCABundle);
  const update = useMutation(CertificateService.method.updateCABundle);
  const queryClient = useQueryClient();
  const [requestId] = useState(() => crypto.randomUUID());
  const [name, setName] = useState(bundle?.name ?? "");
  const [pem, setPem] = useState(bundle?.pem ?? "");
  const [error, setError] = useState("");
  async function save(e: FormEvent) {
    e.preventDefault();
    setError("");
    try {
      if (bundle) {
        const next = clone(CABundleSchema, bundle);
        Object.assign(next, { name: name.trim(), pem });
        await update.mutateAsync({ caBundle: next, updateMask: { paths: ["name", "pem"] }, etag: bundle.etag });
      } else {
        await add.mutateAsync({ orgId, caBundle: create(CABundleSchema, { name: name.trim(), pem }), requestId });
      }
      await queryClient.invalidateQueries();
      onDone();
    } catch (err) {
      setError(ConnectError.from(err).rawMessage);
    }
  }
  return (
    <form onSubmit={save} aria-label={t(bundle ? "bundles.editTitle" : "bundles.addTitle")} className="grid gap-3 rounded-md border border-border p-3" noValidate>
      <label className="grid gap-1 text-sm font-medium">{t("routeForm.fields.name")}<Input value={name} onChange={(e) => setName(e.target.value)} /></label>
      <PemField label={t("bundles.pem")} value={pem} onChange={setPem} />
      {error && <Alert>{error}</Alert>}
      <div className="flex gap-2">
        <Button type="submit" disabled={add.isPending || update.isPending}>{t(bundle ? "routeForm.save" : "bundles.addSubmit")}</Button>
        <Button variant="outline" onClick={onDone}>{t("stepUp.cancel")}</Button>
      </div>
    </form>
  );
}

function BundleRow({ bundle: b, onEdit }: { bundle: CABundle; onEdit: () => void }) {
  const { t } = useTranslation();
  const remove = useMutation(CertificateService.method.deleteCABundle);
  const queryClient = useQueryClient();
  const [asking, setAsking] = useState(false);
  const [error, setError] = useState("");
  return (
    <li className="grid gap-1 rounded-md border border-border p-3 text-sm">
      <span className="font-medium">{b.name}</span>
      <ul className="text-muted-foreground">
        {b.certificates.map((c, i) => <li key={i}>{t("bundles.cert", { subject: c.subject, when: when(c.notAfter) })}</li>)}
      </ul>
      <div className="text-muted-foreground">{t("bundles.targets", { count: b.targetIds.length })}</div>
      <div className="flex flex-wrap items-center gap-2">
        <Button size="sm" variant="outline" onClick={onEdit}>{t("targetForm.edit")}</Button>
        {asking ? (
          <>
            <span>{t("bundles.ask", { name: b.name })}</span>
            <Button size="sm" variant="destructive"
              onClick={() => void remove.mutateAsync({ caBundleId: b.id, etag: b.etag }).then(() => queryClient.invalidateQueries(), (err: unknown) => setError(ConnectError.from(err).rawMessage))}>
              {t("targetForm.remove")}
            </Button>
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
