// SPDX-License-Identifier: Apache-2.0

import { Code, ConnectError, createClient } from "@connectrpc/connect";
import { useMutation, useTransport } from "@connectrpc/connect-query";
import { useQueryClient } from "@tanstack/react-query";
import { useNavigate } from "@tanstack/react-router";
import { useEffect, useRef, useState, type FormEvent } from "react";
import { useTranslation } from "react-i18next";
import { Field } from "@/components/field";
import { Alert } from "@/components/public-page";
import { Button } from "@/components/ui/button";
import { AgentRole, EnrollmentService } from "@/gen/rpmgr/v1/enrollment_pb";
import { StatusService } from "@/gen/rpmgr/v1/status_pb";
import { Reason, reasonOf } from "@/lib/errors";
import { useGroupNames } from "@/routes-data";
import { useStepUp } from "@/step-up";

// The token lifetimes offered, in seconds; the API allows up to 30 days (docs/04-security.md).
const lifetimes = [900, 3600, 86400, 7 * 86400, 30 * 86400];

const lines = (v: string) => v.split("\n").map((l) => l.trim()).filter(Boolean);

// mask hides a token but its kind and its checksum (docs/09-web-ui.md, "Enroll connector dialog").
export function mask(token: string): string {
  const i = token.lastIndexOf("_");
  return `${token.slice(0, "rpmgr_enr_".length)}${"•".repeat(12)}${token.slice(i)}`;
}

// EnrollDialog mints an enrollment token after a step-up and shows the install command, which never
// holds the token, and the token once, masked; it then waits for the new connector and opens its
// page (docs/09-web-ui.md, "Enroll connector dialog"; docs/04-security.md, "Join command").
export function EnrollDialog({ orgId, known, onClose }: { orgId: string; known: Set<string>; onClose: () => void }) {
  const { t } = useTranslation();
  const dialog = useRef<HTMLDialogElement>(null);
  const groups = useGroupNames(orgId);
  const stepUp = useStepUp();
  const create = useMutation(EnrollmentService.method.createEnrollmentToken);
  const command = useMutation(EnrollmentService.method.getInstallCommand);
  const queryClient = useQueryClient();
  const [form, setForm] = useState({ labels: "", group: "", ephemeral: false, uses: "1", lifetime: "3600", targets: "" });
  const [result, setResult] = useState<{ token: string; command: string; lifetime: number }>();
  const [show, setShow] = useState(false);
  const [error, setError] = useState("");
  const [requestId] = useState(() => crypto.randomUUID());
  const [before] = useState(known); // the connectors when the dialog opened
  const [enrolled, setEnrolled] = useWaitForConnector(orgId, before, !!result);
  const navigate = useNavigate();
  useEffect(() => dialog.current?.showModal(), []);
  useEffect(() => {
    if (enrolled) {
      void queryClient.invalidateQueries();
      void navigate({ to: "/connectors/$connectorId", params: { connectorId: enrolled } });
      setEnrolled(undefined);
    }
  }, [enrolled, navigate, queryClient, setEnrolled]);

  async function submit(e: FormEvent) {
    e.preventDefault();
    setError("");
    const uses = form.ephemeral ? Number(form.uses) : 1;
    if (!Number.isInteger(uses) || uses < 0) {
      setError(t("enroll.uses"));
      return;
    }
    const labels = Object.fromEntries(lines(form.labels).map((l) => {
      const i = l.indexOf("=");
      return i < 0 ? [l, ""] : [l.slice(0, i).trim(), l.slice(i + 1).trim()];
    }));
    try {
      const tok = await stepUp(() => create.mutateAsync({
        orgId, labels, ephemeral: form.ephemeral, maxUses: uses, ttl: { seconds: BigInt(form.lifetime) }, gatewayGroupId: form.group, requestId,
      }));
      const cmd = await command.mutateAsync({ orgId, role: AgentRole.CONNECTOR, allowTargets: lines(form.targets) });
      setResult({ token: tok.token, command: cmd.command, lifetime: Number(form.lifetime) });
    } catch (err) {
      const e = ConnectError.from(err);
      if (reasonOf(err) !== Reason.stepUpRequired) {
        setError(e.code === Code.InvalidArgument || e.code === Code.PermissionDenied ? e.rawMessage : t("link.failed", { message: e.rawMessage }));
      }
    }
  }

  return (
    <dialog ref={dialog} aria-labelledby="enroll-title" onCancel={onClose}
      className="m-auto w-full max-w-2xl rounded-lg border border-border bg-background p-6 text-foreground backdrop:bg-black/50">
      <h2 id="enroll-title" className="text-lg font-semibold">{t("enroll.title")}</h2>
      {!result ? (
        <form onSubmit={submit} className="mt-4 grid gap-3" noValidate>
          <label className="grid gap-1.5 text-sm font-medium">
            {t("routeForm.fields.labels")}
            <textarea rows={2} className="rounded-md border border-border bg-background px-3 py-1.5 font-normal" value={form.labels}
              onChange={(e) => setForm({ ...form, labels: e.target.value })} />
          </label>
          <label className="grid gap-1.5 text-sm font-medium">
            {t("routes.group")}
            <select className="h-9 rounded-md border border-border bg-background px-2 font-normal" value={form.group} onChange={(e) => setForm({ ...form, group: e.target.value })}>
              <option value="">{t("enroll.anyGroup")}</option>
              {[...(groups.data ?? new Map<string, string>())].map(([id, n]) => <option key={id} value={id}>{n}</option>)}
            </select>
          </label>
          <fieldset className="grid gap-1.5">
            <legend className="text-sm font-medium">{t("enroll.kind")}</legend>
            <div className="flex gap-4 text-sm">
              <label className="flex items-center gap-1.5"><input type="radio" name="kind" checked={!form.ephemeral} onChange={() => setForm({ ...form, ephemeral: false })} />{t("enroll.permanent")}</label>
              <label className="flex items-center gap-1.5"><input type="radio" name="kind" checked={form.ephemeral} onChange={() => setForm({ ...form, ephemeral: true })} />{t("enroll.ephemeral")}</label>
            </div>
          </fieldset>
          <label className="grid gap-1.5 text-sm font-medium">
            {t("enroll.lifetime")}
            <select className="h-9 rounded-md border border-border bg-background px-2 font-normal" value={form.lifetime} onChange={(e) => setForm({ ...form, lifetime: e.target.value })}>
              {lifetimes.map((s) => <option key={s} value={String(s)}>{t(`enroll.lifetimes.${s}`)}</option>)}
            </select>
          </label>
          {form.ephemeral && (
            <Field label={t("enroll.usesLabel")} hint={t("enroll.usesHint")} inputMode="numeric" value={form.uses} onChange={(e) => setForm({ ...form, uses: e.target.value })} />
          )}
          <label className="grid gap-1.5 text-sm font-medium">
            {t("enroll.targets")}
            <textarea rows={2} className="rounded-md border border-border bg-background px-3 py-1.5 font-normal" value={form.targets}
              onChange={(e) => setForm({ ...form, targets: e.target.value })} />
            <span className="text-xs font-normal text-muted-foreground">{t("enroll.targetsHint")}</span>
          </label>
          {error && <Alert>{error}</Alert>}
          <div className="flex justify-end gap-2">
            <Button variant="outline" onClick={onClose}>{t("stepUp.cancel")}</Button>
            <Button type="submit" disabled={create.isPending || command.isPending}>{t("enroll.create")}</Button>
          </div>
        </form>
      ) : (
        <div className="mt-4 grid gap-3 text-sm">
          <p>{t("enroll.step1")}</p>
          <div className="flex items-start gap-2">
            <pre aria-label={t("enroll.command")} className="grow overflow-x-auto rounded bg-muted p-2 font-mono text-xs">{result.command}</pre>
            <Button size="sm" variant="outline" onClick={() => void navigator.clipboard?.writeText(result.command)}>{t("mfa.copy")}</Button>
          </div>
          <p>{t("enroll.step2")}</p>
          <div className="flex items-center gap-2">
            <code aria-label={t("enroll.token")} className="grow break-all rounded bg-muted p-2 font-mono text-xs">{show ? result.token : mask(result.token)}</code>
            <Button size="sm" variant="outline" onClick={() => void navigator.clipboard?.writeText(result.token)}>{t("mfa.copy")}</Button>
            <Button size="sm" variant="outline" aria-pressed={show} onClick={() => setShow(!show)}>{t(show ? "enroll.hide" : "enroll.show")}</Button>
          </div>
          <p className="text-muted-foreground">{t(`enroll.note`, { lifetime: t(`enroll.lifetimes.${result.lifetime}`) })}</p>
          <p role="status" className="flex items-center gap-2"><span aria-hidden="true">⧗</span>{t("enroll.waiting")}</p>
          <div className="flex justify-end"><Button variant="outline" onClick={onClose}>{t("enroll.close")}</Button></div>
        </div>
      )}
    </dialog>
  );
}

// useWaitForConnector follows the org's events while active and returns a connector that was not
// known before once its control session is up (docs/07-api.md, "Events and streaming").
function useWaitForConnector(orgId: string, known: Set<string>, active: boolean) {
  const transport = useTransport();
  const [connected, setConnected] = useState<string>();
  useEffect(() => {
    if (!active) {
      return;
    }
    const abort = new AbortController();
    void (async () => {
      try {
        const events = createClient(StatusService, transport).watchEvents({ orgId }, { signal: abort.signal });
        for await (const e of events) {
          const up = e.statusChanged.find((id) => id.startsWith("con_") && !known.has(id));
          if (up) {
            setConnected(up);
            return;
          }
        }
      } catch {
        // The watch ended, or the dialog closed.
      }
    })();
    return () => abort.abort();
  }, [orgId, known, active, transport]);
  return [connected, setConnected] as const;
}
