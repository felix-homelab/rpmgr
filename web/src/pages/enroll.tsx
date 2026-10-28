// SPDX-License-Identifier: Apache-2.0

import { Code, ConnectError, createClient } from "@connectrpc/connect";
import { useMutation, useTransport } from "@connectrpc/connect-query";
import { useQueryClient } from "@tanstack/react-query";
import { useNavigate } from "@tanstack/react-router";
import { LoaderCircle } from "lucide-react";
import { useEffect, useRef, useState, type FormEvent } from "react";
import { useTranslation } from "react-i18next";
import { Field } from "@/components/field";
import { Command, OneTimeToken } from "@/components/one-time-token";
import { Alert } from "@/components/public-page";
import { Button } from "@/components/ui/button";
import { Select, Textarea } from "@/components/ui/input";
import { AgentRole, EnrollmentService } from "@/gen/rpmgr/v1/enrollment_pb";
import { StatusService } from "@/gen/rpmgr/v1/status_pb";
import { apiError } from "@/lib/api-error";
import { Reason, reasonOf } from "@/lib/errors";
import { useGroupNames } from "@/routes-data";
import { useStepUp } from "@/step-up";

// The token lifetimes offered, in seconds; the API allows up to 30 days (docs/04-security.md).
const lifetimes = [900, 3600, 86400, 7 * 86400, 30 * 86400];

const lines = (v: string) => v.split("\n").map((l) => l.trim()).filter(Boolean);

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
  const [form, setForm] = useState({ labels: "", group: "", ephemeral: false, uses: "1", lifetime: "3600", targets: "", denied: "" });
  const [result, setResult] = useState<{ token: string; command: string; lifetime: number }>();
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
      const cmd = await command.mutateAsync({ orgId, role: AgentRole.CONNECTOR, allowTargets: lines(form.targets), denyTargets: lines(form.denied) });
      setResult({ token: tok.token, command: cmd.command, lifetime: Number(form.lifetime) });
    } catch (err) {
      const e = ConnectError.from(err);
      if (reasonOf(err) !== Reason.stepUpRequired) {
        setError(e.code === Code.InvalidArgument ? apiError(t, err) : e.code === Code.PermissionDenied ? e.rawMessage : t("link.failed", { message: e.rawMessage }));
      }
    }
  }

  return (
    <dialog ref={dialog} aria-labelledby="enroll-title" onCancel={onClose}
      className="m-auto w-[calc(100%-2rem)] max-w-3xl rounded-xl border border-border bg-card p-6 shadow-2xl">
      <h2 id="enroll-title" className="text-lg font-semibold">{t("enroll.title")}</h2>
      {!result ? (
        <form onSubmit={submit} className="mt-5 grid gap-4" noValidate>
          <label className="grid gap-1.5 text-sm font-medium">
            {t("routeForm.fields.labels")}
            <Textarea rows={2} className="font-normal" value={form.labels} onChange={(e) => setForm({ ...form, labels: e.target.value })} />
          </label>
          <label className="grid gap-1.5 text-sm font-medium">
            {t("routes.group")}
            <Select className="font-normal" value={form.group} onChange={(e) => setForm({ ...form, group: e.target.value })}>
              <option value="">{t("enroll.anyGroup")}</option>
              {[...(groups.data ?? new Map<string, string>())].map(([id, n]) => <option key={id} value={id}>{n}</option>)}
            </Select>
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
            <Select className="font-normal" value={form.lifetime} onChange={(e) => setForm({ ...form, lifetime: e.target.value })}>
              {lifetimes.map((s) => <option key={s} value={String(s)}>{t(`enroll.lifetimes.${s}`)}</option>)}
            </Select>
          </label>
          {form.ephemeral && (
            <Field label={t("enroll.usesLabel")} hint={t("enroll.usesHint")} inputMode="numeric" value={form.uses} onChange={(e) => setForm({ ...form, uses: e.target.value })} />
          )}
          <label className="grid gap-1.5 text-sm font-medium">
            {t("enroll.targets")}
            <Textarea rows={2} className="font-normal" value={form.targets} onChange={(e) => setForm({ ...form, targets: e.target.value })} />
            <span className="text-xs font-normal text-muted-foreground">{t("enroll.targetsHint")}</span>
          </label>
          <label className="grid gap-1.5 text-sm font-medium">
            {t("enroll.denied")}
            <Textarea rows={1} className="font-normal" value={form.denied} onChange={(e) => setForm({ ...form, denied: e.target.value })} />
            <span className="text-xs font-normal text-muted-foreground">{t("enroll.deniedHint")}</span>
          </label>
          {error && <Alert>{error}</Alert>}
          <div className="flex justify-end gap-2">
            <Button variant="outline" onClick={onClose}>{t("stepUp.cancel")}</Button>
            <Button type="submit" disabled={create.isPending || command.isPending}>{t("enroll.create")}</Button>
          </div>
        </form>
      ) : (
        <div className="mt-5 grid gap-3 text-sm">
          <p>{t("enroll.step1")}</p>
          <Command command={result.command} label={t("enroll.command")} />
          <p>{t("enroll.step2")}</p>
          <OneTimeToken token={result.token} label={t("enroll.token")} />
          <p className="text-muted-foreground">{t(`enroll.note`, { lifetime: t(`enroll.lifetimes.${result.lifetime}`) })}</p>
          <p role="status" className="flex items-center gap-2 text-muted-foreground">
            <LoaderCircle aria-hidden="true" className="size-4 animate-spin motion-reduce:animate-none" />{t("enroll.waiting")}
          </p>
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
