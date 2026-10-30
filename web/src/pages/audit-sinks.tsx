// SPDX-License-Identifier: Apache-2.0

import type { MessageInitShape } from "@bufbuild/protobuf";
import { ConnectError } from "@connectrpc/connect";
import { useMutation, useQuery } from "@connectrpc/connect-query";
import { useQueryClient } from "@tanstack/react-query";
import type { TFunction } from "i18next";
import { DatabaseBackup } from "lucide-react";
import { useState, type FormEvent, type ReactNode } from "react";
import { useTranslation } from "react-i18next";
import { EmptyState } from "@/components/empty-state";
import { Field, labelClass } from "@/components/field";
import { PemField } from "@/components/pem-field";
import { Alert } from "@/components/public-page";
import { Row, RowList, panel } from "@/components/row-list";
import { Status, type Look } from "@/components/status";
import { Button } from "@/components/ui/button";
import { Card } from "@/components/ui/card";
import { Select } from "@/components/ui/input";
import { Switch } from "@/components/ui/switch";
import { AuditSinkKind, AuditSinkSchema, AuditSinkService, type AuditSink } from "@/gen/rpmgr/v1/audit_sink_pb";
import { serverProblems, type Problems } from "@/lib/api-error";
import { when } from "@/lib/format";
import { checkUrl, failure } from "@/pages/webhooks";
import { InstanceAdminPage } from "@/pages/settings";

// The shortest secret the API signs with, in bytes (docs/04-security.md, "Audit log").
const minSecret = 16;

// namePattern is the rule of a sink's name, as in the proto.
const namePattern = /^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$/;

// A Draft is what the form holds. The secret is write-only: it starts empty, also when a sink has
// one, and is sent only when typed.
interface Draft {
  name: string;
  kind: AuditSinkKind;
  url: string;
  secret: string;
  address: string;
  caBundle: string;
  entries: boolean;
  enabled: boolean;
}

// A KindSection is what one kind of sink adds to the form: its fields, what it checks before it
// sends anything, and the fields of the sink it writes. A new kind is a new entry of kinds.
interface KindSection {
  label: string;
  fields: (p: { draft: Draft; set: (d: Partial<Draft>) => void; problems: Problems; sink?: AuditSink }) => ReactNode;
  check: (t: TFunction, d: Draft, editing: boolean) => Problems;
  body: (d: Draft, editing: boolean) => { sink: MessageInitShape<typeof AuditSinkSchema>; paths: string[] };
  target: (s: AuditSink) => string;
}

const kinds: Partial<Record<AuditSinkKind, KindSection>> = {
  [AuditSinkKind.WEBHOOK]: {
    label: "auditSinks.kind.webhook",
    fields: (p) => <WebhookFields {...p} />,
    check: (t, d, editing) => {
      const p: Problems = {};
      const bad = checkUrl(t, d.url);
      if (bad) {
        p.url = bad;
      }
      if (d.secret ? d.secret.length < minSecret : !editing) {
        p.secret = t("auditSinks.secretShort", { count: minSecret });
      }
      return p;
    },
    body: (d, editing) => ({
      sink: { url: d.url, secret: d.secret },
      paths: ["url", ...(editing && d.secret === "" ? [] : ["secret"])],
    }),
    target: (s) => s.url,
  },
  [AuditSinkKind.SYSLOG]: {
    label: "auditSinks.kind.syslog",
    fields: (p) => <SyslogFields {...p} />,
    check: (t, d) => {
      const m = /^(.+):(\d{1,5})$/.exec(d.address);
      return m && Number(m[2]) >= 1 && Number(m[2]) <= 65535 ? {} : ({ address: t("auditSinks.addressInvalid") } as Problems);
    },
    body: (d) => ({ sink: { address: d.address, caBundle: d.caBundle }, paths: ["address", "ca_bundle"] }),
    target: (s) => s.address,
  },
};

function WebhookFields({ draft, set, problems, sink }: { draft: Draft; set: (d: Partial<Draft>) => void; problems: Problems; sink?: AuditSink }) {
  const { t } = useTranslation();
  return (
    <>
      <Field label={t("auditSinks.url")} hint={t("auditSinks.urlHint")} type="url" required maxLength={2048} error={problems.url}
        value={draft.url} onChange={(e) => set({ url: e.target.value })} />
      <Field label={t("auditSinks.secret")} type="password" autoComplete="new-password" maxLength={1024} required={!sink}
        hint={sink?.secretSet ? t("auditSinks.secretSet") : t("auditSinks.secretHint", { count: minSecret })} error={problems.secret}
        value={draft.secret} onChange={(e) => set({ secret: e.target.value })} />
    </>
  );
}

function SyslogFields({ draft, set, problems }: { draft: Draft; set: (d: Partial<Draft>) => void; problems: Problems }) {
  const { t } = useTranslation();
  return (
    <>
      <Field label={t("auditSinks.address")} hint={t("auditSinks.addressHint")} required maxLength={300} error={problems.address}
        value={draft.address} onChange={(e) => set({ address: e.target.value })} />
      <PemField label={t("auditSinks.caBundle")} value={draft.caBundle} onChange={(caBundle) => set({ caBundle })} />
      {problems.ca_bundle && <p className="text-xs text-destructive">{problems.ca_bundle}</p>}
      <p className="-mt-2 text-xs text-muted-foreground">{t("auditSinks.caHint")}</p>
    </>
  );
}

// AuditSinksPage is Settings → Audit sinks for the Instance Admin: the external destinations of
// the audit log with how far each is (docs/09-web-ui.md, "Live logs, webhooks and audit sinks
// (Phase 2)"). The API lets only the Instance Admin read or change a sink, so no one else sees
// more than a note.
export function AuditSinksPage() {
  const { t } = useTranslation();
  return (
    <InstanceAdminPage title={t("auditSinks.title")}>
      <AuditSinks />
    </InstanceAdminPage>
  );
}

function AuditSinks() {
  const { t } = useTranslation();
  const list = useQuery(AuditSinkService.method.listAuditSinks, {});
  const [adding, setAdding] = useState(false);
  const sinks = list.data?.auditSinks ?? [];
  return (
    <Card title={t("auditSinks.title")} description={t("auditSinks.intro")}
      actions={!adding && <Button onClick={() => setAdding(true)}>{t("auditSinks.new")}</Button>}>
      {adding && <SinkForm onDone={() => setAdding(false)} onCancel={() => setAdding(false)} />}
      {list.error && <Alert>{t("link.failed", { message: ConnectError.from(list.error).rawMessage })}</Alert>}
      {sinks.length > 0 && (
        <RowList aria-label={t("auditSinks.title")}>
          {sinks.map((s) => <Sink key={s.id} sink={s} />)}
        </RowList>
      )}
      {list.data && sinks.length === 0 && !adding && <EmptyState icon={DatabaseBackup}>{t("auditSinks.none")}</EmptyState>}
    </Card>
  );
}

// SinkForm creates a sink, or edits sink: the common fields, then the section of its kind.
function SinkForm({ sink, onDone, onCancel }: { sink?: AuditSink; onDone: () => void; onCancel: () => void }) {
  const { t } = useTranslation();
  const queryClient = useQueryClient();
  const create = useMutation(AuditSinkService.method.createAuditSink);
  const update = useMutation(AuditSinkService.method.updateAuditSink);
  const [draft, setDraft] = useState<Draft>({
    name: sink?.name ?? "", kind: sink?.kind ?? AuditSinkKind.WEBHOOK, url: sink?.url ?? "", secret: "", address: sink?.address ?? "",
    caBundle: sink?.caBundle ?? "", entries: sink?.entries ?? true, enabled: sink?.enabled ?? true,
  });
  const [problems, setProblems] = useState<Problems>({});
  const [error, setError] = useState("");
  const set = (d: Partial<Draft>) => setDraft((old) => ({ ...old, ...d }));
  const section = kinds[draft.kind]!;

  async function submit(e: FormEvent) {
    e.preventDefault();
    setError("");
    const found = section.check(t, draft, !!sink);
    if (!namePattern.test(draft.name)) {
      found.name = t("violations.name");
    }
    setProblems(found);
    if (Object.keys(found).length > 0) {
      return;
    }
    const w = section.body(draft, !!sink);
    try {
      if (sink) {
        await update.mutateAsync({ auditSink: { ...w.sink, id: sink.id, name: draft.name, entries: draft.entries, enabled: draft.enabled },
          updateMask: { paths: ["name", "entries", "enabled", ...w.paths] }, etag: sink.etag });
      } else {
        await create.mutateAsync({ auditSink: { ...w.sink, name: draft.name, kind: draft.kind, entries: draft.entries, enabled: true } });
      }
      await queryClient.invalidateQueries();
      onDone();
    } catch (err) {
      const fields = serverProblems(t, err);
      setProblems(fields);
      // An answer that names fields shows them there; any other answer is told above the buttons.
      setError(Object.keys(fields).length > 0 ? "" : failure(t, err));
    }
  }

  return (
    <form onSubmit={submit} className={panel} noValidate aria-label={t(sink ? "auditSinks.edit" : "auditSinks.new")}>
      <Field label={t("auditSinks.name")} hint={t("violations.nameHint")} required maxLength={63} error={problems.name}
        value={draft.name} onChange={(e) => set({ name: e.target.value })} />
      {!sink && (
        <div className="grid gap-1.5">
          <label htmlFor="audit-sink-kind" className={labelClass()}>{t("auditSinks.kindLabel")}</label>
          <Select id="audit-sink-kind" className="justify-self-start" value={draft.kind} onChange={(e) => set({ kind: Number(e.target.value) })}>
            {Object.entries(kinds).map(([k, v]) => <option key={k} value={k}>{t(v.label)}</option>)}
          </Select>
        </div>
      )}
      {section.fields({ draft, set, problems, sink })}
      <Switch checked={draft.entries} onClick={() => set({ entries: !draft.entries })} className="justify-self-start">{t("auditSinks.entries")}</Switch>
      <p className="-mt-2 text-xs text-muted-foreground">{t("auditSinks.entriesHint")}</p>
      {error && <Alert>{error}</Alert>}
      <div className="flex gap-2">
        <Button type="submit" disabled={create.isPending || update.isPending}>{t(sink ? "auditSinks.save" : "auditSinks.create")}</Button>
        <Button type="button" variant="outline" onClick={onCancel}>{t("stepUp.cancel")}</Button>
      </div>
    </form>
  );
}

// stateOf is the state of a sink: its look and its words. A sink that failed last is told so
// whether or not it ships.
function stateOf(t: TFunction, s: AuditSink): { look: Look; text: string } {
  const failing = !!s.status?.lastError;
  if (!s.enabled) {
    return { look: failing ? "alert" : "off", text: t(failing ? "auditSinks.state.disabledFailing" : "auditSinks.state.disabled") };
  }
  return failing ? { look: "warn", text: t("auditSinks.state.failing") } : { look: "ok", text: t("auditSinks.state.enabled") };
}

// Sink is one sink with its status and actions: edit, enable or disable, test and delete.
function Sink({ sink: s }: { sink: AuditSink }) {
  const { t } = useTranslation();
  const queryClient = useQueryClient();
  const update = useMutation(AuditSinkService.method.updateAuditSink);
  const remove = useMutation(AuditSinkService.method.deleteAuditSink);
  const test = useMutation(AuditSinkService.method.testAuditSink);
  const [editing, setEditing] = useState(false);
  const [asking, setAsking] = useState(false);
  const [error, setError] = useState("");
  const [tested, setTested] = useState<{ ok: boolean; text: string }>();
  const state = stateOf(t, s);
  const st = s.status;
  const busy = update.isPending || remove.isPending || test.isPending;

  // run does a change and reloads; its failure is shown in the row.
  async function run(change: () => Promise<void>) {
    setError("");
    try {
      await change();
      await queryClient.invalidateQueries();
    } catch (err) {
      setError(failure(t, err));
    } finally {
      setAsking(false);
    }
  }

  if (editing) {
    return <Row><SinkForm sink={s} onCancel={() => setEditing(false)} onDone={() => setEditing(false)} /></Row>;
  }
  return (
    <Row>
      <div className="flex flex-wrap items-center gap-x-3 gap-y-1">
        <span className="font-medium">{s.name}</span>
        <span className="text-muted-foreground">{t(kinds[s.kind]?.label ?? "auditSinks.kind.other")}</span>
        <Status look={state.look}>{state.text}</Status>
      </div>
      <div className="text-muted-foreground">
        <span className="break-all">{kinds[s.kind]?.target(s)}</span>
        {" · "}{t(s.entries ? "auditSinks.withEntries" : "auditSinks.checkpointsOnly")}
        {s.kind === AuditSinkKind.WEBHOOK && ` · ${t(s.secretSet ? "auditSinks.secretIsSet" : "auditSinks.secretIsNotSet")}`}
      </div>
      <dl className="grid grid-cols-[max-content_1fr] gap-x-4 gap-y-1">
        <dt className="text-muted-foreground">{t("auditSinks.lastSuccess")}</dt>
        <dd>{st?.lastSuccessTime ? when(st.lastSuccessTime) : t("auditSinks.never")}</dd>
        <dt className="text-muted-foreground">{t("auditSinks.backlog")}</dt>
        <dd>{st && st.backlog > 0n ? t("auditSinks.waiting", { count: Number(st.backlog), since: when(st.oldestUnshippedTime) }) : t("auditSinks.noBacklog")}</dd>
        {st?.lastError && (
          <>
            <dt className="text-muted-foreground">{t("auditSinks.lastError")}</dt>
            <dd className="break-words text-destructive">{st.lastError}</dd>
          </>
        )}
      </dl>
      {error && <Alert>{error}</Alert>}
      {tested && <p role="status" className={tested.ok ? "text-sm" : "text-sm text-destructive"}>{tested.text}</p>}
      {asking ? (
        <div className="flex flex-wrap items-center gap-2">
          {t("auditSinks.deleteAsk", { name: s.name })}
          <Button size="sm" variant="destructive" disabled={busy} onClick={() => void run(async () => void (await remove.mutateAsync({ auditSinkId: s.id, etag: s.etag })))}>
            {t("auditSinks.delete")}
          </Button>
          <Button size="sm" variant="outline" onClick={() => setAsking(false)}>{t("stepUp.cancel")}</Button>
        </div>
      ) : (
        <div className="flex flex-wrap gap-2">
          <Button size="sm" variant="outline" disabled={busy} onClick={() => setEditing(true)}>{t("auditSinks.edit")}</Button>
          <Button size="sm" variant="outline" disabled={busy}
            onClick={() => void run(async () => void (await update.mutateAsync({ auditSink: { id: s.id, enabled: !s.enabled }, updateMask: { paths: ["enabled"] }, etag: s.etag })))}>
            {t(s.enabled ? "auditSinks.disable" : "auditSinks.enable")}
          </Button>
          <Button size="sm" variant="outline" disabled={busy}
            onClick={() => void run(async () => {
              const r = await test.mutateAsync({ auditSinkId: s.id });
              setTested(r.ok ? { ok: true, text: t("auditSinks.testOk") } : { ok: false, text: t("auditSinks.testFailed", { reason: r.error }) });
            })}>
            {t("auditSinks.test")}
          </Button>
          <Button size="sm" variant="outline" disabled={busy} onClick={() => setAsking(true)}>{t("auditSinks.deleteStart")}</Button>
        </div>
      )}
    </Row>
  );
}
