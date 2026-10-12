// SPDX-License-Identifier: Apache-2.0

import { clone } from "@bufbuild/protobuf";
import { ConnectError } from "@connectrpc/connect";
import { useMutation, useQuery } from "@connectrpc/connect-query";
import { useQueryClient } from "@tanstack/react-query";
import { Link } from "@tanstack/react-router";
import { useId, useState, type FormEvent, type ReactNode } from "react";
import { useTranslation } from "react-i18next";
import { PageHeader } from "@/components/page-header";
import { Alert } from "@/components/public-page";
import { Button } from "@/components/ui/button";
import { Card } from "@/components/ui/card";
import { Input, Select, Textarea } from "@/components/ui/input";
import { AuthService } from "@/gen/rpmgr/v1/auth_pb";
import { InstanceSettingsSchema, OrgSettingsSchema, SettingsService, type InstanceSettings, type OrgSettings } from "@/gen/rpmgr/v1/settings_pb";
import { Reason, reasonOf } from "@/lib/errors";
import { when } from "@/lib/format";
import { settingFields, withRelay, type Section, type SettingField } from "@/pages/settings-fields";
import { useGroups } from "@/routes-data";
import { useOrg } from "@/session";
import { useStepUp } from "@/step-up";

type Message = { tone: "info" | "error"; text: string } | undefined;

// check is the look of a checkbox with its label.
const check = "flex items-center gap-2.5 text-sm";

const etagMismatch = "ETAG_MISMATCH";

// failure is what a settings save's error says; nothing for a cancelled step-up.
function failure(err: unknown, t: (k: string) => string): Message {
  const reason = reasonOf(err);
  if (reason === Reason.stepUpRequired) {
    return undefined;
  }
  return { tone: "error", text: reason === etagMismatch ? t("settings.changed") : ConnectError.from(err).rawMessage };
}

// Settings shows the org's runtime settings, which its Owner changes, and to the Instance Admin
// the instance's, with links to the PKI and Updates pages (docs/09-web-ui.md, "Information
// architecture" and "Settings"; docs/10-operations.md, "Runtime settings").
export function Settings() {
  const { t } = useTranslation();
  const org = useOrg();
  const session = useQuery(AuthService.method.getSession, {});
  const admin = session.data?.instanceAdmin ?? false;
  return (
    <div className="grid max-w-3xl gap-6">
      <PageHeader title={t("settings.title")} description={t("settings.intro")} />
      {admin && <Tabs />}
      {admin && <RevocationLogNotice />}
      {org && <OrgSettingsSection orgId={org.orgId} owner={org.role === "owner"} />}
      {admin && <InstanceSettingsSection title={t("settings.instance")} sections={["agents", "endpoints", "traffic", "acme", "mail", "audit"]} />}
    </div>
  );
}

// Tabs lead the Instance Admin between the settings and the instance's PKI and Updates pages.
function Tabs() {
  const { t } = useTranslation();
  const tab = "-mb-px border-b-2 border-transparent px-1 pb-2.5 font-medium text-muted-foreground transition-colors hover:text-foreground [&.active]:border-primary [&.active]:text-foreground";
  return (
    <nav aria-label={t("settings.pages")} className="flex gap-6 border-b border-border text-sm">
      <Link to="/settings" activeOptions={{ exact: true }} className={tab}>{t("settings.title")}</Link>
      <Link to="/settings/pki" className={tab}>{t("settings.pki")}</Link>
      <Link to="/settings/updates" className={tab}>{t("settings.updates")}</Link>
    </nav>
  );
}

// RevocationLogNotice shows the Instance Admin where the revocation log stands
// (docs/10-operations.md, "Backup and restore"): the alert when entries have waited more than
// 5 minutes for the sink, the standing warning when no sink keeps a copy off the host, nothing
// otherwise.
function RevocationLogNotice() {
  const { t } = useTranslation();
  const st = useQuery(SettingsService.method.getInstanceSettings, {}).data?.revocationLog;
  if (!st) {
    return null;
  }
  if (st.alert) {
    return (
      <p role="alert" className="rounded-xl border border-destructive/30 bg-destructive/8 p-4 text-sm text-destructive">
        {t("settings.revlogAlert", { count: Number(st.unshipped), since: when(st.oldestUnshippedTime) })}
      </p>
    );
  }
  if (!st.sink) {
    return <p role="status" className="rounded-xl border border-warn/40 bg-warn/10 p-4 text-sm">{t("settings.revlogNoSink")}</p>;
  }
  return null;
}

// Updates shows the release check and the update channel to the Instance Admin; uploading a
// manifest for an air-gapped install comes with Phase 2 (docs/04-security.md, "Over-the-air
// updates").
export function Updates() {
  const { t } = useTranslation();
  return (
    <InstanceAdminPage title={t("settings.updates")}>
      <InstanceSettingsSection title={t("settings.updates")} sections={["updates"]} />
    </InstanceAdminPage>
  );
}

// InstanceAdminPage shows its children only to the Instance Admin.
export function InstanceAdminPage({ title, children }: { title: string; children: ReactNode }) {
  const { t } = useTranslation();
  const session = useQuery(AuthService.method.getSession, {});
  const admin = session.data?.instanceAdmin;
  return (
    <div className="grid max-w-3xl gap-6">
      <PageHeader title={title} />
      {admin ? <Tabs /> : <Link to="/settings" className="justify-self-start text-sm underline">{t("settings.title")}</Link>}
      {session.data && (admin ? children : <p className="text-sm text-muted-foreground">{t("settings.adminOnly")}</p>)}
    </div>
  );
}

// OrgSettingsSection keeps the outcome of a save, since a new etag remounts the form with the
// settings as they are now.
function OrgSettingsSection({ orgId, owner }: { orgId: string; owner: boolean }) {
  const { t } = useTranslation();
  const got = useQuery(SettingsService.method.getOrgSettings, { orgId });
  const [message, setMessage] = useState<Message>();
  return (
    <Card title={t("settings.org")} description={!owner && t("settings.ownerOnly")}>
      {got.data?.settings && (
        <OrgForm key={got.data.etag} orgId={orgId} settings={got.data.settings} etag={got.data.etag} disabled={!owner} onDone={setMessage} />
      )}
      {message && <Alert tone={message.tone}>{message.text}</Alert>}
    </Card>
  );
}

// OrgForm saves the org's settings as read with its fields changed, their mask and the etag; a
// change of require_mfa asks for a step-up.
function OrgForm({ orgId, settings, etag, disabled, onDone }: {
  orgId: string; settings: OrgSettings; etag: string; disabled: boolean; onDone: (m: Message) => void;
}) {
  const { t } = useTranslation();
  const groups = useGroups(orgId);
  const stepUp = useStepUp();
  const update = useMutation(SettingsService.method.updateOrgSettings);
  const queryClient = useQueryClient();
  const [form, setForm] = useState({ mfa: settings.requireMfa ?? false, enroll: settings.operatorsMayEnroll ?? false, group: settings.defaultGatewayGroupId });
  async function save(e: FormEvent) {
    e.preventDefault();
    onDone(undefined);
    const next = clone(OrgSettingsSchema, settings);
    Object.assign(next, { requireMfa: form.mfa, operatorsMayEnroll: form.enroll, defaultGatewayGroupId: form.group });
    try {
      await stepUp(() => update.mutateAsync({ orgId, settings: next, etag, updateMask: { paths: ["require_mfa", "operators_may_enroll", "default_gateway_group_id"] } }));
      onDone({ tone: "info", text: t("account.saved") });
    } catch (err) {
      onDone(failure(err, t));
      if (reasonOf(err) !== etagMismatch) {
        return;
      }
    }
    await queryClient.invalidateQueries();
  }
  return (
    <form onSubmit={save} aria-label={t("settings.org")} noValidate>
      <fieldset disabled={disabled} className="grid gap-4">
        <label className={check}>
          <input type="checkbox" className="size-4 accent-primary" checked={form.mfa} onChange={(e) => setForm({ ...form, mfa: e.target.checked })} />
          {t("settings.requireMfa")}
        </label>
        <label className={check}>
          <input type="checkbox" className="size-4 accent-primary" checked={form.enroll} onChange={(e) => setForm({ ...form, enroll: e.target.checked })} />
          {t("settings.operatorsMayEnroll")}
        </label>
        <label className="grid gap-1.5 text-sm font-medium">
          {t("settings.defaultGroup")}
          <Select className="font-normal" value={form.group} onChange={(e) => setForm({ ...form, group: e.target.value })}>
            <option value="">{t("settings.none")}</option>
            {(groups.data ?? []).map((g) => <option key={g.id} value={g.id}>{g.name}</option>)}
          </Select>
        </label>
        <Button type="submit" className="justify-self-start" disabled={update.isPending}>{t("routeForm.save")}</Button>
      </fieldset>
    </form>
  );
}

// InstanceSettingsSection edits the instance settings of the given sections, and only those.
export function InstanceSettingsSection({ title, sections }: { title: string; sections: Section[] }) {
  const got = useQuery(SettingsService.method.getInstanceSettings, {});
  const [message, setMessage] = useState<Message>();
  const fields = settingFields.filter((f) => sections.includes(f.section));
  return (
    <Card title={title}>
      {got.data?.settings && (
        <InstanceForm key={got.data.etag} title={title} sections={sections} fields={fields} settings={got.data.settings} etag={got.data.etag} onDone={setMessage} />
      )}
      {message && <Alert tone={message.tone}>{message.text}</Alert>}
      {got.data && sections.includes("mail") && <SmtpPassword set={got.data.smtpPasswordSet} />}
    </Card>
  );
}

// InstanceForm saves the instance's settings as read with its fields changed, their mask and the
// etag.
function InstanceForm({ title, sections, fields, settings, etag, onDone }: {
  title: string; sections: Section[]; fields: SettingField[]; settings: InstanceSettings; etag: string; onDone: (m: Message) => void;
}) {
  const { t } = useTranslation();
  const update = useMutation(SettingsService.method.updateInstanceSettings);
  const queryClient = useQueryClient();
  const [values, setValues] = useState(() => Object.fromEntries(fields.map((f) => [f.key, f.get(settings)])));
  async function save(e: FormEvent) {
    e.preventDefault();
    const bad = fields.filter((f) => f.kind === "days" && !/^\d*$/.test((values[f.key] ?? "").trim()));
    if (bad.length > 0) {
      onDone({ tone: "error", text: t("settings.days", { fields: bad.map((f) => t(`settings.fields.${f.key}`)).join(", ") }) });
      return;
    }
    onDone(undefined);
    const next = clone(InstanceSettingsSchema, settings);
    fields.forEach((f) => f.set(next, values[f.key] ?? ""));
    try {
      await update.mutateAsync({ settings: withRelay(next), etag, updateMask: { paths: [...new Set(fields.map((f) => f.mask))] } });
      onDone({ tone: "info", text: t("account.saved") });
    } catch (err) {
      onDone(failure(err, t));
      if (reasonOf(err) !== etagMismatch) {
        return;
      }
    }
    await queryClient.invalidateQueries();
  }
  return (
    <form onSubmit={save} aria-label={title} className="grid gap-5" noValidate>
      {sections.map((sec) => (
        <fieldset key={sec} className="grid gap-4 border-border not-first:border-t not-first:pt-5">
          {sections.length > 1 && <legend className="float-left w-full text-sm font-semibold">{t(`settings.sections.${sec}`)}</legend>}
          {fields.filter((f) => f.section === sec).map((f) => (
            <SettingInput key={f.key} field={f} value={values[f.key] ?? ""} onChange={(v) => setValues({ ...values, [f.key]: v })} />
          ))}
        </fieldset>
      ))}
      <Button type="submit" className="justify-self-start" disabled={update.isPending}>{t("routeForm.save")}</Button>
    </form>
  );
}

function SettingInput({ field: f, value, onChange }: { field: SettingField; value: string; onChange: (v: string) => void }) {
  const { t, i18n } = useTranslation();
  const id = useId();
  const label = t(`settings.fields.${f.key}`);
  if (f.kind === "bool") {
    return (
      <label className={check}>
        <input type="checkbox" className="size-4 accent-primary" checked={value === "true"} onChange={(e) => onChange(String(e.target.checked))} />
        {label}
      </label>
    );
  }
  // Most fields have no hint. i18next treats an empty default as missing (returnEmptyString:
  // false) and returns the key, so the hint is asked for only when its key exists (U11).
  const hintKey = `settings.hints.${f.key}`;
  const hint = i18n.exists(hintKey) ? t(hintKey) : "";
  const described = hint ? `${id}-hint` : undefined;
  return (
    <div className="grid gap-1.5">
      <label htmlFor={id} className="text-sm font-medium">{label}</label>
      {f.kind === "select" ? (
        <Select id={id} aria-describedby={described} value={value} onChange={(e) => onChange(e.target.value)}>
          {f.options?.map(([v, k]) => <option key={v} value={String(v)}>{t(`settings.options.${f.key}.${k}`)}</option>)}
        </Select>
      ) : f.kind === "lines" ? (
        <Textarea id={id} aria-describedby={described} rows={2} value={value} onChange={(e) => onChange(e.target.value)} />
      ) : (
        <Input id={id} aria-describedby={described} inputMode={f.kind === "days" ? "numeric" : undefined} value={value} onChange={(e) => onChange(e.target.value)} />
      )}
      {hint && <p id={described} className="text-xs text-muted-foreground">{hint}</p>}
    </div>
  );
}

// SmtpPassword sets or removes the mail relay's password, which is write-only.
function SmtpPassword({ set }: { set: boolean }) {
  const { t } = useTranslation();
  const save = useMutation(SettingsService.method.setSmtpPassword);
  const queryClient = useQueryClient();
  const [password, setPassword] = useState("");
  const [message, setMessage] = useState<Message>();
  async function submit(e: FormEvent) {
    e.preventDefault();
    try {
      await save.mutateAsync({ password });
      setPassword("");
      setMessage({ tone: "info", text: t(password ? "settings.smtpPasswordSaved" : "settings.smtpPasswordRemoved") });
      await queryClient.invalidateQueries();
    } catch (err) {
      setMessage({ tone: "error", text: ConnectError.from(err).rawMessage });
    }
  }
  return (
    <form onSubmit={submit} aria-label={t("settings.smtpPassword")} className="flex flex-wrap items-end gap-2 border-t border-border pt-4" noValidate>
      <label className="grid gap-1.5 text-sm font-medium">
        {t("settings.smtpPassword")}
        <Input type="password" autoComplete="new-password" className="w-64" placeholder={t(set ? "settings.passwordSet" : "settings.passwordNone")}
          value={password} onChange={(e) => setPassword(e.target.value)} />
      </label>
      <Button type="submit" variant="outline" disabled={save.isPending || (!password && !set)}>
        {t(password ? "routeForm.save" : "settings.removePassword")}
      </Button>
      {message && <div className="w-full"><Alert tone={message.tone}>{message.text}</Alert></div>}
    </form>
  );
}
