// SPDX-License-Identifier: Apache-2.0

import { clone } from "@bufbuild/protobuf";
import { ConnectError } from "@connectrpc/connect";
import { useMutation, useQuery } from "@connectrpc/connect-query";
import { useQueryClient } from "@tanstack/react-query";
import { Link } from "@tanstack/react-router";
import { useId, useState, type FormEvent, type ReactNode } from "react";
import { useTranslation } from "react-i18next";
import { Alert } from "@/components/public-page";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { AuthService } from "@/gen/rpmgr/v1/auth_pb";
import { InstanceSettingsSchema, OrgSettingsSchema, SettingsService, type InstanceSettings, type OrgSettings } from "@/gen/rpmgr/v1/settings_pb";
import { Reason, reasonOf } from "@/lib/errors";
import { settingFields, withRelay, type Section, type SettingField } from "@/pages/settings-fields";
import { useGroups } from "@/routes-data";
import { useOrg } from "@/session";
import { useStepUp } from "@/step-up";

type Message = { tone: "info" | "error"; text: string } | undefined;

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
// the instance's, with a link to the Updates page (docs/09-web-ui.md, "Information
// architecture" and "Settings"; docs/10-operations.md, "Runtime settings").
export function Settings() {
  const { t } = useTranslation();
  const org = useOrg();
  const session = useQuery(AuthService.method.getSession, {});
  const admin = session.data?.instanceAdmin ?? false;
  return (
    <div className="grid max-w-3xl gap-8">
      <div className="flex flex-wrap items-baseline gap-4">
        <h1 className="text-2xl font-semibold">{t("settings.title")}</h1>
        {admin && (
          <nav aria-label={t("settings.pages")} className="flex gap-4 text-sm">
            <Link to="/settings/updates" className="underline">{t("settings.updates")}</Link>
          </nav>
        )}
      </div>
      {org && <OrgSettingsSection orgId={org.orgId} owner={org.role === "owner"} />}
      {admin && <InstanceSettingsSection title={t("settings.instance")} sections={["agents", "endpoints", "traffic", "acme", "mail", "audit"]} />}
    </div>
  );
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
  return (
    <div className="grid max-w-3xl gap-6">
      <div className="flex items-baseline gap-4">
        <h1 className="text-2xl font-semibold">{title}</h1>
        <Link to="/settings" className="text-sm underline">{t("settings.title")}</Link>
      </div>
      {session.data && (session.data.instanceAdmin ? children : <p className="text-sm text-muted-foreground">{t("settings.adminOnly")}</p>)}
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
    <section aria-labelledby="org-settings-title" className="grid gap-3">
      <h2 id="org-settings-title" className="text-lg font-semibold">{t("settings.org")}</h2>
      {!owner && <p className="text-sm text-muted-foreground">{t("settings.ownerOnly")}</p>}
      {got.data?.settings && (
        <OrgForm key={got.data.etag} orgId={orgId} settings={got.data.settings} etag={got.data.etag} disabled={!owner} onDone={setMessage} />
      )}
      {message && <Alert tone={message.tone}>{message.text}</Alert>}
    </section>
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
      <fieldset disabled={disabled} className="grid gap-3">
        <label className="flex items-center gap-2 text-sm">
          <input type="checkbox" checked={form.mfa} onChange={(e) => setForm({ ...form, mfa: e.target.checked })} />
          {t("settings.requireMfa")}
        </label>
        <label className="flex items-center gap-2 text-sm">
          <input type="checkbox" checked={form.enroll} onChange={(e) => setForm({ ...form, enroll: e.target.checked })} />
          {t("settings.operatorsMayEnroll")}
        </label>
        <label className="grid gap-1 text-sm font-medium">
          {t("settings.defaultGroup")}
          <select className="h-9 rounded-md border border-border bg-background px-2 font-normal" value={form.group}
            onChange={(e) => setForm({ ...form, group: e.target.value })}>
            <option value="">{t("settings.none")}</option>
            {(groups.data ?? []).map((g) => <option key={g.id} value={g.id}>{g.name}</option>)}
          </select>
        </label>
        <Button type="submit" className="justify-self-start" disabled={update.isPending}>{t("routeForm.save")}</Button>
      </fieldset>
    </form>
  );
}

// InstanceSettingsSection edits the instance settings of the given sections, and only those.
export function InstanceSettingsSection({ title, sections }: { title: string; sections: Section[] }) {
  const id = useId();
  const got = useQuery(SettingsService.method.getInstanceSettings, {});
  const [message, setMessage] = useState<Message>();
  const fields = settingFields.filter((f) => sections.includes(f.section));
  return (
    <section aria-labelledby={id} className="grid gap-3">
      <h2 id={id} className="text-lg font-semibold">{title}</h2>
      {got.data?.settings && (
        <InstanceForm key={got.data.etag} title={title} sections={sections} fields={fields} settings={got.data.settings} etag={got.data.etag} onDone={setMessage} />
      )}
      {message && <Alert tone={message.tone}>{message.text}</Alert>}
      {got.data && sections.includes("mail") && <SmtpPassword set={got.data.smtpPasswordSet} />}
    </section>
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
        <fieldset key={sec} className="grid gap-3">
          {sections.length > 1 && <legend className="font-semibold">{t(`settings.sections.${sec}`)}</legend>}
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
  const { t } = useTranslation();
  const id = useId();
  const label = t(`settings.fields.${f.key}`);
  if (f.kind === "bool") {
    return (
      <label className="flex items-center gap-2 text-sm">
        <input type="checkbox" checked={value === "true"} onChange={(e) => onChange(String(e.target.checked))} />
        {label}
      </label>
    );
  }
  const box = "rounded-md border border-border bg-background px-3 py-1.5 text-sm";
  const hint = t(`settings.hints.${f.key}`, { defaultValue: "" });
  return (
    <div className="grid gap-1">
      <label htmlFor={id} className="text-sm font-medium">{label}</label>
      {f.kind === "select" ? (
        <select id={id} className={`h-9 ${box}`} value={value} onChange={(e) => onChange(e.target.value)}>
          {f.options?.map(([v, k]) => <option key={v} value={String(v)}>{t(`settings.options.${f.key}.${k}`)}</option>)}
        </select>
      ) : f.kind === "lines" ? (
        <textarea id={id} rows={2} className={box} value={value} onChange={(e) => onChange(e.target.value)} />
      ) : (
        <Input id={id} inputMode={f.kind === "days" ? "numeric" : undefined} value={value} onChange={(e) => onChange(e.target.value)} />
      )}
      {hint && <p className="text-xs text-muted-foreground">{hint}</p>}
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
    <form onSubmit={submit} aria-label={t("settings.smtpPassword")} className="flex flex-wrap items-end gap-2" noValidate>
      <label className="grid gap-1 text-sm font-medium">
        {t("settings.smtpPassword")}
        <Input type="password" autoComplete="new-password" className="w-64" placeholder={t(set ? "settings.passwordSet" : "settings.passwordNone")}
          value={password} onChange={(e) => setPassword(e.target.value)} />
      </label>
      <Button type="submit" size="sm" variant="outline" disabled={save.isPending || (!password && !set)}>
        {t(password ? "routeForm.save" : "settings.removePassword")}
      </Button>
      {message && <div className="w-full"><Alert tone={message.tone}>{message.text}</Alert></div>}
    </form>
  );
}
