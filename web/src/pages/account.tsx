// SPDX-License-Identifier: Apache-2.0

import { ConnectError, Code } from "@connectrpc/connect";
import { useMutation, useQuery } from "@connectrpc/connect-query";
import { useQueryClient } from "@tanstack/react-query";
import { getRouteApi } from "@tanstack/react-router";
import { useState, type FormEvent, type ReactNode } from "react";
import { useTranslation } from "react-i18next";
import { Field } from "@/components/field";
import { Alert } from "@/components/public-page";
import { Button } from "@/components/ui/button";
import { Theme, UserService, type User } from "@/gen/rpmgr/v1/user_pb";
import { serverMessage } from "@/lib/link-token";
import { APITokens } from "@/pages/api-tokens";
import { Authenticator } from "@/pages/authenticator";
import { passwordProblem } from "@/pages/reset";
import { Sessions } from "@/pages/sessions";
import { applyTheme } from "@/theme";

const route = getRouteApi("/app/account");

// Account is the user's own page (docs/09-web-ui.md, "Information architecture"): their profile,
// theme, password and authenticator. ?mfa=required says that an org needs a second factor.
export function Account() {
  const { t } = useTranslation();
  const search = route.useSearch();
  return (
    <div className="grid max-w-3xl gap-8">
      <h1 className="text-2xl font-semibold">{t("account.title")}</h1>
      {search.mfa === "required" && <Alert>{t("mfa.required")}</Alert>}
      <Profile />
      <Password />
      <Authenticator />
      <Sessions />
      <APITokens />
    </div>
  );
}

function Section({ title, children }: { title: string; children: ReactNode }) {
  const id = `section-${title.replace(/\W+/g, "-").toLowerCase()}`;
  return (
    <section aria-labelledby={id} className="grid gap-4">
      <h2 id={id} className="text-lg font-semibold">{title}</h2>
      {children}
    </section>
  );
}

// Profile changes the display name and the theme, which applies at once.
function Profile() {
  const { t } = useTranslation();
  const me = useQuery(UserService.method.getMe, {});
  const user = me.data?.user;
  return (
    <Section title={t("account.profile")}>
      {user ? <ProfileForm user={user} /> : <p>{t("stepUp.loading")}</p>}
    </Section>
  );
}

function ProfileForm({ user }: { user: User }) {
  const { t } = useTranslation();
  const update = useMutation(UserService.method.updateMe);
  const queryClient = useQueryClient();
  const [name, setName] = useState(user.displayName);
  const [theme, setTheme] = useState(user.theme || Theme.SYSTEM);
  const [result, setResult] = useState<{ tone: "info" | "error"; text: string }>();

  async function submit(e: FormEvent) {
    e.preventDefault();
    try {
      await update.mutateAsync({ displayName: name, theme });
      applyTheme(theme);
      await queryClient.invalidateQueries();
      setResult({ tone: "info", text: t("account.saved") });
    } catch (err) {
      const e = ConnectError.from(err);
      setResult({ tone: "error", text: e.code === Code.InvalidArgument ? serverMessage(e.rawMessage) : t("link.failed", { message: e.rawMessage }) });
    }
  }

  const themes = [[Theme.SYSTEM, "system"], [Theme.LIGHT, "light"], [Theme.DARK, "dark"]] as const;
  return (
    <form onSubmit={submit} className="grid gap-4" noValidate>
      <Field label={t("login.email")} value={user.email} readOnly />
      <Field label={t("setup.name")} autoComplete="name" required maxLength={100} value={name} onChange={(e) => setName(e.target.value)} />
      <fieldset className="grid gap-1.5">
        <legend className="text-sm font-medium">{t("account.theme")}</legend>
        <div className="flex gap-4 text-sm">
          {themes.map(([value, key]) => (
            <label key={key} className="flex items-center gap-1.5">
              <input type="radio" name="theme" checked={theme === value} onChange={() => setTheme(value)} />
              {t(`account.themes.${key}`)}
            </label>
          ))}
        </div>
      </fieldset>
      {result && <Alert tone={result.tone}>{result.text}</Alert>}
      <Button type="submit" className="justify-self-start" disabled={update.isPending}>{t("account.save")}</Button>
    </form>
  );
}

// Password changes the password; the server ends the user's other sessions.
function Password() {
  const { t } = useTranslation();
  const change = useMutation(UserService.method.changePassword);
  const [form, setForm] = useState({ current: "", next: "", confirm: "" });
  const [result, setResult] = useState<{ tone: "info" | "error"; text: string }>();
  const set = (k: keyof typeof form) => (e: { target: { value: string } }) => setForm({ ...form, [k]: e.target.value });

  async function submit(e: FormEvent) {
    e.preventDefault();
    const problem = passwordProblem(form.next, form.confirm);
    if (problem) {
      setResult({ tone: "error", text: t(problem) });
      return;
    }
    try {
      await change.mutateAsync({ currentPassword: form.current, newPassword: form.next });
      setForm({ current: "", next: "", confirm: "" });
      setResult({ tone: "info", text: t("account.passwordChanged") });
    } catch (err) {
      const e = ConnectError.from(err);
      setResult({ tone: "error", text: e.code === Code.InvalidArgument ? serverMessage(e.rawMessage) : t("link.failed", { message: e.rawMessage }) });
    }
  }

  return (
    <Section title={t("account.password")}>
      <form onSubmit={submit} className="grid gap-4" noValidate>
        <Field label={t("account.currentPassword")} type="password" autoComplete="current-password" required value={form.current} onChange={set("current")} />
        <Field label={t("reset.password")} hint={t("reset.passwordHint")} type="password" autoComplete="new-password" required value={form.next} onChange={set("next")} />
        <Field label={t("reset.confirm")} type="password" autoComplete="new-password" required value={form.confirm} onChange={set("confirm")} />
        {result && <Alert tone={result.tone}>{result.text}</Alert>}
        <Button type="submit" className="justify-self-start" disabled={change.isPending}>{t("account.changePassword")}</Button>
      </form>
    </Section>
  );
}
