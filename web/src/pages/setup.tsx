// SPDX-License-Identifier: Apache-2.0

import { Code, ConnectError } from "@connectrpc/connect";
import { useMutation } from "@connectrpc/connect-query";
import { useQueryClient } from "@tanstack/react-query";
import { Link, useNavigate } from "@tanstack/react-router";
import { useState, type FormEvent } from "react";
import { useTranslation } from "react-i18next";
import { Field } from "@/components/field";
import { Alert, PublicPage } from "@/components/public-page";
import { Button } from "@/components/ui/button";
import { AuthService } from "@/gen/rpmgr/v1/auth_pb";
import { serverMessage, useLinkToken } from "@/lib/link-token";
import { passwordProblem } from "@/pages/reset";

// Setup creates the first user, Owner of the first org and Instance Admin, with the first-user link
// that `rpmgr controller init` prints, and signs them in (docs/10-operations.md, "Install").
export function Setup() {
  const { t } = useTranslation();
  const token = useLinkToken();
  const complete = useMutation(AuthService.method.completePasswordReset);
  const login = useMutation(AuthService.method.login);
  const queryClient = useQueryClient();
  const navigate = useNavigate();
  const [form, setForm] = useState({ email: "", name: "", password: "", confirm: "" });
  const [error, setError] = useState("");
  const [exists, setExists] = useState(false);
  const set = (k: keyof typeof form) => (e: { target: { value: string } }) => setForm({ ...form, [k]: e.target.value });

  async function submit(e: FormEvent) {
    e.preventDefault();
    const problem = passwordProblem(form.password, form.confirm);
    if (problem) {
      setError(t(problem));
      return;
    }
    setError("");
    try {
      const res = await complete.mutateAsync({ token, newPassword: form.password, email: form.email, displayName: form.name });
      await login.mutateAsync({ email: res.email, password: form.password });
    } catch (err) {
      const e = ConnectError.from(err);
      if (e.code === Code.FailedPrecondition) {
        setExists(true);
      } else {
        setError(e.code === Code.InvalidArgument ? serverMessage(e.rawMessage) : t("link.failed", { message: e.rawMessage }));
      }
      return;
    }
    await queryClient.resetQueries();
    await navigate({ to: "/", replace: true });
  }

  if (!token) {
    return <PublicPage title={t("setup.title")}><Alert>{t("link.incomplete")}</Alert></PublicPage>;
  }
  if (exists) {
    return (
      <PublicPage title={t("setup.title")}>
        <Alert>{t("setup.exists")}</Alert>
        <Button asChild className="mt-4"><Link to="/login" search={{}}>{t("login.submit")}</Link></Button>
      </PublicPage>
    );
  }
  return (
    <PublicPage title={t("setup.title")}>
      <p className="text-sm text-muted-foreground">{t("setup.intro")}</p>
      <form onSubmit={submit} className="mt-4 grid gap-4" noValidate>
        <Field label={t("login.email")} type="email" autoComplete="email" required value={form.email} onChange={set("email")} />
        <Field label={t("setup.name")} autoComplete="name" required maxLength={100} value={form.name} onChange={set("name")} />
        <Field label={t("reset.password")} hint={t("reset.passwordHint")} type="password" autoComplete="new-password" required
          value={form.password} onChange={set("password")} />
        <Field label={t("reset.confirm")} type="password" autoComplete="new-password" required value={form.confirm} onChange={set("confirm")} />
        {error && <Alert>{error}</Alert>}
        <Button type="submit" disabled={complete.isPending || login.isPending}>{t("setup.submit")}</Button>
      </form>
    </PublicPage>
  );
}
