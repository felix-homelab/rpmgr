// SPDX-License-Identifier: Apache-2.0

import { ConnectError, Code } from "@connectrpc/connect";
import { useMutation } from "@connectrpc/connect-query";
import { Link } from "@tanstack/react-router";
import { useState, type FormEvent } from "react";
import { useTranslation } from "react-i18next";
import { Field } from "@/components/field";
import { Alert, PublicPage } from "@/components/public-page";
import { Button } from "@/components/ui/button";
import { AuthService } from "@/gen/rpmgr/v1/auth_pb";
import { serverMessage, useLinkToken } from "@/lib/link-token";

// passwordProblem returns the key of what is wrong with a new password and its confirmation: the
// API's length rule (docs/04-security.md, "Human authentication and sessions"), counted in
// characters, or a mismatch.
export function passwordProblem(password: string, confirm: string): string | undefined {
  const n = [...password].length;
  if (n < 12 || n > 256) {
    return "reset.length";
  }
  return password === confirm ? undefined : "reset.mismatch";
}

// Reset sets a new password with a reset link; the user then signs in.
export function Reset() {
  const { t } = useTranslation();
  const token = useLinkToken();
  const complete = useMutation(AuthService.method.completePasswordReset);
  const [password, setPassword] = useState("");
  const [confirm, setConfirm] = useState("");
  const [error, setError] = useState("");
  const [done, setDone] = useState(false);

  async function submit(e: FormEvent) {
    e.preventDefault();
    const problem = passwordProblem(password, confirm);
    if (problem) {
      setError(t(problem));
      return;
    }
    setError("");
    try {
      await complete.mutateAsync({ token, newPassword: password });
      setDone(true);
    } catch (err) {
      const e = ConnectError.from(err);
      setError(e.code === Code.InvalidArgument ? serverMessage(e.rawMessage) : t("link.failed", { message: e.rawMessage }));
    }
  }

  if (!token || done) {
    return (
      <PublicPage title={t("reset.title")}>
        {token ? <Alert tone="info">{t("reset.done")}</Alert> : <Alert>{t("link.incomplete")}</Alert>}
        <Button asChild className="mt-4"><Link to="/login" search={{}}>{t("login.submit")}</Link></Button>
      </PublicPage>
    );
  }
  return (
    <PublicPage title={t("reset.title")}>
      <form onSubmit={submit} className="grid gap-4" noValidate>
        <Field label={t("reset.password")} hint={t("reset.passwordHint")} type="password" autoComplete="new-password" required
          value={password} onChange={(e) => setPassword(e.target.value)} />
        <Field label={t("reset.confirm")} type="password" autoComplete="new-password" required value={confirm}
          onChange={(e) => setConfirm(e.target.value)} />
        {error && <Alert>{error}</Alert>}
        <Button type="submit" disabled={complete.isPending}>{t("reset.submit")}</Button>
      </form>
    </PublicPage>
  );
}
