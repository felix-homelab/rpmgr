// SPDX-License-Identifier: Apache-2.0

import { Code, ConnectError } from "@connectrpc/connect";
import { useMutation } from "@connectrpc/connect-query";
import { useQueryClient } from "@tanstack/react-query";
import { getRouteApi, Link, useNavigate } from "@tanstack/react-router";
import { useState, type FormEvent } from "react";
import { useTranslation } from "react-i18next";
import { Field } from "@/components/field";
import { Alert, PublicPage } from "@/components/public-page";
import { Button } from "@/components/ui/button";
import { AuthService } from "@/gen/rpmgr/v1/auth_pb";
import { Reason, reasonOf, retryAfter } from "@/lib/errors";
import { safeRedirect } from "@/lib/redirect";

const route = getRouteApi("/login");

// Login signs in with an e-mail address and password, then, if the user has an authenticator, with
// a code of it or a recovery code (docs/04-security.md, "Human authentication and sessions").
export function Login() {
  const { t } = useTranslation();
  const search = route.useSearch();
  const navigate = useNavigate();
  const queryClient = useQueryClient();
  const login = useMutation(AuthService.method.login);
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [code, setCode] = useState("");
  const [needCode, setNeedCode] = useState(false);
  const [error, setError] = useState("");

  async function submit(e: FormEvent) {
    e.preventDefault();
    setError("");
    try {
      await login.mutateAsync({ email, password, secondFactor: needCode ? code : "" });
    } catch (err) {
      const code = ConnectError.from(err).code;
      if (code === Code.Unauthenticated && reasonOf(err) === Reason.mfaRequired) {
        setNeedCode(true);
      } else if (code === Code.Unauthenticated) {
        setError(needCode ? t("login.wrongCode") : t("login.wrongPassword"));
        setCode("");
      } else if (code === Code.ResourceExhausted) {
        setError(t("login.tooMany", { count: retryAfter(err) ?? 60 }));
      } else {
        setError(t("login.failed", { message: ConnectError.from(err).rawMessage }));
      }
      return;
    }
    await queryClient.resetQueries();
    await navigate({ href: safeRedirect(search.redirect), replace: true });
  }

  return (
    <PublicPage title={t("login.title")}>
      <form onSubmit={submit} className="grid gap-4" noValidate>
        {!needCode ? (
          <>
            <Field label={t("login.email")} type="email" autoComplete="username" required value={email}
              onChange={(e) => setEmail(e.target.value)} />
            <Field label={t("login.password")} type="password" autoComplete="current-password" required value={password}
              onChange={(e) => setPassword(e.target.value)} />
          </>
        ) : (
          <Field label={t("login.code")} hint={t("login.codeHint")} autoComplete="one-time-code" autoFocus required
            value={code} onChange={(e) => setCode(e.target.value)} />
        )}
        {error && <Alert>{error}</Alert>}
        <Button type="submit" disabled={login.isPending}>
          {t("login.submit")}
        </Button>
      </form>
      <Link to="/forgot" className="mt-4 inline-block text-sm text-muted-foreground underline">
        {t("login.forgot")}
      </Link>
    </PublicPage>
  );
}
