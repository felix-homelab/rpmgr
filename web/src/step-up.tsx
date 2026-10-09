// SPDX-License-Identifier: Apache-2.0

import { Code, ConnectError } from "@connectrpc/connect";
import { useMutation, useQuery } from "@connectrpc/connect-query";
import { createContext, useContext, useEffect, useRef, useState, type FormEvent, type ReactNode } from "react";
import { useTranslation } from "react-i18next";
import { Field } from "@/components/field";
import { Alert } from "@/components/public-page";
import { Button } from "@/components/ui/button";
import { AuthService } from "@/gen/rpmgr/v1/auth_pb";
import { UserService } from "@/gen/rpmgr/v1/user_pb";
import { Reason, reasonOf, retryAfter } from "@/lib/errors";

type Run = <T>(action: () => Promise<T>) => Promise<T>;

const StepUpContext = createContext<Run>((action) => action());

// useStepUp returns a function that runs an action and, when the API asks for a step-up
// (STEP_UP_REQUIRED), asks the user to confirm their identity in a dialog and runs it again, so
// that the user keeps their place (docs/09-web-ui.md, U7). Cancelling rejects with the API's error.
export function useStepUp(): Run {
  return useContext(StepUpContext);
}

interface Pending {
  retry: () => void;
  cancel: () => void;
}

export function StepUpProvider({ children }: { children: ReactNode }) {
  const [pending, setPending] = useState<Pending>();
  const run: Run = async (action) => {
    try {
      return await action();
    } catch (err) {
      if (ConnectError.from(err).code !== Code.Unauthenticated || reasonOf(err) !== Reason.stepUpRequired) {
        throw err;
      }
      await new Promise<void>((resolve, reject) =>
        setPending({ retry: () => (setPending(undefined), resolve()), cancel: () => (setPending(undefined), reject(err)) }),
      );
      return action();
    }
  };
  return (
    <StepUpContext.Provider value={run}>
      {children}
      {pending && <StepUpDialog onDone={pending.retry} onCancel={pending.cancel} />}
    </StepUpContext.Provider>
  );
}

// StepUpDialog asks for the password, or for an authenticator or recovery code if the user has an
// authenticator, as StepUp needs (docs/04-security.md, "Human authentication and sessions").
function StepUpDialog({ onDone, onCancel }: { onDone: () => void; onCancel: () => void }) {
  const { t } = useTranslation();
  const dialog = useRef<HTMLDialogElement>(null);
  const me = useQuery(UserService.method.getMe, {});
  const stepUp = useMutation(AuthService.method.stepUp);
  const [secret, setSecret] = useState("");
  const [error, setError] = useState("");
  const mfa = me.data?.user?.mfa ?? false;

  useEffect(() => {
    dialog.current?.showModal();
  }, []);

  async function submit(e: FormEvent) {
    e.preventDefault();
    try {
      await stepUp.mutateAsync(mfa ? { secondFactor: secret } : { password: secret });
      onDone();
    } catch (err) {
      const code = ConnectError.from(err).code;
      setSecret("");
      setError(code === Code.Unauthenticated ? t(mfa ? "stepUp.wrongCode" : "stepUp.wrongPassword")
        : code === Code.ResourceExhausted ? t("login.tooMany", { count: retryAfter(err) ?? 60 })
        : t("link.failed", { message: ConnectError.from(err).rawMessage }));
    }
  }

  return (
    <dialog ref={dialog} aria-labelledby="step-up-title" onCancel={onCancel}
      className="m-auto w-full max-w-sm rounded-lg border border-border bg-background p-6 text-foreground backdrop:bg-black/50">
      <h2 id="step-up-title" className="text-lg font-semibold">{t("stepUp.title")}</h2>
      <p className="mt-2 text-sm text-muted-foreground">{t("stepUp.intro")}</p>
      <form onSubmit={submit} className="mt-4 grid gap-4" noValidate>
        {me.isPending ? <p>{t("stepUp.loading")}</p> : mfa ? (
          <Field label={t("login.code")} hint={t("login.codeHint")} autoComplete="one-time-code" autoFocus required
            value={secret} onChange={(e) => setSecret(e.target.value)} />
        ) : (
          <Field label={t("login.password")} type="password" autoComplete="current-password" autoFocus required
            value={secret} onChange={(e) => setSecret(e.target.value)} />
        )}
        {error && <Alert>{error}</Alert>}
        <div className="flex justify-end gap-2">
          <Button type="button" variant="outline" onClick={onCancel}>{t("stepUp.cancel")}</Button>
          <Button type="submit" disabled={me.isPending || stepUp.isPending}>{t("stepUp.submit")}</Button>
        </div>
      </form>
    </dialog>
  );
}
