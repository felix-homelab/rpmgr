// SPDX-License-Identifier: Apache-2.0

import { ConnectError, Code } from "@connectrpc/connect";
import { useMutation, useQuery } from "@connectrpc/connect-query";
import { useQueryClient } from "@tanstack/react-query";
import { useState, type FormEvent } from "react";
import { useTranslation } from "react-i18next";
import { Field } from "@/components/field";
import { Alert } from "@/components/public-page";
import { Button } from "@/components/ui/button";
import { TokenService, type APIToken } from "@/gen/rpmgr/v1/token_pb";
import { Reason, reasonOf } from "@/lib/errors";
import { when } from "@/lib/format";
import { serverMessage } from "@/lib/link-token";
import { instancePermission, orgPermissions } from "@/lib/permissions";
import { useOrg } from "@/session";
import { useStepUp } from "@/step-up";

const day = 86400;

// APITokens lists the user's personal API tokens of the org, creates one after a step-up and shows
// it once, and revokes one after a confirmation that names it (docs/04-security.md, "API tokens").
export function APITokens() {
  const { t } = useTranslation();
  const org = useOrg();
  const list = useQuery(TokenService.method.listAPITokens, { orgId: org?.orgId ?? "" }, { enabled: !!org });
  const [created, setCreated] = useState<string>();
  const [adding, setAdding] = useState(false);
  return (
    <section aria-labelledby="section-tokens" className="grid gap-4">
      <h2 id="section-tokens" className="text-lg font-semibold">{t("tokens.title")}</h2>
      <p className="text-sm text-muted-foreground">{t("tokens.intro")}</p>
      {created && (
        <div className="grid gap-2 rounded-md border border-border p-3">
          <p role="status" className="text-sm">{t("tokens.created")}</p>
          <code aria-label={t("tokens.token")} className="break-all font-mono text-sm">{created}</code>
          <div className="flex gap-2">
            <Button variant="outline" size="sm" onClick={() => void navigator.clipboard?.writeText(created)}>{t("mfa.copy")}</Button>
            <Button size="sm" onClick={() => setCreated(undefined)}>{t("tokens.copied")}</Button>
          </div>
        </div>
      )}
      {list.data && list.data.apiTokens.length > 0 && (
        <ul aria-label={t("tokens.title")} className="grid gap-2">
          {list.data.apiTokens.map((tok) => <Token key={tok.id} token={tok} orgId={org!.orgId} />)}
        </ul>
      )}
      {list.data?.apiTokens.length === 0 && <p className="text-sm">{t("tokens.none")}</p>}
      {org && (adding
        ? <NewToken orgId={org.orgId} instanceAdmin={org.instanceAdmin} onDone={(tok) => (setAdding(false), setCreated(tok))} onCancel={() => setAdding(false)} />
        : <Button variant="outline" className="justify-self-start" onClick={() => setAdding(true)}>{t("tokens.new")}</Button>)}
    </section>
  );
}

function NewToken({ orgId, instanceAdmin, onDone, onCancel }: { orgId: string; instanceAdmin: boolean; onDone: (token: string) => void; onCancel: () => void }) {
  const { t } = useTranslation();
  const create = useMutation(TokenService.method.createAPIToken);
  const stepUp = useStepUp();
  const queryClient = useQueryClient();
  const [name, setName] = useState("");
  const [days, setDays] = useState("90");
  const [scopes, setScopes] = useState<string[]>(["org.read"]);
  const [error, setError] = useState("");
  const all = instanceAdmin ? [...orgPermissions, instancePermission] : [...orgPermissions];
  const toggle = (p: string) => setScopes(scopes.includes(p) ? scopes.filter((s) => s !== p) : [...scopes, p]);

  async function submit(e: FormEvent) {
    e.preventDefault();
    const n = Number(days);
    if (!Number.isInteger(n) || n < 1 || n > 365) {
      setError(t("tokens.days"));
      return;
    }
    const requestId = crypto.randomUUID(); // the same for the retry after a step-up
    try {
      const r = await stepUp(() => create.mutateAsync({ orgId, name, scopes, ttl: { seconds: BigInt(n * day) }, requestId }));
      await queryClient.invalidateQueries();
      onDone(r.token);
    } catch (err) {
      const e = ConnectError.from(err);
      if (reasonOf(err) !== Reason.stepUpRequired) {
        setError(e.code === Code.InvalidArgument || e.code === Code.PermissionDenied ? serverMessage(e.rawMessage) : t("link.failed", { message: e.rawMessage }));
      }
    }
  }

  return (
    <form onSubmit={submit} className="grid gap-4 rounded-md border border-border p-3" noValidate>
      <Field label={t("tokens.name")} required maxLength={100} value={name} onChange={(e) => setName(e.target.value)} />
      <Field label={t("tokens.validity")} hint={t("tokens.days")} type="number" min={1} max={365} required value={days}
        onChange={(e) => setDays(e.target.value)} />
      <fieldset className="grid gap-1.5">
        <legend className="text-sm font-medium">{t("tokens.scopes")}</legend>
        {all.map((p) => (
          <label key={p} className="flex items-start gap-2 text-sm">
            <input type="checkbox" className="mt-1" checked={scopes.includes(p)} onChange={() => toggle(p)} />
            <span><code className="font-mono">{p}</code> — {t(`tokens.scope.${p.replace(".", "_")}`)}</span>
          </label>
        ))}
      </fieldset>
      {error && <Alert>{error}</Alert>}
      <div className="flex gap-2">
        <Button type="submit" disabled={create.isPending || scopes.length === 0 || name === ""}>{t("tokens.create")}</Button>
        <Button type="button" variant="outline" onClick={onCancel}>{t("stepUp.cancel")}</Button>
      </div>
    </form>
  );
}

function Token({ token, orgId }: { token: APIToken; orgId: string }) {
  const { t } = useTranslation();
  const revoke = useMutation(TokenService.method.revokeAPIToken);
  const queryClient = useQueryClient();
  const [asking, setAsking] = useState(false);
  return (
    <li className="grid gap-1 rounded-md border border-border p-3 text-sm">
      <div className="flex items-center gap-2">
        <span className="font-medium">{token.name}</span>
        <code className="font-mono text-muted-foreground">{token.prefix}…</code>
        <span className="ml-auto text-muted-foreground">{t("tokens.expires", { when: when(token.expireTime) })}</span>
      </div>
      <div className="text-muted-foreground">{token.scopes.join(", ")}</div>
      <div className="text-muted-foreground">
        {token.lastUseTime ? t("tokens.lastUse", { when: when(token.lastUseTime), ip: token.lastUseIp }) : t("tokens.unused")}
      </div>
      {asking ? (
        <div className="flex items-center gap-2">
          {t("tokens.ask", { name: token.name })}
          <Button size="sm" variant="destructive" disabled={revoke.isPending}
            onClick={() => void revoke.mutateAsync({ orgId, tokenId: token.id }).then(() => queryClient.invalidateQueries())}>
            {t("tokens.revoke")}
          </Button>
          <Button size="sm" variant="outline" onClick={() => setAsking(false)}>{t("stepUp.cancel")}</Button>
        </div>
      ) : (
        <Button size="sm" variant="outline" className="justify-self-start" onClick={() => setAsking(true)}>{t("tokens.revokeAsk")}</Button>
      )}
    </li>
  );
}
