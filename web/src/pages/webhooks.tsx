// SPDX-License-Identifier: Apache-2.0

import { createClient, Code, ConnectError } from "@connectrpc/connect";
import { useMutation, useQuery, useTransport } from "@connectrpc/connect-query";
import { useInfiniteQuery, useQueryClient } from "@tanstack/react-query";
import type { TFunction } from "i18next";
import { Webhook as WebhookIcon } from "lucide-react";
import { useState, type FormEvent } from "react";
import { useTranslation } from "react-i18next";
import { EmptyState } from "@/components/empty-state";
import { Field } from "@/components/field";
import { OneTimeToken } from "@/components/one-time-token";
import { PageHeader } from "@/components/page-header";
import { Alert } from "@/components/public-page";
import { Row, RowList, panel } from "@/components/row-list";
import { Status, type Look } from "@/components/status";
import { Button } from "@/components/ui/button";
import { Card } from "@/components/ui/card";
import { Switch } from "@/components/ui/switch";
import { InstanceWebhookService, WebhookService, type Webhook, type WebhookDelivery } from "@/gen/rpmgr/v1/webhook_pb";
import { apiError, serverProblems, type Problems } from "@/lib/api-error";
import { Reason, reasonOf } from "@/lib/errors";
import { when } from "@/lib/format";
import { useOrg } from "@/session";

const shown = ["url", "event_types"];

// writers are the roles that hold webhooks.write (docs/04-security.md, "Roles"). The API needs it
// for every method, reads included, since a URL may carry a token of the receiver's.
export const writers = ["owner", "admin"];

// eventTypesOf reads the event types of a form: names or prefixes such as route.*, separated by
// commas, spaces or lines. None means all events.
export const eventTypesOf = (text: string): string[] => text.split(/[\s,]+/).filter(Boolean);

// checkUrl says what is wrong with an endpoint's URL, or nothing; the server decides the rest.
export function checkUrl(t: TFunction, text: string): string {
  let u: URL;
  try {
    u = new URL(text);
  } catch {
    return t("webhooks.urlInvalid");
  }
  if (u.protocol !== "https:") {
    return t("webhooks.urlHttps");
  }
  return u.username || u.password || u.hash ? t("webhooks.urlParts") : "";
}

// failure is what a change's error says; nothing for a cancelled step-up.
function failure(t: TFunction, err: unknown): string {
  if (reasonOf(err) === Reason.stepUpRequired) {
    return "";
  }
  const e = ConnectError.from(err);
  if (e.code === Code.InvalidArgument) {
    return apiError(t, err, shown);
  }
  return e.code === Code.PermissionDenied || e.code === Code.FailedPrecondition ? e.rawMessage : t("link.failed", { message: e.rawMessage });
}

// Api is the calls on a set of endpoints: the organisation's, or the instance's when it has no
// organisation. The two services answer alike (docs/07-api.md, "Webhooks").
export interface Api {
  orgId?: string;
  pending: boolean;
  create: (w: { url: string; eventTypes: string[]; enabled: boolean }) => Promise<{ webhook?: Webhook; secret: string }>;
  update: (w: { id: string; url?: string; eventTypes?: string[]; enabled?: boolean }, paths: string[], etag: string) => Promise<unknown>;
  rotate: (id: string) => Promise<{ secret: string }>;
  remove: (id: string, etag: string) => Promise<unknown>;
  test: (id: string) => Promise<{ delivered: boolean; statusCode: number; error: string }>;
  deliveries: (id: string, pageToken: string) => Promise<{ deliveries: WebhookDelivery[]; nextPageToken: string }>;
}

// useApi gives the calls on the organisation's endpoints, or on the instance's if orgId is
// undefined.
function useApi(orgId?: string): Api {
  const transport = useTransport();
  const o = {
    create: useMutation(WebhookService.method.createWebhook), update: useMutation(WebhookService.method.updateWebhook),
    rotate: useMutation(WebhookService.method.rotateWebhookSecret), remove: useMutation(WebhookService.method.deleteWebhook),
    test: useMutation(WebhookService.method.testWebhook),
  };
  const i = {
    create: useMutation(InstanceWebhookService.method.createInstanceWebhook), update: useMutation(InstanceWebhookService.method.updateInstanceWebhook),
    rotate: useMutation(InstanceWebhookService.method.rotateInstanceWebhookSecret), remove: useMutation(InstanceWebhookService.method.deleteInstanceWebhook),
    test: useMutation(InstanceWebhookService.method.testInstanceWebhook),
  };
  const pending = [...Object.values(o), ...Object.values(i)].some((m) => m.isPending);
  if (orgId === undefined) {
    return {
      pending,
      create: (webhook) => i.create.mutateAsync({ webhook, requestId: crypto.randomUUID() }),
      update: (webhook, paths, etag) => i.update.mutateAsync({ webhook, updateMask: { paths }, etag }),
      rotate: (webhookId) => i.rotate.mutateAsync({ webhookId }),
      remove: (webhookId, etag) => i.remove.mutateAsync({ webhookId, etag }),
      test: (webhookId) => i.test.mutateAsync({ webhookId }),
      deliveries: (webhookId, pageToken) => createClient(InstanceWebhookService, transport).listInstanceWebhookDeliveries({ webhookId, pageSize: 50, pageToken }),
    };
  }
  return {
    orgId,
    pending,
    create: (webhook) => o.create.mutateAsync({ orgId, webhook, requestId: crypto.randomUUID() }),
    update: (webhook, paths, etag) => o.update.mutateAsync({ webhook, updateMask: { paths }, etag }),
    rotate: (webhookId) => o.rotate.mutateAsync({ webhookId }),
    remove: (webhookId, etag) => o.remove.mutateAsync({ webhookId, etag }),
    test: (webhookId) => o.test.mutateAsync({ webhookId }),
    deliveries: (webhookId, pageToken) => createClient(WebhookService, transport).listWebhookDeliveries({ webhookId, pageSize: 50, pageToken }),
  };
}

// Webhooks is the organisation's webhook endpoints: their state, create and edit, the signing
// secret shown once, rotate, send test event, delete, and the deliveries of an endpoint
// (docs/09-web-ui.md, "Live logs, webhooks and audit sinks (Phase 2)").
export function Webhooks() {
  const { t } = useTranslation();
  const org = useOrg();
  if (!org) {
    return <p className="text-sm text-muted-foreground">{t("stepUp.loading")}</p>;
  }
  if (!writers.includes(org.role)) {
    return (
      <section aria-labelledby="webhooks-title" className="grid gap-6">
        <PageHeader id="webhooks-title" title={t("webhooks.title")} description={t("webhooks.intro")} />
        <p role="status" className="rounded-xl border border-border p-4 text-sm">{t("webhooks.noAccess")}</p>
      </section>
    );
  }
  return <WebhookList orgId={org.orgId} />;
}

// InstanceWebhooks is the Instance Admin's endpoints, which receive the instance's events, under
// Settings.
export function InstanceWebhooks() {
  return <WebhookList />;
}

// WebhookList is the endpoints of the organisation orgId, or of the instance if there is none,
// with the form that makes one and the secret of the last one made or rotated.
function WebhookList({ orgId }: { orgId?: string }) {
  const { t } = useTranslation();
  const api = useApi(orgId);
  const org = useQuery(WebhookService.method.listWebhooks, { orgId: orgId ?? "" }, { enabled: orgId !== undefined });
  const inst = useQuery(InstanceWebhookService.method.listInstanceWebhooks, {}, { enabled: orgId === undefined });
  const list = orgId === undefined ? inst : org;
  const [secret, setSecret] = useState<{ url: string; value: string }>();
  const [adding, setAdding] = useState(false);
  const add = !adding && <Button onClick={() => setAdding(true)}>{t("webhooks.new")}</Button>;
  const body = (
    <>
      {secret && <Secret url={secret.url} value={secret.value} onDone={() => setSecret(undefined)} />}
      {adding && <Form api={api} onCancel={() => setAdding(false)} onDone={(w, value) => (setAdding(false), setSecret({ url: w.url, value }))} />}
      {list.error && <Alert>{t("link.failed", { message: ConnectError.from(list.error).rawMessage })}</Alert>}
      {list.data && list.data.webhooks.length > 0 && (
        <RowList framed aria-label={t("webhooks.title")}>
          {list.data.webhooks.map((w) => <Endpoint key={w.id} api={api} webhook={w} onSecret={(value) => setSecret({ url: w.url, value })} />)}
        </RowList>
      )}
      {list.data?.webhooks.length === 0 && !adding && <EmptyState icon={WebhookIcon}>{t("webhooks.none")}</EmptyState>}
    </>
  );
  if (orgId === undefined) {
    return <Card title={t("webhooks.instanceTitle")} description={t("webhooks.instanceIntro")} actions={add}>{body}</Card>;
  }
  return (
    <section aria-labelledby="webhooks-title" className="grid gap-6">
      <PageHeader id="webhooks-title" title={t("webhooks.title")} description={t("webhooks.intro")} actions={add} />
      {body}
    </section>
  );
}

// Secret shows the signing secret of an endpoint, which the server returns only once, until the
// user says it is stored. Closing it leaves no copy in the page.
function Secret({ url, value, onDone }: { url: string; value: string; onDone: () => void }) {
  const { t } = useTranslation();
  return (
    <div role="region" aria-label={t("webhooks.secretTitle")} className={panel}>
      <p className="text-sm font-medium">{t("webhooks.secretTitle")}</p>
      <p role="status" className="text-sm">{t("webhooks.secretNote", { url })}</p>
      <OneTimeToken token={value} label={t("webhooks.secret")} />
      <Button size="sm" className="justify-self-start" onClick={onDone}>{t("webhooks.stored")}</Button>
    </div>
  );
}

// Form creates an endpoint, or edits webhook.
function Form({ api, webhook, onCancel, onDone }: { api: Api; webhook?: Webhook; onCancel: () => void; onDone: (w: Webhook, secret: string) => void }) {
  const { t } = useTranslation();
  const queryClient = useQueryClient();
  const [url, setUrl] = useState(webhook?.url ?? "");
  const [types, setTypes] = useState(webhook?.eventTypes.join(", ") ?? "");
  const [enabled, setEnabled] = useState(webhook?.enabled ?? true);
  const [error, setError] = useState("");
  const [problems, setProblems] = useState<Problems>({});

  async function submit(e: FormEvent) {
    e.preventDefault();
    setError("");
    const bad = checkUrl(t, url);
    if (bad) {
      setProblems({ url: bad });
      return;
    }
    setProblems({});
    const eventTypes = eventTypesOf(types);
    try {
      if (webhook) {
        await api.update({ id: webhook.id, url, eventTypes, enabled }, ["url", "event_types", "enabled"], webhook.etag);
        await queryClient.invalidateQueries();
        onDone(webhook, "");
      } else {
        const r = await api.create({ url, eventTypes, enabled });
        await queryClient.invalidateQueries();
        onDone(r.webhook!, r.secret);
      }
    } catch (err) {
      setProblems(serverProblems(t, err));
      setError(failure(t, err));
    }
  }

  return (
    <form onSubmit={submit} className={panel} noValidate aria-label={t(webhook ? "webhooks.edit" : "webhooks.new")}>
      <Field label={t("webhooks.url")} hint={t("webhooks.urlHint")} type="url" required maxLength={2048} error={problems.url} value={url} onChange={(e) => setUrl(e.target.value)} />
      <Field label={t("webhooks.events")} hint={t("webhooks.eventsHint")} error={problems.event_types} value={types} onChange={(e) => setTypes(e.target.value)} />
      <Switch checked={enabled} onClick={() => setEnabled(!enabled)} className="justify-self-start">{t("webhooks.enabled")}</Switch>
      {error && <Alert>{error}</Alert>}
      <div className="flex gap-2">
        <Button type="submit" disabled={api.pending || url === ""}>{t(webhook ? "webhooks.save" : "webhooks.create")}</Button>
        <Button type="button" variant="outline" onClick={onCancel}>{t("stepUp.cancel")}</Button>
      </div>
    </form>
  );
}

// stateOf is the state of an endpoint: its look and its words.
function stateOf(t: TFunction, w: Webhook): { look: Look; text: string } {
  if (!w.enabled) {
    return w.failingSinceTime
      ? { look: "alert", text: t("webhooks.state.disabledFailing", { since: when(w.failingSinceTime) }) }
      : { look: "off", text: t("webhooks.state.disabled") };
  }
  return w.failingSinceTime
    ? { look: "warn", text: t("webhooks.state.failing", { since: when(w.failingSinceTime) }) }
    : { look: "ok", text: t("webhooks.state.enabled") };
}

type Ask = "rotate" | "delete" | undefined;

// Endpoint is one endpoint with its actions: edit, enable again, rotate, test, delete and its deliveries.
function Endpoint({ api, webhook: w, onSecret }: { api: Api; webhook: Webhook; onSecret: (secret: string) => void }) {
  const { t } = useTranslation();
  const queryClient = useQueryClient();
  const [editing, setEditing] = useState(false);
  const [ask, setAsk] = useState<Ask>();
  const [log, setLog] = useState(false);
  const [error, setError] = useState("");
  const [tested, setTested] = useState<{ ok: boolean; text: string }>();
  const state = stateOf(t, w);

  // run does a change and reloads; its failure is shown in the row.
  async function run(change: () => Promise<void>) {
    setError("");
    try {
      await change();
      await queryClient.invalidateQueries();
    } catch (err) {
      setError(failure(t, err));
    } finally {
      setAsk(undefined);
    }
  }

  if (editing) {
    return <Row><Form api={api} webhook={w} onCancel={() => setEditing(false)} onDone={() => setEditing(false)} /></Row>;
  }
  return (
    <Row>
      <div className="flex flex-wrap items-center gap-x-3 gap-y-1">
        <span className="font-medium break-all">{w.url}</span>
        <Status look={state.look}>{state.text}</Status>
      </div>
      <div className="text-muted-foreground">
        {w.eventTypes.length > 0 ? w.eventTypes.join(", ") : t("webhooks.allEvents")}
        {" · "}
        {w.lastSuccessTime ? t("webhooks.lastSuccess", { when: when(w.lastSuccessTime) }) : t("webhooks.neverDelivered")}
        {w.previousSecretSigns && ` · ${t("webhooks.previousSigns", { until: when(w.previousSecretUntil) })}`}
      </div>
      {error && <Alert>{error}</Alert>}
      {tested && <p role="status" className={tested.ok ? "text-sm" : "text-sm text-destructive"}>{tested.text}</p>}
      {ask ? (
        <div className="flex flex-wrap items-center gap-2">
          {t(ask === "rotate" ? "webhooks.rotateAsk" : "webhooks.deleteAsk", { url: w.url })}
          {ask === "rotate" ? (
            <Button size="sm" disabled={api.pending} onClick={() => void run(async () => onSecret((await api.rotate(w.id)).secret))}>
              {t("webhooks.rotate")}
            </Button>
          ) : (
            <Button size="sm" variant="destructive" disabled={api.pending} onClick={() => void run(async () => void (await api.remove(w.id, w.etag)))}>
              {t("webhooks.delete")}
            </Button>
          )}
          <Button size="sm" variant="outline" onClick={() => setAsk(undefined)}>{t("stepUp.cancel")}</Button>
        </div>
      ) : (
        <div className="flex flex-wrap gap-2">
          {!w.enabled && (
            <Button size="sm" disabled={api.pending}
              onClick={() => void run(async () => void (await api.update({ id: w.id, enabled: true }, ["enabled"], w.etag)))}>
              {t("webhooks.reenable")}
            </Button>
          )}
          <Button size="sm" variant="outline" onClick={() => setEditing(true)}>{t("webhooks.edit")}</Button>
          <Button size="sm" variant="outline" disabled={api.pending}
            onClick={() => void run(async () => {
              const r = await api.test(w.id);
              setTested(r.delivered ? { ok: true, text: t("webhooks.testOk", { status: r.statusCode }) } : { ok: false, text: t("webhooks.testFailed", { reason: r.error || r.statusCode }) });
            })}>
            {t("webhooks.test")}
          </Button>
          <Button size="sm" variant="outline" onClick={() => setAsk("rotate")}>{t("webhooks.rotateStart")}</Button>
          <Button size="sm" variant="outline" aria-expanded={log} onClick={() => setLog(!log)}>{t("webhooks.deliveries")}</Button>
          <Button size="sm" variant="outline" onClick={() => setAsk("delete")}>{t("webhooks.deleteStart")}</Button>
        </div>
      )}
      {log && <Deliveries api={api} webhook={w} />}
    </Row>
  );
}

// Deliveries is the delivery log of an endpoint, the newest first, a page at a time.
function Deliveries({ api, webhook }: { api: Api; webhook: Webhook }) {
  const { t } = useTranslation();
  const q = useInfiniteQuery({
    queryKey: ["webhook-deliveries", api.orgId ?? "instance", webhook.id],
    initialPageParam: "",
    getNextPageParam: (last: { next: string }) => last.next || undefined,
    queryFn: async ({ pageParam }) => {
      const r = await api.deliveries(webhook.id, pageParam);
      return { items: r.deliveries, next: r.nextPageToken };
    },
  });
  const items = (q.data?.pages ?? []).flatMap((p) => p.items);
  return (
    <div role="region" aria-label={t("webhooks.deliveries")} className="grid gap-2">
      {q.error && <Alert>{t("link.failed", { message: ConnectError.from(q.error).rawMessage })}</Alert>}
      {q.data && items.length === 0 && <p className="text-muted-foreground">{t("webhooks.noDeliveries")}</p>}
      {items.length > 0 && (
        <ul className="divide-y divide-border rounded-lg border border-border">
          {items.map((d) => <Delivery key={d.id} delivery={d} />)}
        </ul>
      )}
      {q.hasNextPage && (
        <Button size="sm" variant="outline" className="justify-self-start" disabled={q.isFetchingNextPage} onClick={() => void q.fetchNextPage()}>
          {t("webhooks.moreDeliveries")}
        </Button>
      )}
    </div>
  );
}

function Delivery({ delivery: d }: { delivery: WebhookDelivery }) {
  const { t } = useTranslation();
  const ok = d.statusCode >= 200 && d.statusCode < 300;
  return (
    <li className="flex flex-wrap items-center gap-x-4 gap-y-1 px-3 py-2">
      <span className="text-muted-foreground tabular-nums">{when(d.sendTime)}</span>
      <span className="font-medium break-all">{d.eventType}</span>
      <span>{t("webhooks.attempt", { count: d.attempt })}</span>
      <Status look={ok ? "ok" : "failed"}>{d.error || (d.statusCode ? `HTTP ${d.statusCode}` : t("webhooks.noAnswer"))}</Status>
      {d.nextAttemptTime && <span className="text-muted-foreground">{t("webhooks.nextRetry", { when: when(d.nextAttemptTime) })}</span>}
    </li>
  );
}
