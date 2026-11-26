// SPDX-License-Identifier: Apache-2.0

import { ConnectError } from "@connectrpc/connect";
import { useQuery } from "@connectrpc/connect-query";
import type { ReactNode } from "react";
import { useTranslation } from "react-i18next";
import { Alert } from "@/components/public-page";
import { Card } from "@/components/ui/card";
import { DatabaseDriver, KekSource, PasswordSource, SettingsService } from "@/gen/rpmgr/v1/settings_pb";
import { when } from "@/lib/format";

// BootSettingsSection shows the Instance Admin the boot file of the controller that answered,
// read-only (docs/09-web-ui.md, "Settings"). The API never returns a secret, a DSN or the path of
// a secret file, so the section has none to show.
export function BootSettingsSection() {
  const { t } = useTranslation();
  const got = useQuery(SettingsService.method.getBootSettings, {});
  const b = got.data?.settings;
  const db = b?.database;
  const postgres = db?.driver === DatabaseDriver.POSTGRES;
  const password = {
    [PasswordSource.UNSPECIFIED]: "settings.boot.passwordNone", [PasswordSource.NONE]: "settings.boot.passwordNone",
    [PasswordSource.FILE]: "settings.boot.passwordFile", [PasswordSource.CREDENTIAL]: "settings.boot.passwordCredential",
    [PasswordSource.DSN]: "settings.boot.passwordDsn",
  }[db?.passwordSource ?? PasswordSource.UNSPECIFIED];
  const kek = b?.kek?.source === KekSource.SYSTEMD_CREDENTIAL ? t("settings.boot.kekCredential", { name: b.kek.credentialName })
    : b?.kek?.source === KekSource.KMS ? t("settings.boot.kekKms") : t("settings.boot.kekFile");
  const off = t("settings.boot.off");
  return (
    <Card title={t("settings.boot.title")} description={t("settings.boot.description")}>
      {got.error && <Alert>{t("settings.boot.failed")} {ConnectError.from(got.error).rawMessage}</Alert>}
      {b && db && (
        <dl aria-label={t("settings.boot.title")} className="grid grid-cols-[max-content_1fr] gap-x-6 gap-y-1.5 text-sm">
          <Row name={t("settings.boot.node")}>{b.nodeId}</Row>
          {b.configFile && <Row name={t("settings.boot.file")}>{b.configFile}</Row>}
          {b.loadedAt && <Row name={t("settings.boot.loaded")}>{when(b.loadedAt)}</Row>}
          <Row name={t("settings.boot.publicUrl")}>{b.publicUrl}</Row>
          <Row name={t("settings.boot.listen")}>
            {[t("settings.boot.listenHttps", { addr: b.listenHttps || off }), t("settings.boot.listenHttp", { addr: b.listenHttp || off }),
              t("settings.boot.listenAdmin", { addr: b.listenAdmin || off })].join(", ")}
          </Row>
          <Row name={t("settings.boot.database")}>{t(postgres ? "settings.boot.postgres" : "settings.boot.sqlite")}</Row>
          {postgres && (
            <>
              <Row name={t("settings.boot.server")}>{b.database?.host}{db.port && `:${db.port}`}</Row>
              <Row name={t("settings.boot.databaseName")}>{db.database}</Row>
              <Row name={t("settings.boot.user")}>{db.user}</Row>
              <Row name={t("settings.boot.sslmode")}>{db.sslmode || t("settings.boot.notSet")}</Row>
              <Row name={t("settings.boot.password")}>{t(password)}</Row>
            </>
          )}
          <Row name={t("settings.boot.kek")}>{kek}</Row>
          <Row name={t("settings.boot.tlsFiles")}>{t(b.tlsFilesSet ? "settings.boot.tlsFilesSet" : "settings.boot.tlsAcme")}</Row>
          <Row name={t("settings.boot.sink")}>{b.revocationLogSink || t("settings.boot.sinkNone")}</Row>
          <Row name={t("settings.boot.log")}>{[b.logLevel, b.logFormat].filter(Boolean).join(", ") || t("settings.boot.notSet")}</Row>
          <Row name={t("settings.boot.tracing")}>{t(b.tracingEnabled ? "settings.boot.on" : "settings.boot.off")}</Row>
        </dl>
      )}
    </Card>
  );
}

function Row({ name, children }: { name: string; children: ReactNode }) {
  return (
    <>
      <dt className="text-muted-foreground">{name}</dt>
      <dd className="break-all">{children}</dd>
    </>
  );
}
