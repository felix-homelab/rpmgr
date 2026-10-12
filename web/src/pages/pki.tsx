// SPDX-License-Identifier: Apache-2.0

import { ConnectError } from "@connectrpc/connect";
import { useMutation, useQuery } from "@connectrpc/connect-query";
import { useQueryClient } from "@tanstack/react-query";
import { useState } from "react";
import { useTranslation } from "react-i18next";
import { Command } from "@/components/one-time-token";
import { Alert } from "@/components/public-page";
import { Status, type Look } from "@/components/status";
import { Button } from "@/components/ui/button";
import { Card } from "@/components/ui/card";
import { Table, TD, TH, THead, TR } from "@/components/ui/table";
import { CAKeyKind, CAKeyState, PkiService, type CAKey } from "@/gen/rpmgr/v1/pki_pb";
import { Reason, reasonOf } from "@/lib/errors";
import { when } from "@/lib/format";
import { InstanceAdminPage, InstanceSettingsSection } from "@/pages/settings";
import { useStepUp } from "@/step-up";

const kinds: Record<CAKeyKind, string> = {
  [CAKeyKind.CA_KEY_KIND_UNSPECIFIED]: "unspecified",
  [CAKeyKind.CA_KEY_KIND_ROOT]: "root",
  [CAKeyKind.CA_KEY_KIND_INTERMEDIATE]: "intermediate",
  [CAKeyKind.CA_KEY_KIND_CONFIG_SIGNING]: "configSigning",
  [CAKeyKind.CA_KEY_KIND_AUDIT_CHECKPOINT]: "auditCheckpoint",
};

const states: Record<CAKeyState, [string, Look]> = {
  [CAKeyState.CA_KEY_STATE_UNSPECIFIED]: ["unspecified", "unknown"],
  [CAKeyState.CA_KEY_STATE_NEXT]: ["next", "pending"],
  [CAKeyState.CA_KEY_STATE_ACTIVE]: ["active", "ok"],
  [CAKeyState.CA_KEY_STATE_RETIRED]: ["retired", "off"],
};

// Pki shows the Instance Admin the CA's keys and the root's pin, rotates the intermediate, and
// holds the leaf-certificate and password-hash settings (docs/09-web-ui.md, "Settings";
// docs/04-security.md, "PKI and identity").
export function Pki() {
  const { t } = useTranslation();
  return (
    <InstanceAdminPage title={t("pki.title")}>
      <Keys />
      <InstanceSettingsSection title={t("settings.sections.pki")} sections={["pki"]} />
    </InstanceAdminPage>
  );
}

function Keys() {
  const { t } = useTranslation();
  const status = useQuery(PkiService.method.getPkiStatus, {});
  const s = status.data;
  return (
    <Card title={t("pki.keys")}>
      {status.error && <Alert>{status.error.rawMessage}</Alert>}
      {s && (
        <>
          <p className="text-sm">{t("pki.trustDomain")} <code className="font-mono">{s.trustDomain}</code></p>
          <div className="grid gap-1.5 text-sm font-medium">
            {t("pki.rootPin")}
            <Command command={s.rootPin} label={t("pki.rootPin")} />
          </div>
          <Table framed={false}>
            <THead>
              <tr>{["kind", "state", "subject", "valid", "rotates"].map((c) => <TH key={c}>{t(`pki.columns.${c}`)}</TH>)}</tr>
            </THead>
            <tbody>
              {s.keys.map((k, i) => <KeyRow key={i} k={k} />)}
            </tbody>
          </Table>
          <Rotate />
        </>
      )}
    </Card>
  );
}

function KeyRow({ k }: { k: CAKey }) {
  const { t } = useTranslation();
  return (
    <TR>
      <TD className="font-medium">{t(`pki.kinds.${kinds[k.kind]}`)}</TD>
      <TD><Status look={states[k.state][1]}>{t(`pki.states.${states[k.state][0]}`)}</Status></TD>
      <TD className="font-mono text-xs break-all">{k.subject}</TD>
      <TD>{t("pki.validity", { from: when(k.notBefore), to: when(k.notAfter) })}</TD>
      <TD>{k.rotateTime ? when(k.rotateTime) : "—"}</TD>
    </TR>
  );
}

// Rotate replaces the active intermediate now, after a confirmation and a step-up; the old one
// keeps verifying the leaves it issued until it expires.
function Rotate() {
  const { t } = useTranslation();
  const stepUp = useStepUp();
  const rotate = useMutation(PkiService.method.rotateIntermediate);
  const queryClient = useQueryClient();
  const [asking, setAsking] = useState(false);
  const [message, setMessage] = useState<{ tone: "info" | "error"; text: string }>();
  async function run() {
    setMessage(undefined);
    try {
      await stepUp(() => rotate.mutateAsync({}));
      setAsking(false);
      setMessage({ tone: "info", text: t("pki.rotated") });
      await queryClient.invalidateQueries();
    } catch (err) {
      if (reasonOf(err) !== Reason.stepUpRequired) {
        setMessage({ tone: "error", text: ConnectError.from(err).rawMessage });
      }
    }
  }
  return (
    <div className="grid gap-2">
      {asking ? (
        <div className="flex flex-wrap items-center gap-2 rounded-lg border border-destructive/30 bg-destructive/8 p-3 text-sm">
          <span className="w-full sm:w-auto sm:flex-1">{t("pki.rotateAsk")}</span>
          <Button size="sm" variant="destructive" disabled={rotate.isPending} onClick={() => void run()}>{t("pki.rotateIt")}</Button>
          <Button size="sm" variant="outline" onClick={() => setAsking(false)}>{t("stepUp.cancel")}</Button>
        </div>
      ) : (
        <Button size="sm" variant="outline" className="justify-self-start" onClick={() => setAsking(true)}>{t("pki.rotate")}</Button>
      )}
      {message && <Alert tone={message.tone}>{message.text}</Alert>}
    </div>
  );
}
