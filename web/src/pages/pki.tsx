// SPDX-License-Identifier: Apache-2.0

import { ConnectError } from "@connectrpc/connect";
import { useMutation, useQuery } from "@connectrpc/connect-query";
import { useQueryClient } from "@tanstack/react-query";
import { useState } from "react";
import { useTranslation } from "react-i18next";
import { Command } from "@/components/one-time-token";
import { Alert } from "@/components/public-page";
import { Button } from "@/components/ui/button";
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

const states: Record<CAKeyState, string> = {
  [CAKeyState.CA_KEY_STATE_UNSPECIFIED]: "unspecified",
  [CAKeyState.CA_KEY_STATE_NEXT]: "next",
  [CAKeyState.CA_KEY_STATE_ACTIVE]: "active",
  [CAKeyState.CA_KEY_STATE_RETIRED]: "retired",
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
    <section aria-labelledby="pki-keys" className="grid gap-3">
      <h2 id="pki-keys" className="text-lg font-semibold">{t("pki.keys")}</h2>
      {status.error && <Alert>{status.error.rawMessage}</Alert>}
      {s && (
        <>
          <p className="text-sm">{t("pki.trustDomain")} <code className="font-mono">{s.trustDomain}</code></p>
          <div className="grid gap-1 text-sm">
            {t("pki.rootPin")}
            <Command command={s.rootPin} label={t("pki.rootPin")} />
          </div>
          <table className="w-full text-left text-sm">
            <thead className="text-muted-foreground">
              <tr>{["kind", "state", "subject", "valid", "rotates"].map((c) => <th key={c} scope="col" className="py-1 font-medium">{t(`pki.columns.${c}`)}</th>)}</tr>
            </thead>
            <tbody>
              {s.keys.map((k, i) => <KeyRow key={i} k={k} />)}
            </tbody>
          </table>
          <Rotate />
        </>
      )}
    </section>
  );
}

function KeyRow({ k }: { k: CAKey }) {
  const { t } = useTranslation();
  return (
    <tr className="border-t border-border align-top">
      <td className="py-2 font-medium">{t(`pki.kinds.${kinds[k.kind]}`)}</td>
      <td className="py-2">{t(`pki.states.${states[k.state]}`)}</td>
      <td className="py-2 font-mono text-xs break-all">{k.subject}</td>
      <td className="py-2">{t("pki.validity", { from: when(k.notBefore), to: when(k.notAfter) })}</td>
      <td className="py-2">{k.rotateTime ? when(k.rotateTime) : "—"}</td>
    </tr>
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
        <div className="flex flex-wrap items-center gap-2 text-sm">
          {t("pki.rotateAsk")}
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
