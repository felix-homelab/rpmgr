// SPDX-License-Identifier: Apache-2.0

import { useMutation, useQuery } from "@connectrpc/connect-query";
import { useQueryClient } from "@tanstack/react-query";
import { useState } from "react";
import { useTranslation } from "react-i18next";
import { Ask } from "@/components/ask";
import { Alert } from "@/components/public-page";
import { Status, type Look } from "@/components/status";
import { Table, TD, TH, THead, TR } from "@/components/ui/table";
import { Card } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { DnsRecordState, DnsZoneService, type DnsRecord } from "@/gen/rpmgr/v1/dns_pb";
import { apiError } from "@/lib/api-error";
import { Reason, reasonOf } from "@/lib/errors";
import { when } from "@/lib/format";
import { useStepUp } from "@/step-up";

const stateLooks: Record<DnsRecordState, [Look, string]> = {
  [DnsRecordState.UNSPECIFIED]: ["unknown", "unknown"],
  [DnsRecordState.CREATING]: ["pending", "creating"],
  [DnsRecordState.SYNCED]: ["ok", "synced"],
  [DnsRecordState.DRIFTED]: ["warn", "drifted"],
  [DnsRecordState.ORPHANED]: ["warn", "orphaned"],
  [DnsRecordState.ERROR]: ["failed", "error"],
  [DnsRecordState.DELETING]: ["pending", "deleting"],
  [DnsRecordState.FOREIGN]: ["off", "foreign"],
};

type Named = Pick<DnsRecord, "name" | "type" | "content"> & { providerRecordId: string };

// AdoptButton adopts a foreign record after a confirmation that names it, with a step-up (U7): the
// record's current content is kept for a later release with restore, and the next pass rewrites it.
export function AdoptButton({ zoneId, record: r, onError }: { zoneId: string; record: Named; onError: (text: string) => void }) {
  const { t } = useTranslation();
  const stepUp = useStepUp();
  const queryClient = useQueryClient();
  const adopt = useMutation(DnsZoneService.method.adoptRecords);
  async function go() {
    onError("");
    try {
      await stepUp(() => adopt.mutateAsync({ dnsZoneId: zoneId, providerRecordIds: [r.providerRecordId] }));
      await queryClient.invalidateQueries();
    } catch (err) {
      if (reasonOf(err) !== Reason.stepUpRequired) {
        onError(apiError(t, err));
      }
    }
  }
  return <Ask label={t("dnsZone.adopt")} question={t("dnsZone.adoptAsk", { type: r.type, name: r.name, content: r.content })} confirm={t("dnsZone.adoptConfirm")} busy={adopt.isPending} onConfirm={go} />;
}

// ReleaseButton asks for an owned record to leave the ledger: it stays at the provider as it is, or,
// for an adopted record, is put back to the content it had when it was adopted. The DNS job carries
// it out at its next pass, so the record shows the request until then.
function ReleaseButton({ zoneId, record: r, onDone }: { zoneId: string; record: DnsRecord; onDone: (text: string, error: boolean) => void }) {
  const { t } = useTranslation();
  const stepUp = useStepUp();
  const queryClient = useQueryClient();
  const release = useMutation(DnsZoneService.method.releaseRecord);
  const [restore, setRestore] = useState(false);
  const [open, setOpen] = useState(false);
  async function go() {
    onDone("", false);
    try {
      const done = await stepUp(() => release.mutateAsync({ dnsZoneId: zoneId, recordId: r.id, restore }));
      onDone(done.warning || t("dnsZone.releaseAsked", { name: r.name }), !!done.warning);
      await queryClient.invalidateQueries();
    } catch (err) {
      if (reasonOf(err) !== Reason.stepUpRequired) {
        onDone(apiError(t, err), true);
      }
    }
  }
  if (!open) {
    return <Button size="sm" variant="outline" onClick={() => setOpen(true)}>{t("dnsZone.release")}</Button>;
  }
  return (
    <div className="grid gap-2">
      <label className="flex items-center gap-2"><input type="radio" name={`release-${r.id}`} checked={!restore} onChange={() => setRestore(false)} />{t("dnsZone.releaseKeep")}</label>
      <label className="flex items-center gap-2">
        <input type="radio" name={`release-${r.id}`} checked={restore} disabled={!r.adoptedTime} onChange={() => setRestore(true)} />{t("dnsZone.releaseRestore")}
      </label>
      <div className="flex flex-wrap items-center gap-2">
        <Ask label={t("dnsZone.releaseNow")} question={t(restore ? "dnsZone.releaseRestoreAsk" : "dnsZone.releaseKeepAsk", { type: r.type, name: r.name })} confirm={t("dnsZone.releaseConfirm")} busy={release.isPending} onConfirm={go} />
        <Button size="sm" variant="outline" onClick={() => setOpen(false)}>{t("stepUp.cancel")}</Button>
      </div>
    </div>
  );
}

// ZoneRecords lists the records rpmgr owns in a zone, from its ledger, and for an Owner or Admin the
// others, read live from the provider and never stored (docs/09-web-ui.md, "Managed DNS zone"). Any
// other member does not ask for the foreign records, which the API refuses them.
export function ZoneRecords({ zoneId, admin }: { zoneId: string; admin: boolean }) {
  const { t } = useTranslation();
  const records = useQuery(DnsZoneService.method.listZoneRecords, { dnsZoneId: zoneId, includeForeign: admin });
  const [error, setError] = useState("");
  const [note, setNote] = useState("");
  const list = records.data?.records ?? [];
  return (
    <Card title={t("dnsZone.records")} description={admin ? t("dnsZone.recordsLive") : t("dnsZone.recordsOwned")}>
      {records.isError && <Alert>{apiError(t, records.error)}</Alert>}
      {error && <Alert>{error}</Alert>}
      {note && <p role="status">{note}</p>}
      {records.data && list.length === 0 && <p>{t("dnsZone.noRecords")}</p>}
      {list.length > 0 && (
        <Table framed={false}>
          <THead><TR>
            <TH>{t("dnsZone.name")}</TH><TH>{t("dnsZone.type")}</TH><TH>{t("dnsZone.content")}</TH><TH>{t("dnsZone.owner")}</TH><TH>{t("dnsZone.status")}</TH>
            {admin && <TH><span className="sr-only">{t("dnsZone.actions")}</span></TH>}
          </TR></THead>
          <tbody>
            {list.map((r) => {
              const [look, key] = stateLooks[r.state];
              const owned = r.id !== "";
              return (
                <TR key={r.id || r.providerRecordId || r.name + r.type + r.content}>
                  <TD className="font-mono">{r.name}</TD>
                  <TD>{r.type}</TD>
                  <TD className="font-mono">{r.content}{r.proxied ? " (proxied)" : ""}</TD>
                  <TD>{owned ? t("dnsZone.ownedBy") : t("dnsZone.foreign")}{r.adoptedTime && <span className="block text-muted-foreground">{t("dnsZone.adoptedOn", { when: when(r.adoptedTime) })}</span>}</TD>
                  <TD><Status look={look}>{t(`dnsZone.state.${key}`)}</Status>{r.reason && <span className="block text-muted-foreground">{r.reason}</span>}</TD>
                  {admin && (
                    <TD>
                      {owned && <ReleaseButton zoneId={zoneId} record={r} onDone={(text, bad) => (bad ? (setNote(""), setError(text)) : (setError(""), setNote(text)))} />}
                      {!owned && r.state === DnsRecordState.FOREIGN && r.adoptable && <AdoptButton zoneId={zoneId} record={r} onError={setError} />}
                      {!owned && r.state === DnsRecordState.FOREIGN && !r.adoptable && (
                        <span className="text-muted-foreground">{r.adoptReason === "type_not_adoptable" ? t("dnsZone.adoptHintType") : t("dnsZone.adoptHintUnpublished")}</span>
                      )}
                    </TD>
                  )}
                </TR>
              );
            })}
          </tbody>
        </Table>
      )}
    </Card>
  );
}
