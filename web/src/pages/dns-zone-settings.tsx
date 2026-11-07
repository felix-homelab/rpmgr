// SPDX-License-Identifier: Apache-2.0

import { useMutation } from "@connectrpc/connect-query";
import { useQueryClient } from "@tanstack/react-query";
import { useState, type FormEvent } from "react";
import { useTranslation } from "react-i18next";
import { Field } from "@/components/field";
import { Alert } from "@/components/public-page";
import { Button } from "@/components/ui/button";
import { DnsZoneService, type DnsZone } from "@/gen/rpmgr/v1/dns_pb";
import { apiError } from "@/lib/api-error";

// The highest delete threshold UpdateZone accepts (internal/apisvc/dns_zone.go, maxDeleteThreshold;
// docs/15-dns.md, "Defaults").
const maxThreshold = 1000;

const check = "flex items-center gap-2.5 text-sm";

// thresholdOf reads the threshold input: a whole number from 0 to the highest the API accepts, or
// undefined.
export function thresholdOf(text: string): number | undefined {
  if (!/^\d{1,5}$/.test(text.trim())) {
    return undefined;
  }
  const n = Number(text);
  return n <= maxThreshold ? n : undefined;
}

// ZoneSettings changes the gates and the delete threshold of a zone, for Owners and Admins. It
// sends the fields that differ from the zone as read, in the update mask, with the zone's etag, so
// that a change somebody else made meanwhile is refused and not overwritten. UpdateZone needs no
// step-up.
// The form is keyed by the zone's etag by its caller, so that it shows the zone as read last; saved
// and onSaved live above that key.
export function ZoneSettings({ zone, saved, onSaved }: { zone: DnsZone; saved: boolean; onSaved: (v: boolean) => void }) {
  const { t } = useTranslation();
  const queryClient = useQueryClient();
  const update = useMutation(DnsZoneService.method.updateZone);
  const [routes, setRoutes] = useState(zone.publishRouteHostnames);
  const [proxied, setProxied] = useState(zone.allowProxied);
  const [wildcards, setWildcards] = useState(zone.allowWildcards);
  const [threshold, setThreshold] = useState(String(zone.deleteThreshold));
  const [error, setError] = useState("");
  const parsed = thresholdOf(threshold);
  const bad = parsed === undefined ? t("dnsZone.thresholdInvalid", { max: maxThreshold }) : "";
  async function save(e: FormEvent) {
    e.preventDefault();
    onSaved(false);
    setError("");
    if (parsed === undefined) {
      return;
    }
    const paths: string[] = [];
    if (routes !== zone.publishRouteHostnames) paths.push("publish_route_hostnames");
    if (proxied !== zone.allowProxied) paths.push("allow_proxied");
    if (wildcards !== zone.allowWildcards) paths.push("allow_wildcards");
    if (parsed !== zone.deleteThreshold) paths.push("delete_threshold");
    if (paths.length === 0) {
      return;
    }
    try {
      await update.mutateAsync({
        dnsZone: { id: zone.id, publishRouteHostnames: routes, allowProxied: proxied, allowWildcards: wildcards, deleteThreshold: parsed },
        updateMask: { paths },
        etag: zone.etag,
      });
      onSaved(true);
    } catch (err) {
      setError(apiError(t, err));
    }
    await queryClient.invalidateQueries();
  }
  return (
    <form onSubmit={save} aria-label={t("dnsZone.settings")} noValidate className="grid max-w-xl gap-4">
      <label className={check}>
        <input type="checkbox" className="size-4 accent-primary" checked={routes} onChange={(e) => setRoutes(e.target.checked)} />
        {t("dnsZone.publishRoutes")}
      </label>
      <label className={check}>
        <input type="checkbox" className="size-4 accent-primary" checked={proxied} onChange={(e) => setProxied(e.target.checked)} />
        {t("dnsZone.allowProxied")}
      </label>
      <label className={check}>
        <input type="checkbox" className="size-4 accent-primary" checked={wildcards} onChange={(e) => setWildcards(e.target.checked)} />
        {t("dnsZone.allowWildcards")}
      </label>
      <Field label={t("dnsZone.threshold")} hint={t("dnsZone.thresholdHint")} error={bad} inputMode="numeric" value={threshold} onChange={(e) => setThreshold(e.target.value)} />
      {error && <Alert>{error}</Alert>}
      {saved && <p role="status">{t("dnsZone.settingsSaved")}</p>}
      <Button type="submit" className="justify-self-start" disabled={update.isPending}>{t("routeForm.save")}</Button>
    </form>
  );
}
