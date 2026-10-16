// SPDX-License-Identifier: Apache-2.0

import type { ComponentProps } from "react";
import { useController, type Control } from "react-hook-form";
import { useTranslation } from "react-i18next";
import { Select } from "@/components/ui/input";
import { CertificateSource, type Certificate } from "@/gen/rpmgr/v1/certificate_pb";
import { when } from "@/lib/format";
import { useCertificates } from "@/pages/certificates";
import type { RouteValues } from "@/route-form/fields";
import { useOrg } from "@/session";

// hostname is a route's hostname as the server compares it: without spaces and a trailing dot, in
// lower case, an international name in its ASCII form.
function hostname(name: string): string {
  const n = name.trim().replace(/\.$/, "");
  const star = n.startsWith("*.") ? "*." : "";
  try {
    return star + new URL(`http://${n.slice(star.length)}`).hostname;
  } catch {
    return n.toLowerCase();
  }
}

// covers says whether a certificate's name covers a hostname, as the server decides
// (internal/certs, Covers): the same name, or a wildcard's parent with one label in front of it. A
// wildcard hostname is covered by the same wildcard only.
export function covers(san: string, name: string): boolean {
  if (san === name) {
    return true;
  }
  if (!san.startsWith("*.") || name.startsWith("*.")) {
    return false;
  }
  const dot = name.indexOf(".");
  return dot > 0 && name.slice(dot + 1) === san.slice(2);
}

// fitting are the uploaded certificates that cover each of the hostnames, one per line; with none,
// every uploaded certificate.
export function fitting(certs: Certificate[], hostnames: string): Certificate[] {
  const names = hostnames.split("\n").filter((n) => n.trim() !== "").map(hostname);
  return certs.filter((c) => c.source === CertificateSource.UPLOADED && names.every((n) => c.sans.some((san) => covers(san, n))));
}

// CertificateSelect chooses the uploaded certificate of an HTTP route among the org's that cover the
// hostnames the form has, and keeps the certificate's ID as the form's value. The certificate chosen
// before stays offered, so that the select never changes it unasked, and says when it does not
// cover them; the server then refuses it. The select is controlled: its options change as the
// certificates are read and the hostnames typed, and it always shows the form's value.
export function CertificateSelect({ control, name, hostnames, ...props }: Omit<ComponentProps<"select">, "name"> & {
  control: Control<RouteValues>; name: string; hostnames: string;
}) {
  const { t } = useTranslation();
  const { field: { ref, ...field } } = useController({ control, name });
  const chosen = field.value ?? "";
  const org = useOrg();
  const list = useCertificates(org?.orgId);
  const all = list.data ?? [];
  const fit = fitting(all, hostnames);
  const option = (c: Certificate) => t("routeForm.certificate.option", { names: c.sans.join(", "), id: c.id, when: when(c.notAfter) });
  const unfit = chosen !== "" && !fit.some((c) => c.id === chosen);
  const known = all.find((c) => c.id === chosen); // not yet while the certificates are read
  const none = all.some((c) => c.source === CertificateSource.UPLOADED) ? "routeForm.certificate.noneCovers" : "routeForm.certificate.noneUploaded";
  return (
    <Select {...props} ref={ref} name={field.name} value={chosen} onChange={field.onChange} onBlur={field.onBlur}>
      <option value="">{t(fit.length > 0 ? "routeForm.certificate.choose" : none)}</option>
      {fit.map((c) => <option key={c.id} value={c.id}>{option(c)}</option>)}
      {unfit && <option value={chosen}>{known ? t("routeForm.certificate.notCovering", { option: option(known) }) : chosen}</option>}
    </Select>
  );
}
