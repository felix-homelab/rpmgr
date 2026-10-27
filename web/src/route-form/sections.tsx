// SPDX-License-Identifier: Apache-2.0

import { CircleAlert } from "lucide-react";
import { useEffect, useRef, useState, type ReactNode } from "react";
import type { FieldValues, UseFormReturn } from "react-hook-form";
import { useTranslation } from "react-i18next";
import type { Route } from "@/gen/rpmgr/v1/route_pb";
import { routeFields, type RouteField, type RouteValues } from "@/route-form/fields";
import { FieldGrid, FormField } from "@/route-form/form-field";
import { cn } from "@/lib/utils";

// The route form's sections, in the page's order, each with the keys of its fields in their order
// (docs/09-web-ui.md, "Route form"). group is the gateway group of a new route. A UDP or "TCP and
// UDP" route has no CONNECT listener, so its port stands with the hostnames, as how it is reached.
const order = [
  ["general", ["group", "name", "description", "labels"]],
  ["matching", ["hostnames", "pathPrefix", "headerMatches"]],
  ["tls", ["tlsMode", "certificateId", "port80", "hsts"]],
  ["requests", ["hostHeader", "requestHeaders", "responseHeaders", "websocket", "maxBody"]],
  ["upstream", ["transport", "upstreamHeaderTimeout", "upstreamIdleTimeout", "idleTimeout", "flowIdleTimeout", "tcpIdleTimeout",
    "udpFlowIdleTimeout", "maxConnections", "requestsPerSecond", "bandwidth"]],
  ["health", ["healthCheck", "healthPort", "healthPath", "healthStatus", "healthInterval", "healthTimeout", "healthUnhealthy", "healthHealthy"]],
  ["connect", ["listenerMode", "authorities", "connectAuth", "connectHostname", "connectCertificate", "port"]],
  ["maintenance", ["maintenance", "maintenanceMessage"]],
] as const satisfies readonly (readonly [string, readonly string[]])[];

export type SectionId = (typeof order)[number][0];
export const sectionIds: SectionId[] = order.map(([id]) => id);
const placed = new Map<string, SectionId>(order.flatMap(([id, keys]) => keys.map((k) => [k, id] as const)));
const rank = new Map<string, number>(order.flatMap(([, keys]) => keys.map((k, i) => [k, i] as const)));

// sectionOf is the section of a field of route r by its key; undefined for a key no section has.
export function sectionOf(r: Route, key: string): SectionId | undefined {
  return key === "port" && r.spec.case !== "tcp" ? "matching" : placed.get(key);
}

// anchor is the ID of a section's element, which the section list links to.
export const anchor = (id: SectionId) => `route-section-${id}`;

export interface RouteSection {
  id: SectionId;
  fields: RouteField[];
}

// routeSections are the sections of the form for route r, with their fields in order; a section
// without a field for the route's type is left out. A field no section names would stand in
// General rather than be lost.
export function routeSections(r: Route): RouteSection[] {
  const fields = routeFields(r);
  const at = (key: string) => rank.get(key) ?? -1;
  return sectionIds
    .map((id) => ({ id, fields: fields.filter((f) => (sectionOf(r, f.key) ?? "general") === id).sort((a, b) => at(a.key) - at(b.key)) }))
    .filter((s) => s.fields.length > 0);
}

// SectionList links to each section of the form; it stands beside the form from 1024 px and above
// it on narrower screens. A section that holds a field with an error is marked, with an icon and in
// the colour of errors, and its link says so to screen readers.
export function SectionList<V extends FieldValues>({ route, sections, form, className }: {
  route: Route; sections: RouteSection[]; form: UseFormReturn<V>; className?: string;
}) {
  const { t } = useTranslation();
  const invalid = new Set(Object.keys(form.formState.errors).map((k) => sectionOf(route, k) ?? "general"));
  return (
    <nav aria-label={t("routeForm.sections.list")} className={cn("lg:sticky lg:top-24 lg:self-start", className)}>
      <ul className="flex flex-wrap gap-x-1 gap-y-1 text-sm lg:grid lg:gap-0.5">
        {sections.map(({ id }) => (
          <li key={id}>
            <a href={`#${anchor(id)}`} className={cn("flex min-h-9 items-center gap-2 rounded-lg px-3 font-medium text-muted-foreground transition-colors hover:bg-muted hover:text-foreground",
              invalid.has(id) && "text-destructive hover:text-destructive")}>
              {invalid.has(id) && <CircleAlert aria-hidden="true" className="size-4 shrink-0" />}
              {t(`routeForm.sections.${id}`)}
              {invalid.has(id) && <span className="sr-only"> {t("routeForm.sections.invalid")}</span>}
            </a>
          </li>
        ))}
      </ul>
    </nav>
  );
}

// FormSections are the form's sections, each with its heading and its fields; general holds what
// the form adds before General's fields, such as a new route's gateway group.
export function FormSections<V extends RouteValues>({ sections, form, editing = false, general }: {
  sections: RouteSection[]; form: UseFormReturn<V>; editing?: boolean; general?: ReactNode;
}) {
  const { t } = useTranslation();
  return (
    <div className="grid gap-6">
      {sections.map(({ id, fields }) => (
        <section key={id} className="grid gap-4 border-border not-first:border-t not-first:pt-6">
          <h2 id={anchor(id)} className="scroll-mt-24 font-semibold">{t(`routeForm.sections.${id}`)}</h2>
          <FieldGrid>
            {id === "general" && general}
            {fields.map((f) => <FormField key={f.key} field={f} form={form} editing={editing} />)}
          </FieldGrid>
        </section>
      ))}
    </div>
  );
}

// useFirstError moves the focus to the first field with an error, in the page's order, once the
// form shows its errors: after a save or preview the form's checks refuse, or after the server's
// violations land on their fields. The ref goes on the form; the function is called on such a
// failure.
export function useFirstError() {
  const ref = useRef<HTMLFormElement>(null);
  const [failures, setFailures] = useState(0);
  useEffect(() => {
    if (failures > 0) {
      ref.current?.querySelector<HTMLElement>("[aria-invalid='true']")?.focus();
    }
  }, [failures]);
  return [ref, () => setFailures((n) => n + 1)] as const;
}
