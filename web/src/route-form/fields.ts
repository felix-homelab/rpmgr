// SPDX-License-Identifier: Apache-2.0

import { clone } from "@bufbuild/protobuf";
import { DataTransport } from "@/gen/rpmgr/v1/connector_pb";
import { Port80Mode, RouteSchema, TLSMode, type Route } from "@/gen/rpmgr/v1/route_pb";

// A field of the route form: its form key, the route path the API's update mask names
// (internal/apisvc routeFields), how it is edited, and how it reads from and writes to a route.
export interface RouteField {
  key: string;
  path: string;
  kind: "text" | "longtext" | "lines" | "pairs" | "number" | "optionalNumber" | "select" | "tristate";
  options?: [string, string][]; // value and i18n key, for select
  get: (r: Route) => string;
  set: (r: Route, v: string) => void;
}

type Spec = Route["spec"];
type SpecOf<C extends NonNullable<Spec["case"]>> = Extract<Spec, { case: C }>["value"];

const lines = (v: string) => v.split("\n").map((s) => s.trim()).filter(Boolean);
const pairs = (v: string, sep: string) =>
  Object.fromEntries(lines(v).map((l) => {
    const i = l.indexOf(sep);
    return i < 0 ? [l, ""] : [l.slice(0, i).trim(), l.slice(i + sep.length).trim()];
  }));
const showPairs = (m: Record<string, string>, sep: string) =>
  Object.keys(m).sort().map((k) => `${k}${sep}${m[k]}`).join("\n");

// spec returns a field of a spec case, which edits the route's spec only when it has that case.
function spec<C extends NonNullable<Spec["case"]>>(c: C, field: Omit<RouteField, "get" | "set"> & {
  get: (s: SpecOf<C>) => string;
  set: (s: SpecOf<C>, v: string) => void;
}): RouteField {
  return {
    ...field,
    get: (r) => (r.spec.case === c ? field.get(r.spec.value as SpecOf<C>) : ""),
    set: (r, v) => {
      if (r.spec.case === c) {
        field.set(r.spec.value as SpecOf<C>, v);
      }
    },
  };
}

const num = (v: string) => (/^\d+$/.test(v.trim()) ? Number(v.trim()) : Number.NaN);
const optional = (v: string) => (v.trim() === "" ? undefined : num(v));
const transports: [string, string][] = [
  [String(DataTransport.UNSPECIFIED), "default"], [String(DataTransport.AUTO), "auto"], [String(DataTransport.QUIC), "quic"], [String(DataTransport.H2), "h2"],
];

const common: RouteField[] = [
  { key: "name", path: "name", kind: "text", get: (r) => r.name, set: (r, v) => (r.name = v.trim()) },
  { key: "description", path: "description", kind: "longtext", get: (r) => r.description, set: (r, v) => (r.description = v) },
  { key: "labels", path: "labels", kind: "pairs", get: (r) => showPairs(r.labels, "="), set: (r, v) => (r.labels = pairs(v, "=")) },
  { key: "transport", path: "transport", kind: "select", options: transports, get: (r) => String(r.transport), set: (r, v) => (r.transport = Number(v)) },
];

const http: RouteField[] = [
  spec("http", { key: "hostnames", path: "http.hostnames", kind: "lines", get: (s) => s.hostnames.join("\n"), set: (s, v) => (s.hostnames = lines(v)) }),
  spec("http", { key: "pathPrefix", path: "http.path_prefix", kind: "text", get: (s) => s.pathPrefix, set: (s, v) => (s.pathPrefix = v.trim()) }),
  spec("http", { key: "tlsMode", path: "http.tls_mode", kind: "select", options: [[String(TLSMode.TLS_MODE_ACME), "acme"], [String(TLSMode.TLS_MODE_CERTIFICATE), "certificate"]],
    get: (s) => String(s.tlsMode), set: (s, v) => (s.tlsMode = Number(v)) }),
  spec("http", { key: "certificateId", path: "http.certificate_id", kind: "text", get: (s) => s.certificateId, set: (s, v) => (s.certificateId = v.trim()) }),
  spec("http", { key: "port80", path: "http.port80", kind: "select",
    options: [[String(Port80Mode.REDIRECT), "redirect"], [String(Port80Mode.SERVE), "serve"], [String(Port80Mode.OFF), "off"]],
    get: (s) => String(s.port80), set: (s, v) => (s.port80 = Number(v)) }),
  spec("http", { key: "hsts", path: "http.hsts_max_age_seconds", kind: "number", get: (s) => String(s.hstsMaxAgeSeconds), set: (s, v) => (s.hstsMaxAgeSeconds = num(v)) }),
  spec("http", { key: "hostHeader", path: "http.host_header", kind: "text", get: (s) => s.hostHeader, set: (s, v) => (s.hostHeader = v.trim()) }),
  spec("http", { key: "requestHeaders", path: "http.request_headers_set", kind: "pairs", get: (s) => showPairs(s.requestHeadersSet, ": "),
    set: (s, v) => (s.requestHeadersSet = pairs(v, ":")) }),
  spec("http", { key: "responseHeaders", path: "http.response_headers_set", kind: "pairs", get: (s) => showPairs(s.responseHeadersSet, ": "),
    set: (s, v) => (s.responseHeadersSet = pairs(v, ":")) }),
  spec("http", { key: "websocket", path: "http.websocket", kind: "tristate", get: (s) => (s.websocket === undefined ? "" : String(s.websocket)),
    set: (s, v) => (s.websocket = v === "" ? undefined : v === "true") }),
  spec("http", { key: "maxBody", path: "http.max_body_bytes", kind: "number", get: (s) => String(s.maxBodyBytes),
    set: (s, v) => (s.maxBodyBytes = /^\d+$/.test(v.trim()) ? BigInt(v.trim()) : -1n) }),
];

const portField = <C extends "tcp" | "udp">(c: C) =>
  spec(c, { key: "port", path: `${c}.port`, kind: "number", get: (s) => String(s.port), set: (s, v) => (s.port = num(v)) });

const byType: Record<string, RouteField[]> = {
  http,
  tcp: [portField("tcp"), spec("tcp", { key: "idleTimeout", path: "tcp.idle_timeout_seconds", kind: "optionalNumber",
    get: (s) => (s.idleTimeoutSeconds === undefined ? "" : String(s.idleTimeoutSeconds)), set: (s, v) => (s.idleTimeoutSeconds = optional(v)) })],
  udp: [portField("udp"), spec("udp", { key: "flowIdleTimeout", path: "udp.flow_idle_timeout_seconds", kind: "optionalNumber",
    get: (s) => (s.flowIdleTimeoutSeconds === undefined ? "" : String(s.flowIdleTimeoutSeconds)), set: (s, v) => (s.flowIdleTimeoutSeconds = optional(v)) })],
  tlsPassthrough: [spec("tlsPassthrough", { key: "hostnames", path: "tls_passthrough.hostnames", kind: "lines",
    get: (s) => s.hostnames.join("\n"), set: (s, v) => (s.hostnames = lines(v)) })],
};

// routeFields are the fields the form shows for a route of its type.
export function routeFields(r: Route): RouteField[] {
  return [...common, ...(byType[r.spec.case ?? ""] ?? [])];
}

export type RouteValues = Record<string, string>;

export function valuesOf(r: Route): RouteValues {
  return Object.fromEntries(routeFields(r).map((f) => [f.key, f.get(r)]));
}

// routeWith returns the route as read with the form's values in the fields the form shows; every
// other field keeps what the server sent (docs/09-web-ui.md, U1).
export function routeWith(base: Route, values: RouteValues): Route {
  const r = clone(RouteSchema, base);
  for (const f of routeFields(r)) {
    f.set(r, values[f.key] ?? "");
  }
  return r;
}

// numberProblem names the field whose value is not a whole number where one is needed.
export function numberProblems(r: Route, values: RouteValues): string[] {
  return routeFields(r)
    .filter((f) => (f.kind === "number" && !/^\d+$/.test((values[f.key] ?? "").trim())) ||
      (f.kind === "optionalNumber" && !/^\d*$/.test((values[f.key] ?? "").trim())))
    .map((f) => f.key);
}
