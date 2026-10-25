// SPDX-License-Identifier: Apache-2.0

import { clone, create } from "@bufbuild/protobuf";
import { DataTransport } from "@/gen/rpmgr/v1/connector_pb";
import { ConnectAuthMode, HealthCheckSchema, HealthCheckType, ListenerMode, Port80Mode, RouteSchema, TLSMode, type HealthCheck, type Route,
  type TCPRouteSpec } from "@/gen/rpmgr/v1/route_pb";

// A field of the route form: its form key, the route path the API's update mask names
// (internal/apisvc routeFields), how it is edited, and how it reads from and writes to a route.
export interface RouteField {
  key: string;
  path: string;
  kind: "text" | "longtext" | "lines" | "pairs" | "number" | "optionalNumber" | "select" | "tristate" | "certificate";
  options?: [string, string][]; // value and i18n key, for select
  format?: PairFormat; // how a line reads, for pairs
  hint?: string; // the key of its hint under routeForm.hints, instead of its kind's or format's
  errorPath?: string; // the path the request's rules name for it, when several fields share path
  problem?: (v: string) => Problem | undefined; // what is wrong with its value that the rules do not say clearly
  required?: (values: RouteValues) => boolean; // whether the form needs a value; see needsValue
  shown?: (values: RouteValues) => boolean; // whether the form shows it; always if not set
  warning?: (values: RouteValues) => string | undefined; // the i18n key of a warning that stays shown
  covers?: string; // certificate: the key of the field with the names it must cover; hostnames if not set
  fixed?: boolean; // set when the route is created: the edit page shows it read-only
  get: (r: Route) => string;
  set: (r: Route, v: string) => void;
}

// PairFormat is how a line of a field of pairs reads: a label as key=value, a header as Name: value.
// name is what a label key may be (route.proto) or a header name (a token of RFC 9110, which the
// server checks too); a header's name is the same whatever its case.
export interface PairFormat {
  kind: "labels" | "headers";
  sep: string;
  shown: string;
  name: RegExp;
  folds: boolean;
}

const labelFormat: PairFormat = { kind: "labels", sep: "=", shown: "=", name: /^[a-z0-9]([a-z0-9._-]{0,61}[a-z0-9])?$/, folds: false };
const headerFormat: PairFormat = { kind: "headers", sep: ":", shown: ": ", name: /^[!#$%&'*+.^_`|~0-9A-Za-z-]+$/, folds: true };

type Spec = Route["spec"];
type SpecOf<C extends NonNullable<Spec["case"]>> = Extract<Spec, { case: C }>["value"];

const lines = (v: string) => v.split("\n").map((s) => s.trim()).filter(Boolean);
// split is a line of pairs as name and value; undefined without the separator.
function split(line: string, f: PairFormat): [string, string] | undefined {
  const i = line.indexOf(f.sep);
  return i < 0 ? undefined : [line.slice(0, i).trim(), line.slice(i + f.sep.length).trim()];
}
const pairs = (v: string, f: PairFormat) => Object.fromEntries(lines(v).map((l) => split(l, f) ?? [l, ""]));
const showPairs = (m: Record<string, string>, f: PairFormat) =>
  Object.keys(m).sort().map((k) => `${k}${f.shown}${m[k]}`).join("\n");

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
  [String(DataTransport.UNSPECIFIED), "default"], [String(DataTransport.AUTO), "auto"], [String(DataTransport.QUIC), "quic"], [String(DataTransport.H2), "h2"], [String(DataTransport.WSS), "wss"],
];

const common: RouteField[] = [
  { key: "name", path: "name", kind: "text", required: () => true, get: (r) => r.name, set: (r, v) => (r.name = v.trim()) },
  { key: "description", path: "description", kind: "longtext", get: (r) => r.description, set: (r, v) => (r.description = v) },
  { key: "labels", path: "labels", kind: "pairs", format: labelFormat, get: (r) => showPairs(r.labels, labelFormat), set: (r, v) => (r.labels = pairs(v, labelFormat)) },
  { key: "transport", path: "transport", kind: "select", options: transports, get: (r) => String(r.transport), set: (r, v) => (r.transport = Number(v)) },
];

const uploaded = (v: RouteValues) => v.tlsMode === String(TLSMode.TLS_MODE_CERTIFICATE);

const http: RouteField[] = [
  spec("http", { key: "hostnames", path: "http.hostnames", kind: "lines", required: () => true, get: (s) => s.hostnames.join("\n"), set: (s, v) => (s.hostnames = lines(v)) }),
  spec("http", { key: "pathPrefix", path: "http.path_prefix", kind: "text", get: (s) => s.pathPrefix, set: (s, v) => (s.pathPrefix = v.trim()) }),
  spec("http", { key: "tlsMode", path: "http.tls_mode", kind: "select", options: [[String(TLSMode.TLS_MODE_ACME), "acme"], [String(TLSMode.TLS_MODE_CERTIFICATE), "certificate"]],
    get: (s) => String(s.tlsMode), set: (s, v) => (s.tlsMode = Number(v)) }),
  // The ID goes with an uploaded certificate only, which is chosen from those that cover the
  // hostnames; the server refuses one with ACME. tlsMode is set first, so the ID follows the mode
  // chosen, and the form shows the choice only with an uploaded certificate.
  spec("http", { key: "certificateId", path: "http.certificate_id", kind: "certificate", required: uploaded, shown: uploaded,
    get: (s) => s.certificateId, set: (s, v) => (s.certificateId = s.tlsMode === TLSMode.TLS_MODE_CERTIFICATE ? v.trim() : "") }),
  spec("http", { key: "port80", path: "http.port80", kind: "select",
    options: [[String(Port80Mode.REDIRECT), "redirect"], [String(Port80Mode.SERVE), "serve"], [String(Port80Mode.OFF), "off"]],
    get: (s) => String(s.port80), set: (s, v) => (s.port80 = Number(v)) }),
  spec("http", { key: "hsts", path: "http.hsts_max_age_seconds", kind: "number", get: (s) => String(s.hstsMaxAgeSeconds), set: (s, v) => (s.hstsMaxAgeSeconds = num(v)) }),
  spec("http", { key: "hostHeader", path: "http.host_header", kind: "text", get: (s) => s.hostHeader, set: (s, v) => (s.hostHeader = v.trim()) }),
  spec("http", { key: "requestHeaders", path: "http.request_headers_set", kind: "pairs", format: headerFormat,
    get: (s) => showPairs(s.requestHeadersSet, headerFormat), set: (s, v) => (s.requestHeadersSet = pairs(v, headerFormat)) }),
  spec("http", { key: "responseHeaders", path: "http.response_headers_set", kind: "pairs", format: headerFormat,
    get: (s) => showPairs(s.responseHeadersSet, headerFormat), set: (s, v) => (s.responseHeadersSet = pairs(v, headerFormat)) }),
  spec("http", { key: "websocket", path: "http.websocket", kind: "tristate", get: (s) => (s.websocket === undefined ? "" : String(s.websocket)),
    set: (s, v) => (s.websocket = v === "" ? undefined : v === "true") }),
  spec("http", { key: "maxBody", path: "http.max_body_bytes", kind: "number", get: (s) => String(s.maxBodyBytes),
    set: (s, v) => (s.maxBodyBytes = /^\d+$/.test(v.trim()) ? BigInt(v.trim()) : -1n) }),
  // Maintenance answers every request with the maintenance page and its message (D88).
  spec("http", { key: "maintenance", path: "http.maintenance", kind: "select", options: [["false", "off"], ["true", "on"]],
    get: (s) => String(s.maintenance), set: (s, v) => (s.maintenance = v === "true") }),
  spec("http", { key: "maintenanceMessage", path: "http.maintenance_message", kind: "longtext", get: (s) => s.maintenanceMessage,
    set: (s, v) => (s.maintenanceMessage = v) }),
];

// A tcp route in http_connect mode shares a CONNECT listener; its CONNECT fields go with that mode
// only, and a TLS listener's hostname and certificate with tls_basic only (D130).
const httpConnect = (v: RouteValues) => v.listenerMode === String(ListenerMode.HTTP_CONNECT);
const tlsBasic = (v: RouteValues) => httpConnect(v) && v.connectAuth === String(ConnectAuthMode.TLS_BASIC);
// connectOf is a tcp route's CONNECT spec, made when the route is in http_connect mode, which the
// listener mode field, set before the others, decides; undefined otherwise.
function connectOf(s: TCPRouteSpec) {
  if (s.listenerMode !== ListenerMode.HTTP_CONNECT) {
    s.connect = undefined;
    return undefined;
  }
  s.connect ??= { $typeName: "rpmgr.v1.ConnectSpec", authorities: [], authMode: ConnectAuthMode.UNSPECIFIED, hostname: "", certificateId: "" };
  return s.connect;
}
const connectFields: RouteField[] = [
  spec("tcp", { key: "listenerMode", path: "tcp.listener_mode", kind: "select", fixed: true,
    options: [[String(ListenerMode.UNSPECIFIED), "plain"], [String(ListenerMode.HTTP_CONNECT), "httpConnect"]],
    get: (s) => String(s.listenerMode === ListenerMode.HTTP_CONNECT ? ListenerMode.HTTP_CONNECT : s.listenerMode),
    set: (s, v) => (s.listenerMode = Number(v)) }),
  spec("tcp", { key: "authorities", path: "tcp.connect", kind: "lines", required: httpConnect, shown: httpConnect,
    get: (s) => s.connect?.authorities.join("\n") ?? "", set: (s, v) => { const c = connectOf(s); if (c) c.authorities = lines(v); } }),
  spec("tcp", { key: "connectAuth", path: "tcp.connect", kind: "select", shown: httpConnect,
    options: [[String(ConnectAuthMode.NONE), "none"], [String(ConnectAuthMode.TLS_BASIC), "tlsBasic"],
      [String(ConnectAuthMode.PLAIN_BASIC), "plainBasic"]],
    warning: (v) => (httpConnect(v) && v.connectAuth === String(ConnectAuthMode.PLAIN_BASIC) ? "routeForm.connect.plainBasic" : undefined),
    get: (s) => String(s.connect?.authMode || ConnectAuthMode.NONE),
    set: (s, v) => { const c = connectOf(s); if (c) c.authMode = Number(v); } }),
  spec("tcp", { key: "connectHostname", path: "tcp.connect", kind: "text", required: tlsBasic, shown: tlsBasic,
    get: (s) => s.connect?.hostname ?? "",
    set: (s, v) => { const c = connectOf(s); if (c) c.hostname = c.authMode === ConnectAuthMode.TLS_BASIC ? v.trim() : ""; } }),
  spec("tcp", { key: "connectCertificate", path: "tcp.connect", kind: "certificate", required: tlsBasic, shown: tlsBasic, covers: "connectHostname",
    get: (s) => s.connect?.certificateId ?? "",
    set: (s, v) => { const c = connectOf(s); if (c) c.certificateId = c.authMode === ConnectAuthMode.TLS_BASIC ? v.trim() : ""; } }),
];

const portField = <C extends "tcp" | "udp" | "tcpUdp">(c: C, path: string) =>
  spec(c, { key: "port", path: `${path}.port`, kind: "number", get: (s) => String(s.port), set: (s, v) => (s.port = num(v)) });

const byType: Record<string, RouteField[]> = {
  http,
  tcp: [connectFields[0]!, portField("tcp", "tcp"), spec("tcp", { key: "idleTimeout", path: "tcp.idle_timeout_seconds", kind: "optionalNumber",
    get: (s) => (s.idleTimeoutSeconds === undefined ? "" : String(s.idleTimeoutSeconds)), set: (s, v) => (s.idleTimeoutSeconds = optional(v)) }),
  ...connectFields.slice(1)],
  udp: [portField("udp", "udp"), spec("udp", { key: "flowIdleTimeout", path: "udp.flow_idle_timeout_seconds", kind: "optionalNumber",
    get: (s) => (s.flowIdleTimeoutSeconds === undefined ? "" : String(s.flowIdleTimeoutSeconds)), set: (s, v) => (s.flowIdleTimeoutSeconds = optional(v)) })],
  tcpUdp: [portField("tcpUdp", "tcp_udp"),
    spec("tcpUdp", { key: "tcpIdleTimeout", path: "tcp_udp.idle_timeout_seconds", kind: "optionalNumber",
      get: (s) => (s.idleTimeoutSeconds === undefined ? "" : String(s.idleTimeoutSeconds)), set: (s, v) => (s.idleTimeoutSeconds = optional(v)) }),
    spec("tcpUdp", { key: "udpFlowIdleTimeout", path: "tcp_udp.flow_idle_timeout_seconds", kind: "optionalNumber",
      get: (s) => (s.flowIdleTimeoutSeconds === undefined ? "" : String(s.flowIdleTimeoutSeconds)), set: (s, v) => (s.flowIdleTimeoutSeconds = optional(v)) })],
  tlsPassthrough: [spec("tlsPassthrough", { key: "hostnames", path: "tls_passthrough.hostnames", kind: "lines", required: () => true,
    get: (s) => s.hostnames.join("\n"), set: (s, v) => (s.hostnames = lines(v)) })],
};

// The health check (docs/03-connections.md, "Target health"): a field per part, all under the
// update mask's health_check, so that a change of any sends the check whole. The kind comes first,
// as it creates or removes the check the others write to; a part the kind has not, such as an
// HTTP path of a TCP check, is cleared rather than sent hidden.
const kindOf = (v: RouteValues) => v.healthCheck ?? "none";
const checked = (v: RouteValues) => kindOf(v) !== "none";
const httpChecked = (v: RouteValues) => kindOf(v) === String(HealthCheckType.HTTP);
const isHTTP = (c: HealthCheck) => c.type === HealthCheckType.HTTP;
const count = (n: number) => (n === 0 ? "" : String(n));
const statusRange = /^(\d{3})-(\d{3})$/;

function check(key: string, part: string, field: Omit<RouteField, "key" | "path" | "get" | "set"> & {
  get: (c: HealthCheck) => string;
  set: (c: HealthCheck, v: string) => void;
}): RouteField {
  return {
    shown: checked, ...field, key, path: "health_check", errorPath: `health_check.${part}`,
    get: (r) => (r.healthCheck ? field.get(r.healthCheck) : ""),
    set: (r, v) => {
      if (r.healthCheck) {
        field.set(r.healthCheck, v);
      }
    },
  };
}

const health: RouteField[] = [
  { key: "healthCheck", path: "health_check", errorPath: "health_check.type", kind: "select",
    options: [["none", "none"], [String(HealthCheckType.TCP), "tcp"], [String(HealthCheckType.HTTP), "http"]],
    get: (r) => (r.healthCheck ? String(r.healthCheck.type) : "none"),
    set: (r, v) => {
      if (v === "none") {
        r.healthCheck = undefined;
      } else if (r.healthCheck) {
        r.healthCheck.type = Number(v);
      } else {
        r.healthCheck = create(HealthCheckSchema, { type: Number(v) });
      }
    } },
  check("healthPort", "port", { kind: "optionalNumber", hint: "healthPort", get: (c) => count(c.port), set: (c, v) => (c.port = optional(v) ?? 0) }),
  check("healthPath", "http_path", { kind: "text", hint: "healthPath", shown: httpChecked, get: (c) => c.httpPath,
    set: (c, v) => (c.httpPath = isHTTP(c) ? v.trim() : "") }),
  check("healthStatus", "expected_status_min", { kind: "text", hint: "healthStatus", shown: httpChecked,
    problem: (v) => (v.trim() === "" || statusRange.test(v.trim()) ? undefined : { text: "statusRange" }),
    get: (c) => (c.expectedStatusMin === 0 ? "" : `${c.expectedStatusMin}-${c.expectedStatusMax}`),
    set: (c, v) => {
      const m = statusRange.exec(v.trim());
      [c.expectedStatusMin, c.expectedStatusMax] = isHTTP(c) && m ? [Number(m[1]), Number(m[2])] : [0, 0];
    } }),
  check("healthInterval", "interval_seconds", { kind: "optionalNumber", get: (c) => count(c.intervalSeconds),
    set: (c, v) => (c.intervalSeconds = optional(v) ?? 0) }),
  check("healthTimeout", "timeout_seconds", { kind: "optionalNumber", get: (c) => count(c.timeoutSeconds),
    set: (c, v) => (c.timeoutSeconds = optional(v) ?? 0) }),
  check("healthUnhealthy", "unhealthy_threshold", { kind: "optionalNumber", get: (c) => count(c.unhealthyThreshold),
    set: (c, v) => (c.unhealthyThreshold = optional(v) ?? 0) }),
  check("healthHealthy", "healthy_threshold", { kind: "optionalNumber", get: (c) => count(c.healthyThreshold),
    set: (c, v) => (c.healthyThreshold = optional(v) ?? 0) }),
];

// routeFields are the fields the form shows for a route of its type, its health check last.
export function routeFields(r: Route): RouteField[] {
  return [...common, ...(byType[r.spec.case ?? ""] ?? []), ...health];
}

// maskOf is the update mask of the form's fields, each path once.
export function maskOf(r: Route): string[] {
  return [...new Set(routeFields(r).map((f) => f.path))];
}

// fieldAt is the form field a path of the request's rules names, such as
// route.health_check.interval_seconds: the field of that part, else the field of the path.
export function fieldAt(r: Route, path: string): string | undefined {
  const p = path.replace(/^route\./, "");
  const fields = routeFields(r);
  return (fields.find((f) => f.errorPath !== undefined && (p === f.errorPath || p.startsWith(`${f.errorPath}.`))) ??
    fields.find((f) => p === f.path || p.startsWith(`${f.path}[`) || p.startsWith(`${f.path}.`)))?.key;
}

export type RouteValues = Record<string, string>;

// needsValue says whether the form needs a value in a field, given the form's values: the name and
// the hostnames always, a whole number since an empty one is refused, an uploaded certificate's ID
// when the route uses one. Its label then ends in a red asterisk (docs/09-web-ui.md, "Layout and
// navigation").
export function needsValue(f: RouteField, values: RouteValues): boolean {
  return f.kind === "number" || (f.required?.(values) ?? false);
}

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

// A Problem is what is wrong with a field's value, as the key of its text under routeForm and the
// text's values.
export interface Problem {
  text: string;
  values?: Record<string, string | number>;
}

// lineProblem is the first line of a field of pairs that is not in its format: one without the
// separator or with a name that is not one, or a name an earlier line has; lines count from 1, as
// the user sees them, blank ones too.
export function lineProblem(v: string, f: PairFormat): Problem | undefined {
  const seen = new Map<string, number>();
  const all = v.split("\n");
  for (let i = 0; i < all.length; i++) {
    const text = all[i]!.trim();
    if (text === "") {
      continue;
    }
    const line = i + 1, pair = split(text, f);
    if (pair === undefined) {
      return { text: `lines.${f.kind}.separator`, values: { line } };
    }
    const [name] = pair;
    if (!f.name.test(name)) {
      return { text: `lines.${f.kind}.name`, values: { line, name } };
    }
    const same = f.folds ? name.toLowerCase() : name, first = seen.get(same);
    if (first !== undefined) {
      return { text: "lines.twice", values: { line, name, first } };
    }
    seen.set(same, line);
  }
  return undefined;
}

// fieldProblems are the problems of the fields the form shows that the request's rules do not
// state clearly: a whole number where one is needed, no certificate where the route needs an
// uploaded one, a line of pairs not in its format, and what a field's own check finds.
export function fieldProblems(r: Route, values: RouteValues): Record<string, Problem> {
  const out: Record<string, Problem> = {};
  for (const f of routeFields(r)) {
    const v = (values[f.key] ?? "").trim();
    if ((f.kind === "number" && !/^\d+$/.test(v)) || (f.kind === "optionalNumber" && !/^\d*$/.test(v))) {
      out[f.key] = { text: "number" };
    }
    if (f.kind === "certificate" && v === "" && (f.required?.(values) ?? false)) {
      out[f.key] = { text: "certificate.needed" };
    }
    const bad = (f.format && lineProblem(values[f.key] ?? "", f.format)) || (f.problem && (f.shown?.(values) ?? true) && f.problem(v));
    if (bad) {
      out[f.key] = bad;
    }
  }
  return out;
}
