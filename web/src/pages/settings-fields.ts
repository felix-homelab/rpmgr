// SPDX-License-Identifier: Apache-2.0

import { create } from "@bufbuild/protobuf";
import type { Duration } from "@bufbuild/protobuf/wkt";
import type { TFunction } from "i18next";
import {
  PasswordHashProfile, RolloutMode, SmtpSecurity, SmtpSettingsSchema, TransportPolicy, UpdateChannel, type InstanceSettings,
} from "@/gen/rpmgr/v1/settings_pb";

// The sections of the instance settings; the PKI and Updates pages show theirs (docs/09-web-ui.md,
// "Information architecture").
export type Section = "agents" | "pki" | "updates" | "endpoints" | "traffic" | "acme" | "mail" | "audit" | "webhooks";

// A field of the instance settings form: its form key, its section, the settings field the update
// mask names, how it is edited, and how it reads from and writes to the settings.
export interface SettingField {
  key: string;
  section: Section;
  mask: string;
  kind: "days" | "select" | "bool" | "lines" | "text";
  options?: [number, string][];
  required?: (values: Record<string, string>) => boolean; // whether the form needs a value
  validate?: (value: string, t: TFunction) => string; // what is wrong with the value, or nothing
  get: (s: InstanceSettings) => string;
  set: (s: InstanceSettings, v: string) => void;
}

const day = 86400n;
const days = (d?: Duration) => (d ? String(d.seconds / day) : "");
const toDays = (v: string): Duration | undefined =>
  v.trim() === "" ? undefined : ({ $typeName: "google.protobuf.Duration", seconds: /^\d+$/.test(v.trim()) ? BigInt(v.trim()) * day : -1n, nanos: 0 });
const lines = (v: string) => v.split("\n").map((l) => l.trim()).filter(Boolean);
const smtp = (s: InstanceSettings) => s.smtp ?? create(SmtpSettingsSchema);
// smtpField edits a field of the mail relay; a relay without a server is none.
const smtpField = (key: string, field: "server" | "from" | "username", required?: SettingField["required"]): SettingField => ({
  key, section: "mail", required, mask: "smtp", kind: "text", get: (s) => s.smtp?.[field] ?? "",
  set: (s, v) => {
    s.smtp = { ...smtp(s), [field]: v.trim() };
  },
});

const maxRanges = 32;

// ipv4 is the address of "a.b.c.d" as a number, or undefined if it is none.
function ipv4(text: string): number | undefined {
  const m = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/.exec(text);
  const o = m?.slice(1).map(Number);
  return o && o.every((x) => x <= 255) ? ((o[0]! << 24) | (o[1]! << 16) | (o[2]! << 8) | o[3]!) >>> 0 : undefined;
}

// ipv6 is the address of text as a number, or undefined if it is none. An address with an
// embedded IPv4 part is not checked here: the server decides on it.
function ipv6(text: string): bigint | undefined {
  const parts = text.split("::");
  if (parts.length > 2 || !/^[0-9a-f:]+$/i.test(text)) {
    return undefined;
  }
  const head = parts[0] ? parts[0].split(":") : [];
  const tail = parts[1] ? parts[1].split(":") : [];
  const fill = 8 - head.length - tail.length;
  if (parts.length === 2 ? fill < 1 : head.length !== 8) {
    return undefined;
  }
  const groups = [...head, ...Array<string>(parts.length === 2 ? fill : 0).fill("0"), ...tail];
  return groups.every((g) => /^[0-9a-f]{1,4}$/i.test(g)) ? groups.reduce((n, g) => (n << 16n) | BigInt(`0x${g}`), 0n) : undefined;
}

// rangeProblem says what is wrong with one entry of webhook_private_ranges, or nothing: it must be
// an address and a prefix length with no bits set beyond the prefix, as the server requires.
export function rangeProblem(t: TFunction, entry: string): string {
  const [addr = "", len = "", ...extra] = entry.split("/");
  const bad = t("settings.errors.rangeInvalid", { entry });
  if (extra.length > 0 || !/^\d{1,3}$/.test(len)) {
    return bad;
  }
  const bits = Number(len);
  if (!addr.includes(":")) {
    const n = ipv4(addr);
    if (n === undefined || bits > 32) {
      return bad;
    }
    const mask = bits === 0 ? 0 : (~0 << (32 - bits)) >>> 0;
    const net = (n & mask) >>> 0;
    const text = [24, 16, 8, 0].map((s) => (net >>> s) & 255).join(".");
    return net === n ? "" : t("settings.errors.rangeHostBits", { entry, suggest: `${text}/${bits}` });
  }
  if (addr.includes(".")) {
    return bits > 128 ? bad : "";
  }
  const n = ipv6(addr);
  if (n === undefined || bits > 128) {
    return bad;
  }
  return (n & ((1n << BigInt(128 - bits)) - 1n)) === 0n ? "" : t("settings.errors.rangeHostBits6", { entry });
}

// rangesProblem says what is wrong with the lines of webhook_private_ranges, or nothing.
export function rangesProblem(value: string, t: TFunction): string {
  const entries = lines(value);
  const seen = new Set<string>();
  const problems = entries.map((e) => {
    if (seen.has(e)) {
      return t("settings.errors.rangeTwice", { entry: e });
    }
    seen.add(e);
    return rangeProblem(t, e);
  });
  if (entries.length > maxRanges) {
    problems.push(t("settings.errors.rangeMany", { max: maxRanges }));
  }
  return problems.filter(Boolean).join(" ");
}

export const settingFields: SettingField[] = [
  { key: "transport", section: "agents", mask: "default_transport", kind: "select",
    options: [[TransportPolicy.AUTO, "auto"], [TransportPolicy.QUIC, "quic"], [TransportPolicy.H2, "h2"], [TransportPolicy.WSS, "wss"]],
    get: (s) => String(s.defaultTransport ?? TransportPolicy.AUTO), set: (s, v) => (s.defaultTransport = Number(v)) },
  { key: "leafLifetime", section: "pki", mask: "leaf_certificate_lifetime", kind: "days", get: (s) => days(s.leafCertificateLifetime), set: (s, v) => (s.leafCertificateLifetime = toDays(v)) },
  { key: "grace", section: "pki", mask: "expired_certificate_grace", kind: "days", get: (s) => days(s.expiredCertificateGrace), set: (s, v) => (s.expiredCertificateGrace = toDays(v)) },
  { key: "passwordHash", section: "pki", mask: "password_hash_profile", kind: "select",
    options: [[PasswordHashProfile.DEFAULT, "default"], [PasswordHashProfile.LOW_MEMORY, "lowMemory"]],
    get: (s) => String(s.passwordHashProfile ?? PasswordHashProfile.DEFAULT), set: (s, v) => (s.passwordHashProfile = Number(v)) },
  { key: "releaseCheck", section: "updates", mask: "release_check", kind: "bool", get: (s) => String(s.releaseCheck ?? true), set: (s, v) => (s.releaseCheck = v === "true") },
  { key: "channel", section: "updates", mask: "update_channel", kind: "select",
    options: [[UpdateChannel.STABLE, "stable"], [UpdateChannel.PRERELEASE, "prerelease"]],
    get: (s) => String(s.updateChannel ?? UpdateChannel.STABLE), set: (s, v) => (s.updateChannel = Number(v)) },
  // Which rollout Roll out… starts: easy, a queue of agents one after another, unless set (D129).
  { key: "rolloutMode", section: "updates", mask: "rollout_mode", kind: "select",
    options: [[RolloutMode.EASY, "easy"], [RolloutMode.ADVANCED, "advanced"]],
    get: (s) => String(s.rolloutMode || RolloutMode.EASY), set: (s, v) => (s.rolloutMode = Number(v)) },
  { key: "aliases", section: "endpoints", mask: "public_url_aliases", kind: "lines", get: (s) => s.publicUrlAliases.join("\n"), set: (s, v) => (s.publicUrlAliases = lines(v)) },
  { key: "endpoints", section: "endpoints", mask: "controller_endpoints", kind: "lines", get: (s) => s.controllerEndpoints.join("\n"), set: (s, v) => (s.controllerEndpoints = lines(v)) },
  { key: "hourly", section: "traffic", mask: "hourly_rollup_retention", kind: "days", get: (s) => days(s.hourlyRollupRetention), set: (s, v) => (s.hourlyRollupRetention = toDays(v)) },
  { key: "daily", section: "traffic", mask: "daily_rollup_retention", kind: "days", get: (s) => days(s.dailyRollupRetention), set: (s, v) => (s.dailyRollupRetention = toDays(v)) },
  { key: "acmeDirectory", section: "acme", mask: "acme_directory_url", kind: "text", get: (s) => s.acmeDirectoryUrl ?? "", set: (s, v) => (s.acmeDirectoryUrl = v.trim() || undefined) },
  { key: "acmeEmail", section: "acme", mask: "acme_email", kind: "text", get: (s) => s.acmeEmail ?? "", set: (s, v) => (s.acmeEmail = v.trim() || undefined) },
  smtpField("smtpServer", "server"),
  // A relay needs a sender address.
  smtpField("smtpFrom", "from", (v) => (v.smtpServer ?? "").trim() !== ""),
  smtpField("smtpUser", "username"),
  { key: "smtpSecurity", section: "mail", mask: "smtp", kind: "select", options: [[SmtpSecurity.STARTTLS, "starttls"], [SmtpSecurity.TLS, "tls"]],
    get: (s) => String(s.smtp?.security || SmtpSecurity.STARTTLS), set: (s, v) => (s.smtp = { ...smtp(s), security: Number(v) }) },
  // The private networks organisations' webhook receivers may be in (D145). One range per line.
  { key: "webhookPrivateRanges", section: "webhooks", mask: "webhook_private_ranges", kind: "lines", validate: rangesProblem,
    get: (s) => s.webhookPrivateRanges.join("\n"), set: (s, v) => (s.webhookPrivateRanges = lines(v)) },
  { key: "auditRetention", section: "audit", mask: "audit_retention", kind: "days", get: (s) => days(s.auditRetention), set: (s, v) => (s.auditRetention = toDays(v)) },
];

// withRelay drops a mail relay without a server: the controller then sends no mail.
export function withRelay(s: InstanceSettings): InstanceSettings {
  if (s.smtp && s.smtp.server === "") {
    s.smtp = undefined;
  }
  return s;
}
