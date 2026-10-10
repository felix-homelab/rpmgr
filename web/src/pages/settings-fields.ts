// SPDX-License-Identifier: Apache-2.0

import { create } from "@bufbuild/protobuf";
import type { Duration } from "@bufbuild/protobuf/wkt";
import {
  PasswordHashProfile, SmtpSecurity, SmtpSettingsSchema, TransportPolicy, UpdateChannel, type InstanceSettings,
} from "@/gen/rpmgr/v1/settings_pb";

// The sections of the instance settings; the PKI and Updates pages show theirs (docs/09-web-ui.md,
// "Information architecture").
export type Section = "agents" | "pki" | "updates" | "endpoints" | "traffic" | "acme" | "mail" | "audit";

// A field of the instance settings form: its form key, its section, the settings field the update
// mask names, how it is edited, and how it reads from and writes to the settings.
export interface SettingField {
  key: string;
  section: Section;
  mask: string;
  kind: "days" | "select" | "bool" | "lines" | "text";
  options?: [number, string][];
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
const smtpField = (key: string, field: "server" | "from" | "username"): SettingField => ({
  key, section: "mail", mask: "smtp", kind: "text", get: (s) => s.smtp?.[field] ?? "",
  set: (s, v) => {
    s.smtp = { ...smtp(s), [field]: v.trim() };
  },
});

export const settingFields: SettingField[] = [
  { key: "transport", section: "agents", mask: "default_transport", kind: "select",
    options: [[TransportPolicy.AUTO, "auto"], [TransportPolicy.QUIC, "quic"], [TransportPolicy.H2, "h2"]],
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
  { key: "aliases", section: "endpoints", mask: "public_url_aliases", kind: "lines", get: (s) => s.publicUrlAliases.join("\n"), set: (s, v) => (s.publicUrlAliases = lines(v)) },
  { key: "endpoints", section: "endpoints", mask: "controller_endpoints", kind: "lines", get: (s) => s.controllerEndpoints.join("\n"), set: (s, v) => (s.controllerEndpoints = lines(v)) },
  { key: "hourly", section: "traffic", mask: "hourly_rollup_retention", kind: "days", get: (s) => days(s.hourlyRollupRetention), set: (s, v) => (s.hourlyRollupRetention = toDays(v)) },
  { key: "daily", section: "traffic", mask: "daily_rollup_retention", kind: "days", get: (s) => days(s.dailyRollupRetention), set: (s, v) => (s.dailyRollupRetention = toDays(v)) },
  { key: "acmeDirectory", section: "acme", mask: "acme_directory_url", kind: "text", get: (s) => s.acmeDirectoryUrl ?? "", set: (s, v) => (s.acmeDirectoryUrl = v.trim() || undefined) },
  { key: "acmeEmail", section: "acme", mask: "acme_email", kind: "text", get: (s) => s.acmeEmail ?? "", set: (s, v) => (s.acmeEmail = v.trim() || undefined) },
  smtpField("smtpServer", "server"),
  smtpField("smtpFrom", "from"),
  smtpField("smtpUser", "username"),
  { key: "smtpSecurity", section: "mail", mask: "smtp", kind: "select", options: [[SmtpSecurity.STARTTLS, "starttls"], [SmtpSecurity.TLS, "tls"]],
    get: (s) => String(s.smtp?.security || SmtpSecurity.STARTTLS), set: (s, v) => (s.smtp = { ...smtp(s), security: Number(v) }) },
  { key: "auditRetention", section: "audit", mask: "audit_retention", kind: "days", get: (s) => days(s.auditRetention), set: (s, v) => (s.auditRetention = toDays(v)) },
];

// withRelay drops a mail relay without a server: the controller then sends no mail.
export function withRelay(s: InstanceSettings): InstanceSettings {
  if (s.smtp && s.smtp.server === "") {
    s.smtp = undefined;
  }
  return s;
}
