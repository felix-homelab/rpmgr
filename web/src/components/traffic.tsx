// SPDX-License-Identifier: Apache-2.0

import { create } from "@bufbuild/protobuf";
import { timestampDate, timestampFromMs, timestampMs } from "@bufbuild/protobuf/wkt";
import { useState } from "react";
import { useTranslation } from "react-i18next";
import { Area, AreaChart, CartesianGrid, ResponsiveContainer, Tooltip, XAxis, YAxis } from "recharts";
import { TrafficBucketSchema, type TrafficBucket } from "@/gen/rpmgr/v1/metrics_pb";
import { i18n } from "@/i18n";

const units = ["B", "kB", "MB", "GB", "TB", "PB"];

// bytes formats a byte count in decimal units, as "1.2 GB".
export function bytes(n: bigint | number): string {
  let v = Number(n);
  let u = 0;
  while (v >= 1000 && u < units.length - 1) {
    v /= 1000;
    u++;
  }
  const digits = u === 0 || v >= 100 ? 0 : 1;
  return `${new Intl.NumberFormat(i18n.language, { maximumFractionDigits: digits }).format(v)} ${units[u]}`;
}

export const hourMs = 3600_000;
export const dayMs = 24 * hourMs;

// filled returns a bucket for every step from the one that holds from up to end: those the API
// sent, which are only those with traffic, and empty ones for the others. Steps are counted in UTC,
// as the API's buckets are.
export function filled(buckets: TrafficBucket[], from: number, end: number, step: number): TrafficBucket[] {
  const sent = new Map(buckets.filter((b) => b.start).map((b) => [timestampMs(b.start!), b]));
  const out: TrafficBucket[] = [];
  for (let at = from - (from % step); at < end; at += step) {
    out.push(sent.get(at) ?? create(TrafficBucketSchema, { start: timestampFromMs(at) }));
  }
  return out;
}

export interface Totals {
  in: bigint;
  out: bigint;
  connections: bigint;
  errors: bigint;
}

// totals adds buckets up.
export function totals(buckets: TrafficBucket[]): Totals {
  return buckets.reduce((s, b) => ({ in: s.in + b.bytesIn, out: s.out + b.bytesOut, connections: s.connections + b.connections, errors: s.errors + b.errors }),
    { in: 0n, out: 0n, connections: 0n, errors: 0n });
}

// TotalsLine says how many bytes went in and out, over how many connections, with how many errors.
export function TotalsLine({ t: sum }: { t: Totals }) {
  const { t } = useTranslation();
  return (
    <p className="text-sm">
      {t("traffic.totals", { in: bytes(sum.in), out: bytes(sum.out), connections: t("traffic.connections", { count: Number(sum.connections) }),
        errors: t("traffic.errors", { count: Number(sum.errors) }) })}
    </p>
  );
}

// TrafficChart draws the bytes in and out of each bucket. The drawing is for the eye only; the
// same values are in a table, for screen readers and keyboards (docs/09-web-ui.md, U8), made when
// it is opened.
export function TrafficChart({ buckets, daily = false }: { buckets: TrafficBucket[]; daily?: boolean }) {
  const { t } = useTranslation();
  const [open, setOpen] = useState(false);
  if (buckets.length === 0) {
    return <p className="text-sm text-muted-foreground">{t("traffic.empty")}</p>;
  }
  const label = new Intl.DateTimeFormat(i18n.language, daily ? { dateStyle: "short" } : { hour: "2-digit", minute: "2-digit" });
  const points = buckets.map((b) => ({
    at: b.start ? label.format(timestampDate(b.start)) : "",
    in: Number(b.bytesIn),
    out: Number(b.bytesOut),
  }));
  return (
    <div className="grid gap-2">
      <div aria-hidden="true" className="h-48 w-full">
        <ResponsiveContainer width="100%" height="100%">
          <AreaChart data={points} accessibilityLayer={false} margin={{ top: 4, right: 8, bottom: 0, left: 8 }}>
            <CartesianGrid vertical={false} stroke="var(--color-border)" />
            <XAxis dataKey="at" tickLine={false} axisLine={false} minTickGap={24} tick={{ fill: "var(--color-muted-foreground)", fontSize: 12 }} />
            <YAxis tickFormatter={(v: number) => bytes(v)} tickLine={false} axisLine={false} width={64} tick={{ fill: "var(--color-muted-foreground)", fontSize: 12 }} />
            {/* The series' colours are too light for text, so the tooltip writes in the text colour. */}
            <Tooltip formatter={(v) => bytes(Number(v))} contentStyle={{ background: "var(--color-background)", borderColor: "var(--color-border)" }}
              itemStyle={{ color: "var(--color-foreground)" }} labelStyle={{ color: "var(--color-foreground)" }} />
            <Area type="monotone" dataKey="in" name={t("traffic.in")} stroke="var(--color-chart-in)" fill="var(--color-chart-in)" fillOpacity={0.2} isAnimationActive={false} />
            <Area type="monotone" dataKey="out" name={t("traffic.out")} stroke="var(--color-chart-out)" fill="var(--color-chart-out)" fillOpacity={0.2} isAnimationActive={false} />
          </AreaChart>
        </ResponsiveContainer>
      </div>
      <details className="text-sm" onToggle={(e) => setOpen(e.currentTarget.open)}>
        <summary className="cursor-pointer text-muted-foreground">{t("traffic.table")}</summary>
        {open && <table className="mt-2 w-full text-left">
          <thead className="text-muted-foreground">
            <tr>{["at", "in", "out", "connections", "errors"].map((c) => <th key={c} scope="col" className="py-1 font-medium">{t(`traffic.columns.${c}`)}</th>)}</tr>
          </thead>
          <tbody>
            {buckets.map((b, i) => (
              <tr key={i} className="border-t border-border">
                <td className="py-1">{points[i]!.at}</td>
                <td className="py-1">{bytes(b.bytesIn)}</td>
                <td className="py-1">{bytes(b.bytesOut)}</td>
                <td className="py-1">{b.connections.toLocaleString(i18n.language)}</td>
                <td className="py-1">{b.errors.toLocaleString(i18n.language)}</td>
              </tr>
            ))}
          </tbody>
        </table>}
      </details>
    </div>
  );
}
