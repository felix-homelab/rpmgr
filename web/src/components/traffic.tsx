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

// TrafficStats sums traffic up as figures: bytes in and out, each with its series' colour, so that
// they are the chart's legend, connections and errors.
export function TrafficStats({ t: sum }: { t: Totals }) {
  const { t } = useTranslation();
  const count = (n: bigint) => n.toLocaleString(i18n.language);
  const stats: [string, string, string?][] = [
    [t("traffic.in"), bytes(sum.in), "bg-chart-in"],
    [t("traffic.out"), bytes(sum.out), "bg-chart-out"],
    [t("traffic.columns.connections"), count(sum.connections)],
    [t("traffic.columns.errors"), count(sum.errors)],
  ];
  return (
    <dl className="grid grid-cols-2 gap-4 sm:grid-cols-4">
      {stats.map(([label, value, swatch]) => (
        <div key={label} className="grid gap-0.5">
          <dt className="flex items-center gap-2 text-sm text-muted-foreground">
            {swatch && <span aria-hidden="true" className={`h-1 w-3 rounded-full ${swatch}`} />}
            {label}
          </dt>
          <dd className="text-lg font-semibold">{value}</dd>
        </div>
      ))}
    </dl>
  );
}

// TrafficChart draws the bytes in and out of each bucket: two lines over a light wash, on hairline
// grid lines, with a tooltip. The drawing is for the eye only; the same values are in a table, for
// screen readers and keyboards (docs/09-web-ui.md, U8), made when it is opened. A period without
// any traffic gets a note instead of a flat line.
export function TrafficChart({ buckets, daily = false }: { buckets: TrafficBucket[]; daily?: boolean }) {
  const { t } = useTranslation();
  const [open, setOpen] = useState(false);
  if (buckets.every((b) => !b.bytesIn && !b.bytesOut && !b.connections && !b.errors)) {
    return (
      <p className="grid h-48 place-items-center rounded-lg border border-dashed border-border text-sm text-muted-foreground">
        {t("traffic.empty")}
      </p>
    );
  }
  const label = new Intl.DateTimeFormat(i18n.language, daily ? { dateStyle: "short" } : { hour: "2-digit", minute: "2-digit" });
  const points = buckets.map((b) => ({
    at: b.start ? label.format(timestampDate(b.start)) : "",
    in: Number(b.bytesIn),
    out: Number(b.bytesOut),
  }));
  const tick = { fill: "var(--color-muted-foreground)", fontSize: 12 };
  const dot = { r: 4, strokeWidth: 2, stroke: "var(--color-card)" };
  return (
    <div className="grid gap-3">
      <div aria-hidden="true" className="h-56 w-full">
        <ResponsiveContainer width="100%" height="100%">
          <AreaChart data={points} accessibilityLayer={false} margin={{ top: 8, right: 4, bottom: 0, left: 0 }}>
            <CartesianGrid vertical={false} stroke="var(--color-border)" />
            <XAxis dataKey="at" tickLine={false} axisLine={false} minTickGap={32} tick={tick} />
            <YAxis tickFormatter={(v: number) => bytes(v)} tickLine={false} axisLine={false} width={64} tick={tick} />
            {/* The series' colours are too light for text, so the tooltip writes in the text colour. */}
            <Tooltip formatter={(v) => bytes(Number(v))} cursor={{ stroke: "var(--color-input)" }}
              contentStyle={{ background: "var(--color-card)", borderColor: "var(--color-border)", borderRadius: 8, fontSize: 13 }}
              itemStyle={{ color: "var(--color-foreground)" }} labelStyle={{ color: "var(--color-muted-foreground)" }} />
            <Area type="monotone" dataKey="in" name={t("traffic.in")} stroke="var(--color-chart-in)" strokeWidth={2} fill="var(--color-chart-in)"
              fillOpacity={0.1} activeDot={dot} isAnimationActive={false} />
            <Area type="monotone" dataKey="out" name={t("traffic.out")} stroke="var(--color-chart-out)" strokeWidth={2} fill="var(--color-chart-out)"
              fillOpacity={0.1} activeDot={dot} isAnimationActive={false} />
          </AreaChart>
        </ResponsiveContainer>
      </div>
      <details className="text-sm" onToggle={(e) => setOpen(e.currentTarget.open)}>
        <summary className="cursor-pointer text-muted-foreground hover:text-foreground">{t("traffic.table")}</summary>
        {open && <table className="mt-3 w-full text-left tabular-nums">
          <thead className="text-muted-foreground">
            <tr>{["at", "in", "out", "connections", "errors"].map((c) => <th key={c} scope="col" className="py-1.5 font-medium">{t(`traffic.columns.${c}`)}</th>)}</tr>
          </thead>
          <tbody>
            {buckets.map((b, i) => (
              <tr key={i} className="border-t border-border">
                <td className="py-1.5">{points[i]!.at}</td>
                <td className="py-1.5">{bytes(b.bytesIn)}</td>
                <td className="py-1.5">{bytes(b.bytesOut)}</td>
                <td className="py-1.5">{b.connections.toLocaleString(i18n.language)}</td>
                <td className="py-1.5">{b.errors.toLocaleString(i18n.language)}</td>
              </tr>
            ))}
          </tbody>
        </table>}
      </details>
    </div>
  );
}
