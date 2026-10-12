// SPDX-License-Identifier: Apache-2.0

import { timestampFromMs } from "@bufbuild/protobuf/wkt";
import { useQuery } from "@connectrpc/connect-query";
import { useState } from "react";
import { useTranslation } from "react-i18next";
import { Alert } from "@/components/public-page";
import { dayMs, filled, hourMs, totals, TrafficChart, TrafficStats } from "@/components/traffic";
import { Card } from "@/components/ui/card";
import { MetricsService, TrafficResolution } from "@/gen/rpmgr/v1/metrics_pb";

const spans = {
  day: { resolution: TrafficResolution.HOURLY, ms: 24 * hourMs, step: hourMs },
  month: { resolution: TrafficResolution.DAILY, ms: 30 * dayMs, step: dayMs },
};

// RouteTraffic shows a route's traffic of the last 24 hours per hour, or of the last 30 days per
// day (docs/09-web-ui.md, "Route detail").
export function RouteTraffic({ routeId }: { routeId: string }) {
  const { t } = useTranslation();
  const [now] = useState(() => Date.now());
  const [span, setSpan] = useState<keyof typeof spans>("day");
  const s = spans[span];
  const traffic = useQuery(MetricsService.method.getRouteTraffic, {
    routeId, resolution: s.resolution, from: timestampFromMs(now - s.ms), to: timestampFromMs(now),
  });
  const buckets = filled(traffic.data?.buckets ?? [], now - s.ms, now, s.step);
  return (
    <Card title={t("traffic.title")} actions={
      <div className="flex rounded-lg border border-border bg-muted p-0.5">
        {(Object.keys(spans) as (keyof typeof spans)[]).map((k) => (
          <button key={k} type="button" aria-pressed={k === span} onClick={() => setSpan(k)}
            className="rounded-md px-3 py-1 text-sm font-medium text-muted-foreground aria-pressed:bg-card aria-pressed:text-foreground aria-pressed:shadow-xs">
            {t(`traffic.spans.${k}`)}
          </button>
        ))}
      </div>
    }>
      {traffic.error && <Alert>{traffic.error.rawMessage}</Alert>}
      {traffic.data && (
        <>
          <TrafficStats t={totals(buckets)} />
          <TrafficChart buckets={buckets} daily={span === "month"} />
        </>
      )}
    </Card>
  );
}
