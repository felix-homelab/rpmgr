// SPDX-License-Identifier: Apache-2.0

import { timestampFromMs } from "@bufbuild/protobuf/wkt";
import { useQuery } from "@connectrpc/connect-query";
import { useState } from "react";
import { useTranslation } from "react-i18next";
import { Alert } from "@/components/public-page";
import { dayMs, filled, hourMs, totals, TotalsLine, TrafficChart } from "@/components/traffic";
import { Button } from "@/components/ui/button";
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
    <section aria-labelledby="traffic-title" className="grid gap-2">
      <div className="flex flex-wrap items-center gap-2">
        <h2 id="traffic-title" className="mr-2 text-lg font-semibold">{t("traffic.title")}</h2>
        {(Object.keys(spans) as (keyof typeof spans)[]).map((k) => (
          <Button key={k} size="sm" variant={k === span ? "default" : "outline"} aria-pressed={k === span} onClick={() => setSpan(k)}>
            {t(`traffic.spans.${k}`)}
          </Button>
        ))}
      </div>
      {traffic.error && <Alert>{traffic.error.rawMessage}</Alert>}
      {traffic.data && (
        <>
          <TotalsLine t={totals(buckets)} />
          <TrafficChart buckets={buckets} daily={span === "month"} />
        </>
      )}
    </section>
  );
}
