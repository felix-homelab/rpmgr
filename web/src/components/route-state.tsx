// SPDX-License-Identifier: Apache-2.0

import { useTranslation } from "react-i18next";
import { RouteState } from "@/gen/rpmgr/v1/route_pb";
import { cn } from "@/lib/utils";

// The look of each route state: an icon and a colour, always next to the state's name, so that no
// state is told by colour alone (docs/09-web-ui.md, U8).
const looks: Record<RouteState, { icon: string; key: string; tone: string }> = {
  [RouteState.UNSPECIFIED]: { icon: "?", key: "unknown", tone: "text-muted-foreground" },
  [RouteState.DISABLED]: { icon: "○", key: "disabled", tone: "text-muted-foreground" },
  [RouteState.PENDING]: { icon: "⧗", key: "pending", tone: "text-muted-foreground" },
  [RouteState.READY]: { icon: "●", key: "ready", tone: "text-ok" },
  [RouteState.DEGRADED]: { icon: "◐", key: "degraded", tone: "text-warn" },
  [RouteState.UNAVAILABLE]: { icon: "▲", key: "unavailable", tone: "text-destructive" },
  [RouteState.ERROR]: { icon: "✕", key: "error", tone: "text-destructive" },
};

export const routeStateKeys = Object.values(looks).map((l) => l.key);

export function routeStateKey(state: RouteState): string {
  return looks[state].key;
}

// RouteStateChip shows a route's observed state (docs/06-data-model.md, "Desired vs observed state").
export function RouteStateChip({ state }: { state: RouteState }) {
  const { t } = useTranslation();
  const look = looks[state];
  return (
    <span className={cn("inline-flex items-center gap-1.5 whitespace-nowrap", look.tone)}>
      <span aria-hidden="true">{look.icon}</span>
      {t(`routeState.${look.key}`)}
    </span>
  );
}
