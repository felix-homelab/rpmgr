// SPDX-License-Identifier: Apache-2.0

import { useTranslation } from "react-i18next";
import { Status, type Look } from "@/components/status";
import { RouteState } from "@/gen/rpmgr/v1/route_pb";

// The look of each route state.
const looks: Record<RouteState, { look: Look; key: string }> = {
  [RouteState.UNSPECIFIED]: { look: "unknown", key: "unknown" },
  [RouteState.DISABLED]: { look: "off", key: "disabled" },
  [RouteState.PENDING]: { look: "pending", key: "pending" },
  [RouteState.READY]: { look: "ok", key: "ready" },
  [RouteState.DEGRADED]: { look: "warn", key: "degraded" },
  [RouteState.UNAVAILABLE]: { look: "alert", key: "unavailable" },
  [RouteState.ERROR]: { look: "failed", key: "error" },
};

export const routeStateKeys = Object.values(looks).map((l) => l.key);

export function routeStateKey(state: RouteState): string {
  return looks[state].key;
}

// RouteStateChip shows a route's observed state (docs/06-data-model.md, "Desired vs observed state").
export function RouteStateChip({ state }: { state: RouteState }) {
  const { t } = useTranslation();
  const { look, key } = looks[state];
  return <Status look={look}>{t(`routeState.${key}`)}</Status>;
}
