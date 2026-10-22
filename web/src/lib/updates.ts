// SPDX-License-Identifier: Apache-2.0

import { useQuery } from "@connectrpc/connect-query";
import { ReleaseService, type RolloutTarget } from "@/gen/rpmgr/v1/release_pb";

// useRolloutTargets returns the running or paused rollout's targets by agent ID, so that the
// connector and gateway lists can show where each agent stands (docs/09-web-ui.md, "Settings";
// D121). Without an active rollout it is empty.
export function useRolloutTargets(): Map<string, RolloutTarget> {
  const active = useQuery(ReleaseService.method.listRollouts, { activeOnly: true }, { refetchInterval: 5000 });
  const id = active.data?.rollouts[0]?.id ?? "";
  const list = useQuery(ReleaseService.method.listRolloutTargets, { rolloutId: id, pageSize: 500 },
    { enabled: !!id, refetchInterval: 5000 });
  return new Map((list.data?.rolloutTargets ?? []).map((t) => [t.agentId, t]));
}
