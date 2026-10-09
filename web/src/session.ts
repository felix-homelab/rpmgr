// SPDX-License-Identifier: Apache-2.0

import type { Transport } from "@connectrpc/connect";
import { createQueryOptions, useQuery } from "@connectrpc/connect-query";
import { AuthService } from "@/gen/rpmgr/v1/auth_pb";

// sessionQuery reads the caller's session; the pages behind sign-in load it first.
export function sessionQuery(transport: Transport) {
  return createQueryOptions(AuthService.method.getSession, {}, { transport });
}

// useOrg returns the org the UI works in, and the user's role there: in Phase 1 the user's first
// org; the org switcher comes with the multi-org UI (docs/05-features.md, Phase 2).
export function useOrg(): { orgId: string; role: string; instanceAdmin: boolean } | undefined {
  const session = useQuery(AuthService.method.getSession, {});
  const first = session.data?.memberships[0];
  return first && { orgId: first.orgId, role: first.role, instanceAdmin: session.data?.instanceAdmin ?? false };
}
