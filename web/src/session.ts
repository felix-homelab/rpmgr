// SPDX-License-Identifier: Apache-2.0

import type { Transport } from "@connectrpc/connect";
import { createQueryOptions } from "@connectrpc/connect-query";
import { AuthService } from "@/gen/rpmgr/v1/auth_pb";

// sessionQuery reads the caller's session; the pages behind sign-in load it first.
export function sessionQuery(transport: Transport) {
  return createQueryOptions(AuthService.method.getSession, {}, { transport });
}
