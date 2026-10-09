// SPDX-License-Identifier: Apache-2.0

import { Code, ConnectError, createRouterTransport, type ServiceImpl } from "@connectrpc/connect";
import { createMemoryHistory } from "@tanstack/react-router";
import { render } from "@testing-library/react";
import { create } from "@bufbuild/protobuf";
import { App } from "@/app";
import { ErrorInfoSchema, RetryInfoSchema } from "@/gen/google/rpc/error_details_pb";
import { AuthService } from "@/gen/rpmgr/v1/auth_pb";

type Auth = Partial<ServiceImpl<typeof AuthService>>;

// apiError is an error of the API with a reason, as the server sends it (docs/07-api.md, "Errors").
export function apiError(code: Code, reason?: string, retrySeconds?: number): ConnectError {
  const err = new ConnectError("api error", code);
  if (reason) {
    err.details.push({ desc: ErrorInfoSchema, value: create(ErrorInfoSchema, { reason, domain: "rpmgr.v1" }) });
  }
  if (retrySeconds !== undefined) {
    err.details.push({ desc: RetryInfoSchema, value: create(RetryInfoSchema, { retryDelay: { seconds: BigInt(retrySeconds) } }) });
  }
  return err;
}

// auth is an AuthService with a session of Ada; without a session GetSession is
// UNAUTHENTICATED.
export function auth(over: Auth = {}, session = true): Auth {
  return {
    getSession: () => {
      if (!session) {
        throw apiError(Code.Unauthenticated);
      }
      return { userId: "usr_ada", email: "ada@example.com", displayName: "Ada" };
    },
    logout: () => ({}),
    ...over,
  };
}

// show renders the UI at path with an API that serves impl.
export function show(path: string, impl: Auth) {
  const history = createMemoryHistory({ initialEntries: [path] });
  const transport = createRouterTransport(({ service }) => service(AuthService, impl));
  return { history, ...render(<App transport={transport} history={history} />) };
}
