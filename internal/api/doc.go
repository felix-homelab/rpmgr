// SPDX-License-Identifier: Apache-2.0

// Package api serves the public API, rpmgr.v1, with connect-go (docs/07-api.md). Every method goes
// through one interceptor that authenticates the caller, authorizes the method by its
// (rpmgr.v1.authz) option and validates the request with protovalidate. Authorization fails
// closed: a service with a method that lacks the option, names an unknown permission or a
// resource field the request does not have is never mounted, and a request for a method the
// interceptor cannot place is refused (docs/04-security.md, "One enforcement point, with defence
// in depth").
package api
