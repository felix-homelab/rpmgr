// SPDX-License-Identifier: Apache-2.0

package api

import "context"

// WithCaller returns ctx with the caller, as the interceptor sets it, for tests of handler
// helpers.
func WithCaller(ctx context.Context, c *Caller) context.Context {
	return context.WithValue(ctx, callerKey{}, c)
}
