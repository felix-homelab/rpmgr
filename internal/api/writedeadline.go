// SPDX-License-Identifier: Apache-2.0

package api

import (
	"context"
	"net/http"
	"time"
)

type responseWriterKey struct{}

// keepResponseWriter makes the response writer of a request reachable from its context, for
// SetWriteDeadline.
func keepResponseWriter(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		next.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), responseWriterKey{}, w)))
	})
}

// SetWriteDeadline sets the deadline of the writes of a handler's response, so that a stream whose
// client stops reading ends with an error at t and not when the connection's own timeout does. A
// handler that streams sets it before each message. It returns http.ErrNotSupported if ctx is not
// that of a request served through Mount or the connection cannot take a deadline.
func SetWriteDeadline(ctx context.Context, t time.Time) error {
	w, ok := ctx.Value(responseWriterKey{}).(http.ResponseWriter)
	if !ok {
		return http.ErrNotSupported
	}
	return http.NewResponseController(w).SetWriteDeadline(t)
}
