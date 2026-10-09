// SPDX-License-Identifier: Apache-2.0

package tunnel

import (
	"context"

	"go.opentelemetry.io/otel/trace"

	tunnelv1 "github.com/felix-homelab/rpmgr/gen/rpmgr/tunnel/v1"
)

// SetTraceContext writes the span context of ctx into open, so that the connector's spans
// continue the gateway's trace (docs/10-operations.md, "Traces"); without a span it writes
// nothing.
func SetTraceContext(ctx context.Context, open *tunnelv1.StreamOpen) {
	sc := trace.SpanContextFromContext(ctx)
	if !sc.IsValid() {
		return
	}
	tid, sid := sc.TraceID(), sc.SpanID()
	open.TraceId, open.SpanId, open.TraceFlags = tid[:], sid[:], uint32(sc.TraceFlags())
}

// TraceContext returns ctx with the remote span context open carries, if a valid one.
func TraceContext(ctx context.Context, open *tunnelv1.StreamOpen) context.Context {
	var tid trace.TraceID
	var sid trace.SpanID
	if len(open.GetTraceId()) != len(tid) || len(open.GetSpanId()) != len(sid) {
		return ctx
	}
	copy(tid[:], open.GetTraceId())
	copy(sid[:], open.GetSpanId())
	sc := trace.NewSpanContext(trace.SpanContextConfig{TraceID: tid, SpanID: sid,
		TraceFlags: trace.TraceFlags(open.GetTraceFlags() & 0xff), Remote: true}) //nolint:gosec // G115: masked to a byte
	if !sc.IsValid() {
		return ctx
	}
	return trace.ContextWithRemoteSpanContext(ctx, sc)
}
