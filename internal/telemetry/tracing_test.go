// SPDX-License-Identifier: Apache-2.0

package telemetry_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/sdk/resource"
	"go.opentelemetry.io/otel/sdk/trace/tracetest"
	"go.opentelemetry.io/otel/trace"

	"github.com/felix-homelab/rpmgr/internal/telemetry"
)

// TestTracerProvider (docs/10-operations.md, "Traces"): with a ratio of 0 a new trace is not
// exported unless a span of it fails; a child of a sampled remote parent is exported where remote
// parents are trusted, and not where they are not; with a ratio of 1 every span is.
func TestTracerProvider(t *testing.T) {
	exp := tracetest.NewInMemoryExporter()
	tp := telemetry.NewTracerProvider(exp, 0, true, resource.Empty())
	tr := tp.Tracer("test")
	ctx := context.Background()
	_, ok := tr.Start(ctx, "ok")
	ok.End()
	_, failed := tr.Start(ctx, "failed")
	failed.SetStatus(codes.Error, "upstream refused")
	failed.End()
	parent := trace.NewSpanContext(trace.SpanContextConfig{TraceID: trace.TraceID{1}, SpanID: trace.SpanID{2}, TraceFlags: trace.FlagsSampled,
		Remote: true})
	_, child := tr.Start(trace.ContextWithRemoteSpanContext(ctx, parent), "child")
	child.End()
	if err := tp.ForceFlush(ctx); err != nil {
		t.Fatal(err)
	}
	names := map[string]bool{}
	for _, s := range exp.GetSpans() {
		names[s.Name] = true
	}
	if names["ok"] || !names["failed"] || !names["child"] || len(names) != 2 {
		t.Fatalf("exported %v, want the failed span and the sampled parent's child", names)
	}

	exp = tracetest.NewInMemoryExporter()
	tp = telemetry.NewTracerProvider(exp, 1, true, resource.Empty())
	_, all := tp.Tracer("test").Start(ctx, "ok")
	all.End()
	_ = tp.ForceFlush(ctx)
	if len(exp.GetSpans()) != 1 {
		t.Fatalf("a ratio of 1 exported %d spans", len(exp.GetSpans()))
	}

	// Without trust in remote parents, a sampled one does not make its child sampled.
	exp = tracetest.NewInMemoryExporter()
	tp = telemetry.NewTracerProvider(exp, 0, false, resource.Empty())
	_, public := tp.Tracer("test").Start(trace.ContextWithRemoteSpanContext(ctx, parent), "public")
	public.End()
	_ = tp.ForceFlush(ctx)
	if len(exp.GetSpans()) != 0 {
		t.Fatalf("a public client's sampled parent made %d spans exported", len(exp.GetSpans()))
	}
}

// TestStartTracing: with an endpoint, spans reach the OTLP/HTTP collector when tracing stops;
// without one, nothing is sent; a bad section is refused.
func TestStartTracing(t *testing.T) {
	old := otel.GetTracerProvider()
	t.Cleanup(func() { otel.SetTracerProvider(old) })
	var posts atomic.Int32
	collector := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost && r.URL.Path == "/v1/traces" {
			posts.Add(1)
		}
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(collector.Close)
	ctx := context.Background()

	stop, err := telemetry.StartTracing(ctx, telemetry.TracingConfig{}, "gateway", "0.1.0")
	if err != nil {
		t.Fatal(err)
	}
	_, s := otel.Tracer("test").Start(ctx, "off")
	s.End()
	_ = stop(ctx)
	if posts.Load() != 0 {
		t.Fatal("something was sent with tracing off")
	}

	one := 1.0
	stop, err = telemetry.StartTracing(ctx, telemetry.TracingConfig{OTLPEndpoint: collector.URL + "/v1/traces", SampleRatio: &one}, "gateway", "0.1.0")
	if err != nil {
		t.Fatal(err)
	}
	_, s = otel.Tracer("test").Start(ctx, "on")
	s.End()
	sctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	if err := stop(sctx); err != nil {
		t.Fatal(err)
	}
	if posts.Load() == 0 {
		t.Fatal("nothing reached the collector")
	}

	half, two := 0.5, 2.0
	for name, cfg := range map[string]telemetry.TracingConfig{
		"not a URL":  {OTLPEndpoint: "collector:4318"},
		"no host":    {OTLPEndpoint: "https:///v1/traces"},
		"a ratio >1": {OTLPEndpoint: collector.URL, SampleRatio: &two},
	} {
		if _, err := telemetry.StartTracing(ctx, cfg, "gateway", "0.1.0"); err == nil {
			t.Errorf("%s: started", name)
		}
	}
	if err := (telemetry.TracingConfig{SampleRatio: &half}).Check(); err != nil {
		t.Errorf("a ratio without an endpoint: %v", err)
	}
}
