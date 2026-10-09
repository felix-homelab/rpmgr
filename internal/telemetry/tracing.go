// SPDX-License-Identifier: Apache-2.0

package telemetry

import (
	"context"
	"errors"
	"fmt"
	"net/url"
	"sync"
	"sync/atomic"
	"time"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracehttp"
	"go.opentelemetry.io/otel/propagation"
	"go.opentelemetry.io/otel/sdk/resource"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
)

// DefaultSampleRatio is the share of traces sampled at their start ([R] docs/10-operations.md,
// "Traces").
const DefaultSampleRatio = 0.01

// TracingConfig is the tracing section of a boot file (docs/10-operations.md, "Traces").
type TracingConfig struct {
	// OTLPEndpoint is the OTLP/HTTP traces URL, such as https://collector:4318/v1/traces; empty
	// turns tracing off.
	OTLPEndpoint string `yaml:"otlp_endpoint"`
	// SampleRatio is the share of traces sampled at their start, 0 to 1; DefaultSampleRatio if
	// not set. A span that fails is exported whatever the sampling.
	SampleRatio *float64 `yaml:"sample_ratio"`
}

// Check reports what is wrong with the section.
func (c TracingConfig) Check() error {
	var errs []error
	if c.OTLPEndpoint != "" {
		if u, err := url.Parse(c.OTLPEndpoint); err != nil || (u.Scheme != "https" && u.Scheme != "http") || u.Host == "" {
			errs = append(errs, fmt.Errorf("tracing.otlp_endpoint %q: want an http or https URL", c.OTLPEndpoint))
		}
	}
	if r := c.SampleRatio; r != nil && (*r < 0 || *r > 1) {
		errs = append(errs, fmt.Errorf("tracing.sample_ratio %v: want 0 to 1", *r))
	}
	return errors.Join(errs...)
}

// StartTracing installs the process's tracer provider and the W3C trace-context propagator
// (docs/10-operations.md, "Traces"). Without an endpoint it installs only the propagator, and
// nothing is exported. The returned function exports what is left and stops.
func StartTracing(ctx context.Context, cfg TracingConfig, role, version string) (func(context.Context) error, error) {
	otel.SetTextMapPropagator(propagation.TraceContext{})
	if cfg.OTLPEndpoint == "" {
		return func(context.Context) error { return nil }, nil
	}
	if err := cfg.Check(); err != nil {
		return nil, err
	}
	exp, err := otlptracehttp.New(ctx, otlptracehttp.WithEndpointURL(cfg.OTLPEndpoint))
	if err != nil {
		return nil, err
	}
	ratio := DefaultSampleRatio
	if cfg.SampleRatio != nil {
		ratio = *cfg.SampleRatio
	}
	// A connector continues the gateway's decision from StreamOpen; a gateway and a controller see
	// remote parents only from public clients, whose decision they do not take.
	tp := NewTracerProvider(exp, ratio, role == "connector", resource.NewSchemaless(attribute.String("service.name", "rpmgr"),
		attribute.String("service.version", version), attribute.String("rpmgr.role", role)))
	otel.SetTracerProvider(tp)
	return tp.Shutdown, nil
}

// NewTracerProvider returns a provider that samples ratio of new traces, follows a local
// parent's decision, and a remote parent's only with trustRemote, and exports the sampled spans
// in batches to exp. It records every other span too, so that one that fails is exported on its
// own.
func NewTracerProvider(exp sdktrace.SpanExporter, ratio float64, trustRemote bool, res *resource.Resource) *sdktrace.TracerProvider {
	share := sdktrace.TraceIDRatioBased(ratio)
	opts := []sdktrace.ParentBasedSamplerOption{}
	if !trustRemote {
		opts = append(opts, sdktrace.WithRemoteParentSampled(share), sdktrace.WithRemoteParentNotSampled(share))
	}
	failed := newFailedSpans(exp)
	return sdktrace.NewTracerProvider(sdktrace.WithResource(res), sdktrace.WithBatcher(exp), sdktrace.WithSpanProcessor(failed),
		sdktrace.WithSampler(recording{sdktrace.ParentBased(share, opts...)}))
}

// recording is a sampler that records the spans its inner sampler drops.
type recording struct{ sdktrace.Sampler }

func (r recording) ShouldSample(p sdktrace.SamplingParameters) sdktrace.SamplingResult {
	res := r.Sampler.ShouldSample(p)
	if res.Decision == sdktrace.Drop {
		res.Decision = sdktrace.RecordOnly
	}
	return res
}

func (r recording) Description() string { return "Recording{" + r.Sampler.Description() + "}" }

// failedSpans exports the spans that were not sampled but failed, in the background; when its
// queue is full it drops them rather than slow down the request that failed.
type failedSpans struct {
	exp     sdktrace.SpanExporter
	queue   chan sdktrace.ReadOnlySpan
	done    chan struct{}
	mu      sync.RWMutex // closed and the queue's closing
	closed  bool
	pending atomic.Int64 // queued spans not exported yet
}

func newFailedSpans(exp sdktrace.SpanExporter) *failedSpans {
	f := &failedSpans{exp: exp, queue: make(chan sdktrace.ReadOnlySpan, 1024), done: make(chan struct{})}
	go func() {
		defer close(f.done)
		for s := range f.queue {
			batch := []sdktrace.ReadOnlySpan{s}
			for len(batch) < 64 && len(f.queue) > 0 {
				batch = append(batch, <-f.queue)
			}
			_ = f.exp.ExportSpans(context.Background(), batch)
			f.pending.Add(-int64(len(batch)))
		}
	}()
	return f
}

func (f *failedSpans) OnStart(context.Context, sdktrace.ReadWriteSpan) {}

func (f *failedSpans) OnEnd(s sdktrace.ReadOnlySpan) {
	if s.SpanContext().IsSampled() || s.Status().Code != codes.Error {
		return
	}
	f.mu.RLock()
	defer f.mu.RUnlock()
	if f.closed {
		return
	}
	f.pending.Add(1)
	select {
	case f.queue <- s:
	default:
		f.pending.Add(-1)
	}
}

func (f *failedSpans) Shutdown(ctx context.Context) error {
	f.mu.Lock()
	if !f.closed {
		f.closed = true
		close(f.queue)
	}
	f.mu.Unlock()
	select {
	case <-f.done:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

// ForceFlush waits until the queued spans are exported.
func (f *failedSpans) ForceFlush(ctx context.Context) error {
	for f.pending.Load() > 0 {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(5 * time.Millisecond):
		}
	}
	return nil
}
