// SPDX-License-Identifier: Apache-2.0

package gateway_test

import (
	"net"
	"net/http"
	"testing"
	"time"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/propagation"
	"go.opentelemetry.io/otel/sdk/resource"
	"go.opentelemetry.io/otel/sdk/trace/tracetest"
	"go.opentelemetry.io/otel/trace"

	"github.com/felix-homelab/rpmgr/internal/gateway"
	"github.com/felix-homelab/rpmgr/internal/telemetry"
)

// traced installs a tracer provider that samples every trace into the returned exporter, for one
// test that must not run in parallel with others.
func traced(t *testing.T) *tracetest.InMemoryExporter {
	t.Helper()
	exp := tracetest.NewInMemoryExporter()
	tp := telemetry.NewTracerProvider(exp, 1, true, resource.Empty())
	old, oldProp := otel.GetTracerProvider(), otel.GetTextMapPropagator()
	otel.SetTracerProvider(tp)
	otel.SetTextMapPropagator(propagation.TraceContext{})
	t.Cleanup(func() { otel.SetTracerProvider(old); otel.SetTextMapPropagator(oldProp) })
	return exp
}

// TestTracing_ContextCrossesTheTunnel (docs/10-operations.md, "Traces"): the gateway's span of a
// stream it opens is the parent of the connector's dial span, through StreamOpen; an HTTP request
// continues the client's trace context, and its upstream gets the gateway's span as parent.
func TestTracing_ContextCrossesTheTunnel(t *testing.T) {
	exp := traced(t)
	p := newPlane(t, service(t, echoService), "rt_1")
	port := freePort(t)
	p.routes.Apply([]gateway.TCPRoute{{ID: "rt_1", Port: port}})
	if err := ping(dialPort(t, port), "traced"); err != nil {
		t.Fatal(err)
	}
	var open, dial *tracetest.SpanStub
	eventually(t, "no spans of the stream", func() bool {
		for _, s := range exp.GetSpans() {
			switch s.Name {
			case "rpmgr.gateway.open_stream":
				open = &s
			case "rpmgr.connector.dial":
				dial = &s
			}
		}
		return open != nil && dial != nil
	})
	if dial.SpanContext.TraceID() != open.SpanContext.TraceID() || dial.Parent.SpanID() != open.SpanContext.SpanID() || !dial.Parent.IsRemote() {
		t.Fatalf("the connector's span %v is not the child of the gateway's %v", dial.Parent, open.SpanContext)
	}

	exp.Reset()
	got := make(chan string, 1)
	upLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	up := &http.Server{ReadHeaderTimeout: 5 * time.Second, Handler: http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		got <- r.Header.Get("traceparent")
	})}
	go func() { _ = up.Serve(upLn) }()
	t.Cleanup(func() { _ = up.Close() })
	hp := newPlaneWith(t, upLn.Addr().String(), "none", "rt_web")
	e := newHTTPEnvOn(t, hp.sessions, gateway.HTTPRoute{ID: "rt_web", Upstream: "http", Hosts: []gateway.HTTPHost{{Hostname: "app.example.com"}}})
	const client = "00-0af7651916cd43dd8448eb211c80319c-b7ad6b7169203331-01"
	if r := get(t, e.client(false), "https://app.example.com/", http.Header{"Traceparent": {client}}); r.status != http.StatusOK {
		t.Fatalf("a request: %d", r.status)
	}
	upstream := <-got
	var server *tracetest.SpanStub
	eventually(t, "no span of the request", func() bool {
		for _, s := range exp.GetSpans() {
			if s.Name == "rpmgr.gateway.http" {
				server = &s
			}
		}
		return server != nil
	})
	clientTrace, _ := trace.TraceIDFromHex("0af7651916cd43dd8448eb211c80319c")
	if server.SpanContext.TraceID() != clientTrace || server.Parent.SpanID().String() != "b7ad6b7169203331" {
		t.Fatalf("the request's span %v does not continue the client's trace", server.Parent)
	}
	if want := "00-" + clientTrace.String() + "-" + server.SpanContext.SpanID().String() + "-01"; upstream != want {
		t.Fatalf("the upstream got traceparent %q, want %q", upstream, want)
	}
}
