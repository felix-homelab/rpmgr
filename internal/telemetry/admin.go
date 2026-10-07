// SPDX-License-Identifier: Apache-2.0

package telemetry

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/collectors"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

// The admin listener (docs/10-operations.md, "Ports", "Metrics", "Health").
const (
	readyTimeout = 5 * time.Second // a readiness check that takes longer counts as not ready
	adminHeader  = 10 * time.Second
)

// NewRegistry returns a role's metrics registry with the Go runtime and process collectors; feature
// code registers the role's metrics on it. Labels use stable IDs, never per-connection or
// per-client-IP values.
func NewRegistry() *prometheus.Registry {
	r := prometheus.NewRegistry()
	r.MustRegister(collectors.NewGoCollector(), collectors.NewProcessCollector(collectors.ProcessCollectorOpts{}))
	return r
}

// AdminHandler serves /metrics from reg, /healthz, which answers while the process runs, and
// /readyz, which answers 503 with the reason while ready returns an error; ready may be nil.
func AdminHandler(reg *prometheus.Registry, ready func(context.Context) error) http.Handler {
	mux := http.NewServeMux()
	mux.Handle("GET /metrics", promhttp.HandlerFor(reg, promhttp.HandlerOpts{}))
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write([]byte("ok\n")) })
	mux.HandleFunc("GET /readyz", func(w http.ResponseWriter, r *http.Request) {
		if ready != nil {
			ctx, cancel := context.WithTimeout(r.Context(), readyTimeout)
			defer cancel()
			if err := ready(ctx); err != nil {
				http.Error(w, "not ready: "+err.Error(), http.StatusServiceUnavailable)
				return
			}
		}
		_, _ = w.Write([]byte("ok\n"))
	})
	return mux
}

// CheckAdminAddr refuses an admin address that could be reached from the internet: it must be a
// loopback or private address, or localhost, never all interfaces or a public address.
func CheckAdminAddr(addr string) error {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return err
	}
	if strings.EqualFold(host, "localhost") {
		return nil
	}
	ip := net.ParseIP(host)
	switch {
	case ip == nil:
		return fmt.Errorf("admin address %q: want a loopback or private IP address", addr)
	case ip.IsUnspecified():
		return fmt.Errorf("admin address %q: all interfaces include public ones; bind a loopback or private address", addr)
	case !ip.IsLoopback() && !ip.IsPrivate() && !ip.IsLinkLocalUnicast():
		return fmt.Errorf("admin address %q is public; the admin listener is never public", addr)
	}
	return nil
}

// ServeAdmin serves AdminHandler on addr until ctx ends.
func ServeAdmin(ctx context.Context, addr string, reg *prometheus.Registry, ready func(context.Context) error) error {
	if err := CheckAdminAddr(addr); err != nil {
		return err
	}
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return err
	}
	srv := &http.Server{Handler: AdminHandler(reg, ready), ReadHeaderTimeout: adminHeader}
	stop := context.AfterFunc(ctx, func() { _ = srv.Close() })
	defer stop()
	if err := srv.Serve(ln); !errors.Is(err, http.ErrServerClosed) {
		return err
	}
	return nil
}
