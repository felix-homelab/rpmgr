// SPDX-License-Identifier: Apache-2.0

package telemetry_test

import (
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/felix-homelab/rpmgr/internal/telemetry"
)

func get(t *testing.T, h http.Handler, method, path string) (int, string) {
	t.Helper()
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequestWithContext(context.Background(), method, path, nil))
	b, _ := io.ReadAll(rec.Body)
	return rec.Code, string(b)
}

func TestAdminHandler(t *testing.T) {
	reg := telemetry.NewRegistry()
	var notReady error
	h := telemetry.AdminHandler(reg, func(context.Context) error { return notReady })
	if code, _ := get(t, h, http.MethodGet, "/healthz"); code != http.StatusOK {
		t.Errorf("/healthz: %d", code)
	}
	if code, _ := get(t, h, http.MethodGet, "/readyz"); code != http.StatusOK {
		t.Errorf("/readyz when ready: %d", code)
	}
	notReady = errors.New("no control session")
	if code, body := get(t, h, http.MethodGet, "/readyz"); code != http.StatusServiceUnavailable || !strings.Contains(body, "no control session") {
		t.Errorf("/readyz when not ready: %d %q", code, body)
	}
	if code, body := get(t, h, http.MethodGet, "/metrics"); code != http.StatusOK || !strings.Contains(body, "go_goroutines") {
		t.Errorf("/metrics: %d", code)
	}
	for _, path := range []string{"/debug/pprof/", "/debug/pprof/heap", "/", "/metrics/x"} {
		if code, _ := get(t, h, http.MethodGet, path); code != http.StatusNotFound {
			t.Errorf("%s: %d, want 404", path, code)
		}
	}
	if code, _ := get(t, h, http.MethodPost, "/healthz"); code != http.StatusMethodNotAllowed {
		t.Errorf("POST /healthz: %d", code)
	}
	if code, _ := get(t, telemetry.AdminHandler(reg, nil), http.MethodGet, "/readyz"); code != http.StatusOK {
		t.Errorf("/readyz without a check: %d", code)
	}
}

func TestCheckAdminAddr(t *testing.T) {
	for addr, ok := range map[string]bool{
		"127.0.0.1:7381": true, "[::1]:7381": true, "localhost:7383": true, "10.0.0.5:7382": true,
		"192.168.1.2:7381": true, "172.16.0.1:7381": true, "[fd00::1]:7381": true, "[fe80::1]:7381": true,
		"0.0.0.0:7381": false, "[::]:7381": false, ":7381": false, "203.0.113.5:7381": false, "8.8.8.8:7381": false,
		"[2001:db8::1]:7381": false, "admin.example.com:7381": false, "127.0.0.1": false,
	} {
		if err := telemetry.CheckAdminAddr(addr); (err == nil) != ok {
			t.Errorf("%s: %v, want ok %v", addr, err, ok)
		}
	}
}

func TestServeAdmin(t *testing.T) {
	if err := telemetry.ServeAdmin(context.Background(), "0.0.0.0:0", telemetry.NewRegistry(), nil); err == nil {
		t.Fatal("served on all interfaces")
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := ln.Addr().String()
	_ = ln.Close()
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- telemetry.ServeAdmin(ctx, addr, telemetry.NewRegistry(), nil) }()
	var resp *http.Response
	for i := 0; i < 100; i++ {
		req, _ := http.NewRequestWithContext(context.Background(), http.MethodGet, "http://"+addr+"/healthz", nil)
		if resp, err = http.DefaultClient.Do(req); err == nil {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if err != nil || resp.StatusCode != http.StatusOK {
		t.Fatalf("/healthz over TCP: %v", err)
	}
	_ = resp.Body.Close()
	cancel()
	if err := <-done; err != nil {
		t.Fatalf("ServeAdmin ended with %v", err)
	}
}
