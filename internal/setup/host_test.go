// SPDX-License-Identifier: Apache-2.0

package setup

import (
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// TestReady: setup waits until /readyz answers 200, and gives up with the last answer when its
// context ends first.
func TestReady(t *testing.T) {
	var calls atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/readyz" || calls.Add(1) < 2 {
			w.WriteHeader(http.StatusServiceUnavailable)
		}
	}))
	t.Cleanup(srv.Close)
	addr := strings.TrimPrefix(srv.URL, "http://")
	if err := ready(context.Background(), addr); err != nil || calls.Load() != 2 {
		t.Fatalf("ready after %d calls: %v", calls.Load(), err)
	}

	never := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusServiceUnavailable)
	}))
	t.Cleanup(never.Close)
	ctx, cancel := context.WithTimeout(context.Background(), 1500*time.Millisecond)
	defer cancel()
	if err := ready(ctx, strings.TrimPrefix(never.URL, "http://")); err == nil || !strings.Contains(err.Error(), "503") {
		t.Errorf("never ready: %v", err)
	}
}

// TestHostDefaults: the real port check sees an address in use, and giving a tree away fails
// without root, whether the service user exists or not.
func TestHostDefaults(t *testing.T) {
	var h Host
	h.defaults()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = ln.Close() }()
	if h.PortFree(ln.Addr().String()) {
		t.Errorf("%s in use reported free", ln.Addr())
	}
	if h.Paths != DefaultPaths() {
		t.Errorf("paths %+v", h.Paths)
	}
	if os.Geteuid() == 0 {
		t.Skip("runs as root")
	}
	if err := h.GiveTo(t.TempDir()); err == nil {
		t.Error("a tree given away without root")
	}
}
