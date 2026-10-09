// SPDX-License-Identifier: Apache-2.0

package load_test

import (
	"context"
	"encoding/pem"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/felix-homelab/rpmgr/bench/load"
)

// listen serves a TCP service on a loopback port and returns its address.
func listen(t *testing.T, serve func(net.Listener) error) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	go func() { _ = serve(ln) }()
	return ln.Addr().String()
}

func TestThroughput(t *testing.T) {
	ctx := context.Background()
	for dir, serve := range map[string]func(net.Listener) error{"up": load.ServeSink, "down": load.ServeSource} {
		addr := listen(t, serve)
		for _, streams := range []int{1, 4} {
			r, err := load.Throughput(ctx, addr, dir, streams, 200*time.Millisecond)
			if err != nil || r.Failures != 0 || r.Bytes == 0 || r.Mbps() <= 0 {
				t.Errorf("%s ×%d: %+v %v", dir, streams, r, err)
			}
		}
	}
	addr := listen(t, load.ServeSink)
	for _, bad := range []struct {
		dir     string
		streams int
	}{{"up", 0}, {"sideways", 1}} {
		if _, err := load.Throughput(ctx, addr, bad.dir, bad.streams, time.Millisecond); err == nil {
			t.Errorf("%s ×%d accepted", bad.dir, bad.streams)
		}
	}
	if r, _ := load.Throughput(ctx, "127.0.0.1:1", "up", 2, time.Millisecond); r.Failures != 2 {
		t.Errorf("no service: %+v", r)
	}
}

func TestSetup(t *testing.T) {
	addr := listen(t, load.ServeEcho)
	r, err := load.Setup(context.Background(), addr, 100, 300*time.Millisecond)
	if err != nil || len(r.Latencies) != 30 || r.Failures != 0 || r.Percentile(99) < r.Percentile(50) {
		t.Fatalf("%d latencies, %d failures, %v", len(r.Latencies), r.Failures, err)
	}
	if _, err := load.Setup(context.Background(), addr, 0, time.Second); err == nil {
		t.Error("rate 0 accepted")
	}
	if (load.SetupResult{}).Percentile(99) != 0 {
		t.Error("the percentile of nothing")
	}
}

func TestUDP(t *testing.T) {
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = pc.Close() })
	go func() { _ = load.ServeUDPEcho(pc) }()
	for _, size := range []int{1200, 1400, 3000} {
		r, err := load.UDP(context.Background(), pc.LocalAddr().String(), size, 200, 500*time.Millisecond)
		if err != nil || r.Sent != 100 || r.Received != 100 || r.Loss() != 0 || r.PPS() <= 0 {
			t.Errorf("%d bytes: %+v %v", size, r, err)
		}
	}
	for _, bad := range [][2]int{{7, 10}, {65001, 10}, {1200, 0}} {
		if _, err := load.UDP(context.Background(), pc.LocalAddr().String(), bad[0], bad[1], time.Millisecond); err == nil {
			t.Errorf("size %d, rate %d accepted", bad[0], bad[1])
		}
	}
	if (load.UDPResult{}).Loss() != 0 || (load.UDPResult{Sent: 4, Received: 1}).Loss() != 75 {
		t.Error("loss")
	}
}

func TestHTTP(t *testing.T) {
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write([]byte("ok")) }))
	srv.EnableHTTP2 = true
	srv.StartTLS()
	t.Cleanup(srv.Close)
	ca := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: srv.Certificate().Raw})
	addr := srv.Listener.Addr().String()
	r, err := load.HTTP(context.Background(), addr, "https://example.com/", ca, 4, 300*time.Millisecond)
	if err != nil || r.Failures != 0 || len(r.Latencies) == 0 || r.RPS() <= 0 {
		t.Fatalf("%d requests, %d failures, %v", len(r.Latencies), r.Failures, err)
	}
	// A name the certificate does not hold fails every request; nothing is skipped.
	if r, err := load.HTTP(context.Background(), addr, "https://other.test/", ca, 2, 100*time.Millisecond); err != nil || len(r.Latencies) != 0 || r.Failures == 0 {
		t.Errorf("another name: %d requests, %d failures, %v", len(r.Latencies), r.Failures, err)
	}
	if _, err := load.HTTP(context.Background(), addr, "https://example.com/", nil, 1, time.Millisecond); err == nil {
		t.Error("no CA accepted")
	}
	if _, err := load.HTTP(context.Background(), addr, "https://example.com/", ca, 0, time.Millisecond); err == nil {
		t.Error("no workers accepted")
	}
}

func TestHold(t *testing.T) {
	addr := listen(t, load.ServeEcho)
	r, err := load.Hold(context.Background(), addr, 3, 500*time.Millisecond)
	if err != nil || r.Lost != 0 || r.Conns != 3 || r.Pings < 3 {
		t.Fatalf("%+v %v", r, err)
	}
	// A service that closes at once loses every connection.
	closing := listen(t, func(ln net.Listener) error {
		for {
			c, err := ln.Accept()
			if err != nil {
				return err
			}
			_ = c.Close()
		}
	})
	if r, _ := load.Hold(context.Background(), closing, 2, 300*time.Millisecond); r.Lost != 2 {
		t.Errorf("a closing service: %+v", r)
	}
	if _, err := load.Hold(context.Background(), addr, 0, time.Millisecond); err == nil {
		t.Error("no connections accepted")
	}
}

func TestWho(t *testing.T) {
	addr := listen(t, func(ln net.Listener) error { return load.ServeWho(ln, "con1") })
	r, err := load.Who(context.Background(), addr, 50, 200*time.Millisecond)
	if err != nil || r.By["con1"] != 10 || r.Failures != 0 {
		t.Fatalf("%+v %v", r, err)
	}
	if r, _ := load.Who(context.Background(), "127.0.0.1:1", 20, 100*time.Millisecond); r.Failures != 2 {
		t.Errorf("no service: %+v", r)
	}
	if _, err := load.Who(context.Background(), addr, 0, time.Second); err == nil {
		t.Error("rate 0 accepted")
	}
}
