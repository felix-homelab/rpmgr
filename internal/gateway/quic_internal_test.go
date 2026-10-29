// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"math/big"
	"net"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/quic-go/quic-go"

	"github.com/felix-homelab/rpmgr/internal/tunnel"
)

// selfSigned returns a server configuration for "localhost" and the pool that trusts it.
func selfSigned(t *testing.T) (*tls.Config, *x509.CertPool) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "localhost"}, DNSNames: []string{"localhost"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), KeyUsage: x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}, BasicConstraintsValid: true, IsCA: true}
	der, err := x509.CreateCertificate(rand.Reader, tpl, tpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	pool := x509.NewCertPool()
	pool.AddCert(cert)
	return &tls.Config{MinVersion: tls.VersionTLS13, Certificates: []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: key}}}, pool
}

var last atomic.Pointer[tunnel.QUICSession] // the session the last serve call got

func newQUICSide(t *testing.T, addr string, served *atomic.Int32) (*quicSide, *x509.CertPool) {
	t.Helper()
	cfg, pool := selfSigned(t)
	q := &quicSide{addr: addr, tls: cfg, budget: tunnel.NewBudget(tunnel.DefaultWindowBudget), reg: prometheus.NewRegistry(),
		serve: func(s *tunnel.QUICSession) {
			last.Store(s)
			served.Add(1)
			<-s.Done()
		}}
	t.Cleanup(q.close)
	return q, pool
}

func dialQUIC(t *testing.T, to string, pool *x509.CertPool, wait time.Duration) (*tunnel.QUICSession, error) {
	t.Helper()
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	tr := &quic.Transport{Conn: pc}
	t.Cleanup(func() { _ = tr.Close(); _ = pc.Close() })
	addr, err := net.ResolveUDPAddr("udp", to)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), wait)
	defer cancel()
	return tunnel.DialQUIC(ctx, tr, addr, &tls.Config{MinVersion: tls.VersionTLS13, RootCAs: pool, ServerName: "localhost"},
		tunnel.NewBudget(tunnel.DefaultWindowBudget))
}

// TestQUICSide_StopAcceptingKeepsOpenSessions: after the switch of a hand-off the old process takes
// no new QUIC session, and its open ones stay up until it closes the transport; a new dial gets no
// answer, so a connector on auto takes TCP, and nothing resets the open session.
func TestQUICSide_StopAcceptingKeepsOpenSessions(t *testing.T) {
	var served atomic.Int32
	q, pool := newQUICSide(t, "127.0.0.1:0", &served)
	if err := q.open(context.Background()); err != nil {
		t.Fatal(err)
	}
	if !q.bound() || q.localAddr() == "" {
		t.Fatal("not bound after open")
	}
	s, err := dialQUIC(t, q.localAddr(), pool, 3*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; served.Load() == 0 && i < 300; i++ { // a session not accepted yet is refused by Close
		time.Sleep(10 * time.Millisecond)
	}
	q.stopAccepting()
	if _, err := dialQUIC(t, q.localAddr(), pool, 300*time.Millisecond); err == nil {
		t.Fatal("a new session after stopAccepting")
	}
	select {
	case <-s.Done():
		t.Fatalf("the open session ended: %v", s.Err())
	case <-time.After(300 * time.Millisecond):
	}
	if n := served.Load(); n != 1 {
		t.Fatalf("%d sessions served, want 1", n)
	}
	srv := last.Load()
	q.close()
	select {
	case <-srv.Done():
	case <-time.After(3 * time.Second):
		t.Fatal("the open session outlived close")
	}
	if err := q.open(context.Background()); !errors.Is(err, net.ErrClosed) {
		t.Fatalf("open after close: %v", err)
	}
}

// TestQUICSide_OpenWhenFree: the new process binds once the old one's socket closes a moment after
// the old process exited; a port that stays held is reported with the address-in-use error; any
// other error is final at once.
func TestQUICSide_OpenWhenFree(t *testing.T) {
	oldEvery, oldFor := quicBindEvery, quicBindFor
	t.Cleanup(func() { quicBindEvery, quicBindFor = oldEvery, oldFor })
	quicBindEvery, quicBindFor = 10*time.Millisecond, 2*time.Second
	var served atomic.Int32

	held, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = held.Close() })
	q, _ := newQUICSide(t, held.LocalAddr().String(), &served)
	go func() { time.Sleep(150 * time.Millisecond); _ = held.Close() }()
	if err := q.openWhenFree(context.Background()); err != nil {
		t.Fatalf("not bound after the port freed: %v", err)
	}

	still, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = still.Close() })
	quicBindFor = 100 * time.Millisecond
	q2, _ := newQUICSide(t, still.LocalAddr().String(), &served)
	start := time.Now()
	if err := q2.openWhenFree(context.Background()); !errors.Is(err, syscall.EADDRINUSE) {
		t.Fatalf("a held port: %v", err)
	}
	if d := time.Since(start); d < 50*time.Millisecond || d > time.Second {
		t.Fatalf("retried for %v, want about the bind window and no tight loop or hang", d)
	}
	if q2.bound() {
		t.Fatal("bound a held port")
	}

	quicBindFor = time.Minute
	q3, _ := newQUICSide(t, "no-such-host.invalid:1", &served)
	start = time.Now()
	if err := q3.openWhenFree(context.Background()); err == nil || errors.Is(err, syscall.EADDRINUSE) {
		t.Fatalf("a bad address: %v", err)
	}
	if time.Since(start) > 5*time.Second {
		t.Fatal("retried a final error")
	}

	// ctx ending stops the retries.
	q4, _ := newQUICSide(t, still.LocalAddr().String(), &served)
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	if err := q4.openWhenFree(ctx); !errors.Is(err, syscall.EADDRINUSE) {
		t.Fatalf("ctx ended: %v", err)
	}
}

// TestQUICSide_StoppedNeverOpens: a middle generation that switched binds no QUIC port after the
// first old process exits, so the third generation can.
func TestQUICSide_StoppedNeverOpens(t *testing.T) {
	var served atomic.Int32
	q, _ := newQUICSide(t, "127.0.0.1:0", &served)
	q.stopAccepting() // before it ever opened
	if err := q.open(context.Background()); !errors.Is(err, errStopped) {
		t.Fatalf("open after stopAccepting: %v", err)
	}
	if err := q.openWhenFree(context.Background()); !errors.Is(err, errStopped) {
		t.Fatalf("openWhenFree after stopAccepting: %v", err)
	}
	if err := q.openUntilBound(context.Background(), func(error) { t.Error("retried a stopped listener") }); !errors.Is(err, errStopped) {
		t.Fatalf("openUntilBound after stopAccepting: %v", err)
	}
	if q.bound() {
		t.Fatal("bound after stopAccepting")
	}
}

// TestQUICSide_KeepsTrying: after the bind window the gateway keeps trying slowly until the port
// frees, reports each failure, and the gauge follows the listener.
func TestQUICSide_KeepsTrying(t *testing.T) {
	oldEvery, oldFor, oldRetry := quicBindEvery, quicBindFor, quicRetryEvery
	t.Cleanup(func() { quicBindEvery, quicBindFor, quicRetryEvery = oldEvery, oldFor, oldRetry })
	quicBindEvery, quicBindFor, quicRetryEvery = 5*time.Millisecond, 30*time.Millisecond, 50*time.Millisecond
	held, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = held.Close() })
	var served atomic.Int32
	q, _ := newQUICSide(t, held.LocalAddr().String(), &served)
	reg := prometheus.NewRegistry()
	q.reg = reg
	if err := q.register(); err != nil {
		t.Fatal(err)
	}
	gauge := func() float64 {
		mfs, err := reg.Gather()
		if err != nil {
			t.Fatal(err)
		}
		for _, mf := range mfs {
			if mf.GetName() == "rpmgr_gateway_quic_bound" {
				return mf.GetMetric()[0].GetGauge().GetValue()
			}
		}
		t.Fatal("no rpmgr_gateway_quic_bound")
		return -1
	}
	if gauge() != 0 {
		t.Fatal("gauge 1 before open")
	}
	var fails atomic.Int32
	done := make(chan error, 1)
	go func() { done <- q.openUntilBound(context.Background(), func(error) { fails.Add(1) }) }()
	for i := 0; fails.Load() < 2 && i < 300; i++ {
		time.Sleep(10 * time.Millisecond)
	}
	if fails.Load() < 2 || gauge() != 0 {
		t.Fatalf("%d failures reported, gauge %v", fails.Load(), gauge())
	}
	_ = held.Close()
	if err := <-done; err != nil {
		t.Fatalf("not bound after the port freed: %v", err)
	}
	if gauge() != 1 {
		t.Fatal("gauge 0 while bound")
	}
}
