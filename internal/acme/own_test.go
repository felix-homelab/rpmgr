// SPDX-License-Identifier: Apache-2.0

package acme_test

import (
	"bytes"
	"context"
	"crypto/tls"
	"errors"
	"log/slog"
	"net"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/mholt/acmez/v3"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/fieldmaskpb"

	rpmgrv1 "github.com/felix-homelab/rpmgr/gen/rpmgr/v1"
	"github.com/felix-homelab/rpmgr/internal/acme"
	"github.com/felix-homelab/rpmgr/internal/acme/acmetest"
	"github.com/felix-homelab/rpmgr/internal/lease"
	"github.com/felix-homelab/rpmgr/internal/settings"
	"github.com/felix-homelab/rpmgr/internal/store"
	"github.com/felix-homelab/rpmgr/internal/store/storetest"
)

// syncBuffer is a log destination for several goroutines.
type syncBuffer struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (s *syncBuffer) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.Write(p)
}

func (s *syncBuffer) String() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.String()
}

func eventually(t *testing.T, d time.Duration, msg string, f func() bool) {
	t.Helper()
	for deadline := time.Now().Add(d); !f(); time.Sleep(100 * time.Millisecond) {
		if time.Now().After(deadline) {
			t.Fatal(msg)
		}
	}
}

// TestOwn: the controller's own certificate. Only a public DNS name is eligible. A CA that cannot
// be reached leaves the controller without one and logs why. Pebble then issues it, validated
// over the controller's own port 80 (HTTP-01), and it is served whatever name the client asked;
// it is renewed; a renewal that fails keeps the certificate in use. Without port 80 the CA
// validates over port 443 (TLS-ALPN-01).
func TestOwn(t *testing.T) {
	acme.SetOwnRenewCheck(t, 500*time.Millisecond)
	for host, want := range map[string]bool{"panel.example.com": true, "localhost": false, "ctl": false, "127.0.0.1": false,
		"2001:db8::1": false, "panel.internal": false, "box.local": false, "app.localhost": false, "*.example.com": false} {
		if acme.Eligible(host) != want {
			t.Errorf("Eligible(%q) = %v", host, !want)
		}
	}
	db := storetest.Migrated(t, store.SQLite)
	storetest.Init(t, db)
	sys := storetest.SystemCtx(t)
	storage := acme.NewStorage(db, sys, sealer(t), lease.New(db, "ctn_a", nil), nil)
	t.Cleanup(storage.Close)
	if _, err := acme.NewOwn(acme.OwnOptions{DB: db, Sys: sys, Storage: storage, Host: "localhost"}); err == nil {
		t.Fatal("an Own for localhost")
	}
	setCA := func(dir string) {
		t.Helper()
		if _, err := settings.UpdateInstance(sys, db, &rpmgrv1.InstanceSettings{AcmeDirectoryUrl: proto.String(dir),
			AcmeEmail: proto.String("ops@example.com")}, &fieldmaskpb.FieldMask{Paths: []string{"acme_directory_url", "acme_email"}}, 0); err != nil {
			t.Fatal(err)
		}
	}
	var logs syncBuffer
	logger := slog.New(slog.NewTextHandler(&logs, nil))
	const failed = `msg="cannot obtain the public URL's certificate; keeping the one in use" host=panel.example.com renewal=`

	// The controller's port 80 and 443; they answer with the Own in use.
	var cur atomic.Pointer[acme.Own]
	plain, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	web := &http.Server{ReadHeaderTimeout: 5 * time.Second, Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		cur.Load().HTTPHandler(http.NotFoundHandler()).ServeHTTP(w, r)
	})}
	go func() { _ = web.Serve(plain) }()
	t.Cleanup(func() { _ = web.Close() })
	secure, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{MinVersion: tls.VersionTLS13, NextProtos: []string{"http/1.1", acmez.ACMETLS1Protocol},
		GetCertificate: func(h *tls.ClientHelloInfo) (*tls.Certificate, error) { return cur.Load().GetCertificate(h) }})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = secure.Close() })
	go func() {
		for {
			c, err := secure.Accept()
			if err != nil {
				return
			}
			go func() { _ = c.(*tls.Conn).Handshake(); _ = c.Close() }()
		}
	}()

	// A CA that cannot be reached.
	setCA("https://127.0.0.1:1/directory")
	own, err := acme.NewOwn(acme.OwnOptions{DB: db, Sys: sys, Storage: storage, Host: "panel.example.com", Logger: logger})
	if err != nil {
		t.Fatal(err)
	}
	unreachable, stop := context.WithCancel(context.Background())
	if err := own.Manage(unreachable); err != nil {
		t.Fatal(err)
	}
	eventually(t, 30*time.Second, "no warning about the CA that cannot be reached", func() bool { return strings.Contains(logs.String(), failed+"false") })
	if _, err := own.GetCertificate(&tls.ClientHelloInfo{ServerName: "panel.example.com"}); own.Has() || !errors.Is(err, acme.ErrNoCertificate) {
		t.Fatalf("a certificate without a CA: %v", err)
	}
	stop()
	own.Stop()

	dns, err := acmetest.StartDNS([]string{"example.com"}, func(string) []string { return nil })
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(dns.Close)
	pebble, err := acmetest.Start(acmetest.Options{HTTPPort: plain.Addr().(*net.TCPAddr).Port, TLSPort: secure.Addr().(*net.TCPAddr).Port,
		Resolver: dns.Addr, Validity: time.Minute})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(pebble.Close)
	setCA(pebble.DirectoryURL)
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	roots, err := pebble.IssuanceRoots(ctx)
	if err != nil {
		t.Fatal(err)
	}
	serial := func(host string) string {
		c, err := tls.Dial("tcp", secure.Addr().String(), &tls.Config{ServerName: host, RootCAs: roots, MinVersion: tls.VersionTLS13})
		if err != nil {
			return ""
		}
		defer func() { _ = c.Close() }()
		return c.ConnectionState().PeerCertificates[0].SerialNumber.String()
	}
	start := func(o acme.OwnOptions) *acme.Own {
		t.Helper()
		o.DB, o.Sys, o.Storage, o.Logger, o.TrustedRoots, o.DisableARI, o.RenewalWindowRatio = db, sys, storage, logger, pebble.ServerRoots, true, 0.9
		own, err := acme.NewOwn(o)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(own.Stop)
		cur.Store(own)
		if err := own.Manage(ctx); err != nil {
			t.Fatal(err)
		}
		return own
	}

	// HTTP-01 on port 80.
	acme.SetOwnHTTP01Only(t, true)
	own = start(acme.OwnOptions{Host: "panel.example.com"})
	var first string
	eventually(t, time.Minute, "the certificate was never obtained", func() bool { first = serial("panel.example.com"); return first != "" })
	if !own.Has() {
		t.Fatal("Has after obtaining")
	}
	if c, err := own.GetCertificate(&tls.ClientHelloInfo{ServerName: "other.example.com"}); err != nil || c.Leaf == nil ||
		c.Leaf.DNSNames[0] != "panel.example.com" {
		t.Fatalf("another name: %v", err)
	}
	// With 90 % of its one-minute lifetime as the renewal window, the certificate is due after 6 s.
	var renewed string
	eventually(t, time.Minute, "the certificate was not renewed", func() bool {
		renewed = serial("panel.example.com")
		return renewed != "" && renewed != first
	})
	// The next renewal fails: the CA reaches nothing at the name. A renewal already validated may
	// still complete; once one failed, none can succeed, and the certificate in use stays.
	dns.SetA("panel.example.com", net.IPv4(127, 0, 0, 2))
	posts := pebble.ChallengePosts.Load()
	eventually(t, time.Minute, "no failed renewal", func() bool { return strings.Contains(logs.String(), failed+"true") })
	if pebble.ChallengePosts.Load() == posts {
		t.Fatal("the renewal did not ask the CA to validate")
	}
	kept := serial("panel.example.com")
	if kept == "" || !own.Has() {
		t.Fatal("no certificate in use after a failed renewal")
	}
	time.Sleep(time.Second)
	if s := serial("panel.example.com"); s != kept {
		t.Fatalf("the certificate in use changed after a failed renewal: %s, was %s", s, kept)
	}

	// TLS-ALPN-01 on port 443, for a controller without port 80.
	acme.SetOwnHTTP01Only(t, false)
	start(acme.OwnOptions{Host: "alpn.example.com", NoHTTP01: true})
	eventually(t, time.Minute, "the TLS-ALPN-01 certificate was never obtained", func() bool { return serial("alpn.example.com") != "" })
}
