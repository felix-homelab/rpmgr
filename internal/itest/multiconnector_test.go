// SPDX-License-Identifier: Apache-2.0

package itest_test

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/felix-homelab/rpmgr/internal/certs"
	"github.com/felix-homelab/rpmgr/internal/config"
	"github.com/felix-homelab/rpmgr/internal/connector"
	"github.com/felix-homelab/rpmgr/internal/domains"
	"github.com/felix-homelab/rpmgr/internal/gateway"
	"github.com/felix-homelab/rpmgr/internal/itest"
	"github.com/felix-homelab/rpmgr/internal/routes"
	"github.com/felix-homelab/rpmgr/internal/snapshot"
	"github.com/felix-homelab/rpmgr/internal/store"
	"github.com/felix-homelab/rpmgr/internal/store/ent"
	entconnector "github.com/felix-homelab/rpmgr/internal/store/ent/connector"
	"github.com/felix-homelab/rpmgr/internal/store/ent/domain"
	"github.com/felix-homelab/rpmgr/internal/store/ent/routehttp"
	"github.com/felix-homelab/rpmgr/internal/store/ent/routetarget"
)

// nameApp is a web app that answers its name and closes each connection, so that every request
// takes a new tunnel stream.
func nameApp(t *testing.T, name string) int {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	srv := &http.Server{ReadHeaderTimeout: 5 * time.Second, Handler: http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Connection", "close")
		_, _ = io.WriteString(w, name)
	})}
	go func() { _ = srv.Serve(ln) }()
	t.Cleanup(func() { _ = srv.Close() })
	return ln.Addr().(*net.TCPAddr).Port
}

// tcpPing writes msg on c and reads it back within 5 s.
func tcpPing(c net.Conn, msg []byte) error {
	_ = c.SetDeadline(time.Now().Add(5 * time.Second))
	defer func() { _ = c.SetDeadline(time.Time{}) }()
	if _, err := c.Write(msg); err != nil {
		return err
	}
	got := make([]byte, len(msg))
	if _, err := io.ReadFull(c, got); err != nil {
		return err
	}
	if !bytes.Equal(got, msg) {
		return fmt.Errorf("echo %q, not %q", got, msg)
	}
	return nil
}

// TestMultiConnector: a route's targets on two connectors are ranked across them (D90). A failover
// target gets no stream while the preferred connector is ready and every stream once it is not; one
// priority is shared by weight; a target that refuses passes the stream to the other connector; and
// switching one connector off and on leaves the routes the other serves alone undisturbed.
func TestMultiConnector(t *testing.T) {
	for _, transport := range []string{"h2", "auto"} {
		t.Run(transport, func(t *testing.T) { testMultiConnector(t, transport) })
	}
}

func testMultiConnector(t *testing.T, transport string) {
	c := itest.StartController(t, itest.Options{Sources: routes.Sources()})
	dir := t.TempDir()
	gwAddr := addr(freeTCPUDPPort(t))
	group := c.GatewayGroup(t, "eu")
	gw := c.EnrollGateway(t, filepath.Join(dir, "gw-id"), group, []string{gwAddr})
	a, b := c.EnrollConnector(t, filepath.Join(dir, "a-id")), c.EnrollConnector(t, filepath.Join(dir, "b-id"))
	appA, appB, echoA := nameApp(t, "A"), nameApp(t, "B"), echoServer(t)
	refused := freeTCPUDPPort(t) // nothing listens there
	tcpA, tcpD := freeTCPUDPPort(t), freeTCPUDPPort(t)

	k, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(9), Subject: pkix.Name{CommonName: "a.example.com"},
		DNSNames:  []string{"a.example.com", "f.example.com", "s.example.com", "d.example.com"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(24 * time.Hour)}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &k.PublicKey, k)
	if err != nil {
		t.Fatal(err)
	}
	leaf, _ := x509.ParseCertificate(der)
	pool := x509.NewCertPool()
	pool.AddCert(leaf)
	pk, _ := x509.MarshalPKCS8PrivateKey(k)

	type target struct {
		con                    string
		port, priority, weight int
	}
	if _, err := store.ConfigTx(c.Sys, c.DB, func(tx *ent.Tx) ([]string, error) {
		var changed []string
		if transport == "h2" {
			for _, id := range []string{a.AgentID, b.AgentID} {
				if err := tx.Connector.UpdateOneID(id).SetTransport(entconnector.TransportH2).Exec(c.Sys); err != nil {
					return nil, err
				}
			}
		}
		addTargets := func(route string, targets []target, http bool) error {
			for _, tg := range targets {
				q := tx.RouteTarget.Create().SetOrgID(c.Org).SetRouteID(route).SetConnectorID(tg.con).SetKind("address").
					SetHost("127.0.0.1").SetPort(tg.port).SetPriority(tg.priority).SetWeight(max(tg.weight, 1))
				if http {
					q.SetUpstreamProtocol(routetarget.UpstreamProtocolHTTP)
				}
				if err := q.Exec(c.Sys); err != nil {
					return err
				}
			}
			return nil
		}
		tcpRoute := func(name string, port int, targets ...target) error {
			if _, err := routes.AddPool(c.Sys, tx, c.Org, group, routes.TCP, port, port); err != nil {
				return err
			}
			alloc, err := routes.Allocate(c.Sys, tx, c.Org, group, routes.TCP, port)
			if err != nil {
				return err
			}
			r, err := tx.Route.Create().SetOrgID(c.Org).SetName(name).SetType("tcp").SetGatewayGroupID(group).Save(c.Sys)
			if err != nil {
				return err
			}
			changed = append(changed, r.ID)
			if err := tx.RouteTCP.Create().SetOrgID(c.Org).SetRouteID(r.ID).SetPortAllocationID(alloc.ID).Exec(c.Sys); err != nil {
				return err
			}
			return addTargets(r.ID, targets, false)
		}
		d, err := domains.Claim(c.Sys, tx, c.Org, "example.com", true)
		if err != nil {
			return nil, err
		}
		if err := tx.Domain.UpdateOne(d).SetStatus(domain.StatusVerified).Exec(c.Sys); err != nil {
			return nil, err
		}
		crt, err := certs.Upload(c.Sys, tx, c.Sealer(), c.Org, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}),
			pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: pk}), time.Now())
		if err != nil {
			return nil, err
		}
		changed = append(changed, crt.ID)
		httpRoute := func(name, host string, targets ...target) error {
			r, err := tx.Route.Create().SetOrgID(c.Org).SetName(name).SetType("http").SetGatewayGroupID(group).Save(c.Sys)
			if err != nil {
				return err
			}
			changed = append(changed, r.ID)
			if err := tx.RouteHTTP.Create().SetOrgID(c.Org).SetRouteID(r.ID).SetTLSMode(routehttp.TLSModeCertificate).
				SetCertificateID(crt.ID).Exec(c.Sys); err != nil {
				return err
			}
			if _, err := routes.AddHostname(c.Sys, tx, r.ID, host, ""); err != nil {
				return err
			}
			return addTargets(r.ID, targets, true)
		}
		for _, err := range []error{
			tcpRoute("tcp-a", tcpA, target{a.AgentID, echoA, 0, 1}),
			tcpRoute("tcp-d", tcpD, target{a.AgentID, echoA, 0, 1}, target{b.AgentID, refused, 0, 1}),
			httpRoute("web-a", "a.example.com", target{a.AgentID, appA, 0, 1}),
			httpRoute("web-f", "f.example.com", target{a.AgentID, appA, 0, 1}, target{b.AgentID, appB, 10, 1}),
			httpRoute("web-s", "s.example.com", target{a.AgentID, appA, 0, 1}, target{b.AgentID, appB, 0, 3}),
			httpRoute("web-d", "d.example.com", target{a.AgentID, appA, 0, 1}, target{b.AgentID, refused, 0, 1}),
		} {
			if err != nil {
				return nil, err
			}
		}
		return changed, nil
	}); err != nil {
		t.Fatal(err)
	}

	var gc config.Gateway
	gc.Version = 1
	gc.Controller.Endpoints = []string{c.URL}
	gc.IdentityDir, gc.StateDir = gw.Dir, filepath.Join(dir, "gw-state")
	gc.Listen.TCP, gc.Listen.UDP, gc.Listen.Admin = gwAddr, gwAddr, addr(freeTCPUDPPort(t))
	if err := os.MkdirAll(gc.StateDir, 0o750); err != nil {
		t.Fatal(err)
	}
	runRole(t, func(ctx context.Context, listening func()) error {
		return gateway.Run(ctx, gateway.RunOptions{Config: gc, Version: "0.1.0", DrainPeriod: 200 * time.Millisecond, Listening: listening})
	})
	for _, con := range []struct {
		dir, name string
		ports     []int
	}{{a.Dir, "a", []int{appA, echoA}}, {b.Dir, "b", []int{appB, refused}}} {
		var cc config.Connector
		cc.Version = 1
		cc.Controller.Endpoints = []string{c.URL}
		cc.IdentityDir, cc.StateDir = con.dir, filepath.Join(dir, con.name+"-state")
		cc.PolicyFile = filepath.Join(dir, con.name+"-policy.yaml")
		cc.Listen.Admin = addr(freeTCPUDPPort(t))
		if err := os.MkdirAll(cc.StateDir, 0o750); err != nil {
			t.Fatal(err)
		}
		ps := make([]string, len(con.ports))
		for i, p := range con.ports {
			ps[i] = strconv.Itoa(p)
		}
		policy := fmt.Sprintf("version: 1\nallow_targets:\n  - cidr: 127.0.0.1/32\n    ports: [%s]\n", strings.Join(ps, ", "))
		if err := os.WriteFile(cc.PolicyFile, []byte(policy), 0o600); err != nil {
			t.Fatal(err)
		}
		runRole(t, func(ctx context.Context, listening func()) error {
			return connector.Run(ctx, connector.RunOptions{Config: cc, Version: "0.1.0", Getenv: func(string) string { return "" },
				Listening: listening})
		})
	}

	client := &http.Client{Timeout: 10 * time.Second, Transport: &http.Transport{DisableKeepAlives: true,
		TLSClientConfig: &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS13},
		DialContext: func(ctx context.Context, network, _ string) (net.Conn, error) {
			var d net.Dialer
			return d.DialContext(ctx, network, gwAddr)
		}}}
	get := func(host string) (string, error) {
		resp, err := client.Get("https://" + host + "/")
		if err != nil {
			return "", err
		}
		defer func() { _ = resp.Body.Close() }()
		body, err := io.ReadAll(resp.Body)
		if err == nil && resp.StatusCode != http.StatusOK {
			err = fmt.Errorf("%s: %s", resp.Status, body)
		}
		return string(body), err
	}
	answers := func(host string, n int) map[string]int {
		t.Helper()
		got := map[string]int{}
		for range n {
			body, err := get(host)
			if err != nil {
				t.Fatalf("%s: %v", host, err)
			}
			got[body]++
		}
		return got
	}
	waitFor := func(what string, cond func() bool) {
		t.Helper()
		deadline := time.Now().Add(30 * time.Second)
		for !cond() {
			if time.Now().After(deadline) {
				t.Fatalf("timed out waiting for %s", what)
			}
			time.Sleep(20 * time.Millisecond)
		}
	}
	setEnabled := func(con string, enabled bool) {
		t.Helper()
		rev, err := store.ConfigTx(c.Sys, c.DB, func(tx *ent.Tx) ([]string, error) {
			return []string{con}, tx.Connector.UpdateOneID(con).SetEnabled(enabled).Exec(c.Sys)
		})
		if err != nil {
			t.Fatal(err)
		}
		waitFor("the switch applied", func() bool {
			for _, id := range []string{gw.AgentID, a.AgentID, b.AgentID} {
				st, err := c.DB.Client().AgentState.Get(c.Sys, id)
				if err != nil || snapshot.RevisionStatus(st, rev, time.Now()) != snapshot.ApplyApplied {
					return false
				}
			}
			return true
		})
	}
	// Both connectors serve: web-s answers from each.
	waitFor("both connectors ready", func() bool {
		body, err := get("s.example.com")
		return err == nil && body == "B"
	})
	waitFor("connector A ready", func() bool {
		body, err := get("a.example.com")
		return err == nil && body == "A"
	})

	// The failover target gets nothing while A is ready.
	if got := answers("f.example.com", 40); got["A"] != 40 {
		t.Fatalf("web-f answers %v, want only A", got)
	}
	// Weights 1 and 3 of one priority share the streams.
	if got := answers("s.example.com", 200); got["B"] < 110 || got["B"] > 190 {
		t.Fatalf("web-s answers %v, want about 50 A and 150 B", got)
	}
	// B's target refuses: every request still succeeds, through A.
	if got := answers("d.example.com", 40); got["A"] != 40 {
		t.Fatalf("web-d answers %v, want only A", got)
	}
	for i := range 20 {
		c, err := net.DialTimeout("tcp", addr(tcpD), 5*time.Second)
		if err != nil {
			t.Fatal(err)
		}
		if err := tcpPing(c, []byte("ping "+strconv.Itoa(i))); err != nil {
			t.Fatalf("tcp-d connection %d: %v", i, err)
		}
		_ = c.Close()
	}

	// A switched off: the failover takes every stream; A on again: it takes them back.
	setEnabled(a.AgentID, false)
	waitFor("web-f on B", func() bool { body, err := get("f.example.com"); return err == nil && body == "B" })
	if got := answers("f.example.com", 20); got["B"] != 20 {
		t.Fatalf("web-f answers %v with A off, want only B", got)
	}
	setEnabled(a.AgentID, true)
	waitFor("web-f on A again", func() bool { body, err := get("f.example.com"); return err == nil && body == "A" })

	// B switched off and on twice under traffic on A's own routes: none of it fails.
	long, err := net.DialTimeout("tcp", addr(tcpA), 5*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = long.Close() }()
	ctx, stop := context.WithCancel(t.Context())
	var (
		wg       sync.WaitGroup
		ops      atomic.Int64
		failMu   sync.Mutex
		failures []string
	)
	fail := func(format string, args ...any) {
		failMu.Lock()
		defer failMu.Unlock()
		failures = append(failures, fmt.Sprintf(format, args...))
	}
	wg.Go(func() {
		for i := 0; ctx.Err() == nil; i++ {
			if body, err := get("a.example.com"); err != nil || body != "A" {
				fail("web-a request %d: %q %v", i, body, err)
			}
			ops.Add(1)
		}
	})
	wg.Go(func() {
		for i := 0; ctx.Err() == nil; i++ {
			if err := tcpPing(long, []byte("long "+strconv.Itoa(i))); err != nil {
				fail("tcp-a long connection, ping %d: %v", i, err)
				return
			}
			ops.Add(1)
			time.Sleep(10 * time.Millisecond)
		}
	})
	for range 2 {
		setEnabled(b.AgentID, false)
		time.Sleep(300 * time.Millisecond)
		setEnabled(b.AgentID, true)
		waitFor("web-s on B again", func() bool { body, err := get("s.example.com"); return err == nil && body == "B" })
	}
	stop()
	wg.Wait()
	if len(failures) > 0 || ops.Load() < 20 {
		t.Fatalf("%d operations on A's own routes, failures: %v", ops.Load(), failures)
	}
}
