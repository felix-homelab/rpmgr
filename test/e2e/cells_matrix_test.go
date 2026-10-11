// SPDX-License-Identifier: Apache-2.0

//go:build e2e

package e2e

import (
	"errors"
	"fmt"
	"os"
	"strconv"
	"testing"
	"time"
)

// The full cross-product of the end-to-end matrix (docs/12-testing-and-quality.md, "End-to-end
// topology matrix"), which the nightly run sets E2E_FULL=1 for: every scenario below runs on a cell
// of every Phase 1 route type on each transport value, served by both connectors and checked
// through both gateways. Its routes use the ports from 23000, 100 per scenario.

// fullMatrix skips a test outside the nightly run.
func fullMatrix(t *testing.T) {
	t.Helper()
	if os.Getenv("E2E_FULL") == "" {
		t.Skip("the full matrix runs nightly, with E2E_FULL=1")
	}
}

var transports = []string{"auto", "quic", "h2"}

// mroute is one route of a matrix cell.
type mroute struct {
	kind, transport, name, host string
	port                        int
}

// cell creates the routes of one scenario's cell: per transport a tcp, a udp, an http route with an
// HTTP/1.1 upstream (HTTP/1.1, HTTP/2 and WebSocket clients), one with an h2c upstream (gRPC) and a
// tls_passthrough route. It waits until every route answers through both gateways.
func cell(t *testing.T, scenario int) []mroute {
	t.Helper()
	var rs []mroute
	for i, tr := range transports {
		base := 23000 + 100*scenario + 10*i
		prefix := fmt.Sprintf("m%d-%s", scenario, tr)
		rs = append(rs,
			mroute{kind: "tcp", transport: tr, name: prefix + "-tcp", port: base + 1},
			mroute{kind: "udp", transport: tr, name: prefix + "-udp", port: base + 2},
			mroute{kind: "web", transport: tr, name: prefix + "-web", host: prefix + "-web.e2e.test"},
			mroute{kind: "grpc", transport: tr, name: prefix + "-grpc", host: prefix + "-grpc.e2e.test"},
			mroute{kind: "pt", transport: tr, name: prefix + "-pt", host: prefix + ".pt.e2e.test"})
	}
	connectors := []string{"--connector", "con1", "--connector", "con2"}
	for _, r := range rs {
		common := append([]string{"--name", r.name, "--transport", r.transport}, connectors...)
		var err error
		switch r.kind {
		case "tcp":
			_, err = seed("route", append(common, "--port", strconv.Itoa(r.port), "--target", serviceAddr)...)
		case "udp":
			_, err = seed("udp-route", append(common, "--port", strconv.Itoa(r.port), "--target", svcHost+":7008")...)
		case "web", "grpc":
			upstream := map[string]string{"web": "http", "grpc": "h2c"}[r.kind]
			if err = routeCertificate(r.name, r.host); err == nil {
				_, err = seed("http-route", append(common, "--hostname", r.host, "--target", svcHost+":7080", "--upstream", upstream,
					"--cert-file", "/var/lib/rpmgr/route-"+r.name+".crt", "--key-file", "/var/lib/rpmgr/route-"+r.name+".key")...)
			}
		case "pt":
			_, err = seed("passthrough-route", append(common, "--hostname", r.host, "--target", svcHost+":7443")...)
		}
		if err != nil {
			t.Fatal(err)
		}
	}
	for _, r := range rs {
		for _, gw := range []string{"gw1", "gw2"} {
			eventually(t, 60*time.Second, r.name+" through "+gw, func() error { return r.check(gw) })
		}
	}
	t.Cleanup(func() { disable(t, rs) })
	return rs
}

// routeCertificate writes the certificate an http route uploads, from the web CA.
func routeCertificate(name, host string) error {
	crt, key, err := issue(host, host)
	if err != nil {
		return err
	}
	if err := writeFile("ctl", "route-"+name+".crt", crt); err != nil {
		return err
	}
	return writeFile("ctl", "route-"+name+".key", key)
}

// check checks a route through a gateway as a client of its kind does.
func (r mroute) check(gw string) error {
	switch r.kind {
	case "tcp":
		return client("check", "-addr", addr(gw, r.port))
	case "udp":
		return client("udp", "-addr", addr(gw, r.port), "-sizes", "100,1200,3000,60000", "-duration", "3s")
	case "web":
		if err := client("http", "-addr", gw+":8443", "-url", "https://"+r.host+"/m", "-expect", "HTTP/1.1 "+r.host+" /m"); err != nil {
			return err
		}
		if err := client("http", "-addr", gw+":8443", "-h2", "-url", "https://"+r.host+"/m2", "-expect", r.host+" /m2"); err != nil {
			return err
		}
		return client("ws", "-addr", gw+":8443", "-host", r.host)
	case "grpc":
		return client("grpc", "-addr", gw+":8443", "-host", r.host)
	default:
		return client("tls", "-addr", gw+":8443", "-host", r.host, "-expect", "e2e backend")
	}
}

// all checks every route through both gateways.
func all(t *testing.T, rs []mroute, what string) {
	t.Helper()
	for _, r := range rs {
		for _, gw := range []string{"gw1", "gw2"} {
			eventually(t, 60*time.Second, what+": "+r.name+" through "+gw, func() error { return r.check(gw) })
		}
	}
}

// disable removes routes from service.
func disable(t *testing.T, rs []mroute) {
	t.Helper()
	for _, r := range rs {
		if _, err := seed("route-update", "--name", r.name, "--enabled", "false"); err != nil {
			t.Error(err)
		}
	}
}

// holds keeps a connection through each tcp route of rs, through gw, for d; the returned function
// waits for them and reports the first that failed.
func holds(rs []mroute, gw string, d time.Duration) func() error {
	var done []<-chan error
	for _, r := range rs {
		if r.kind == "tcp" {
			done = append(done, background(func() error { return client("hold", "-addr", addr(gw, r.port), "-duration", d.String()) }))
		}
	}
	time.Sleep(time.Second)
	return func() error {
		var errs []error
		for _, c := range done {
			errs = append(errs, <-c)
		}
		return errors.Join(errs...)
	}
}

// restart kills node's role with sig and starts it again.
func restart(t *testing.T, node, role string, port int, sig string) {
	t.Helper()
	if err := signal(node, sig); err != nil {
		t.Fatal(err)
	}
	if err := startRole(node, role); err != nil {
		t.Fatal(err)
	}
	if err := ready(node, port); err != nil {
		t.Fatal(err)
	}
}

// TestMatrix runs every scenario of the matrix that needs real processes on a cell of every route
// type and transport. Connector revocation, UDP blackholed mid-session and the restore of a single
// route type are per-PR cells of their own; certificate expiry, grace re-authentication and clock
// skew run in-process with a fake clock (internal/itest); NAT rebinding is not covered yet.
func TestMatrix(t *testing.T) {
	fullMatrix(t)
	scenarios := []struct {
		name string
		run  func(t *testing.T, rs []mroute)
	}{
		{"steady state", func(t *testing.T, rs []mroute) {}},
		{"unrelated change", func(t *testing.T, rs []mroute) {
			wait := holds(rs, "gw1", 6*time.Second)
			addRoute(t, "m-unrelated", 23999, "auto", "con1")
			if err := wait(); err != nil {
				t.Errorf("an open connection across an unrelated change: %v", err)
			}
		}},
		{"same-route change", func(t *testing.T, rs []mroute) {
			wait := holds(rs, "gw2", 6*time.Second)
			for _, r := range rs {
				if _, err := seed("route-update", "--name", r.name, "--idle", "2h"); err != nil {
					t.Fatal(err)
				}
			}
			if err := wait(); err != nil {
				t.Errorf("an open connection across a change of its route: %v", err)
			}
		}},
		{"route removed", func(t *testing.T, rs []mroute) {
			wait := holds(rs, "gw2", 4*time.Second)
			disable(t, rs)
			for _, r := range rs {
				for _, gw := range []string{"gw1", "gw2"} {
					eventually(t, 30*time.Second, "removed: "+r.name+" through "+gw, func() error {
						if r.check(gw) == nil {
							return errors.New("it still answers")
						}
						return nil
					})
				}
			}
			if err := wait(); err != nil {
				t.Errorf("an open connection of a removed route within the drain period: %v", err)
			}
			for _, r := range rs {
				if _, err := seed("route-update", "--name", r.name, "--enabled", "true"); err != nil {
					t.Fatal(err)
				}
			}
		}},
		{"gateway drained", func(t *testing.T, rs []mroute) {
			wait := holds(rs, "gw2", 5*time.Second)
			restart(t, "gw1", "gateway", 7382, "TERM")
			if err := wait(); err != nil {
				t.Errorf("a connection through the other gateway: %v", err)
			}
		}},
		{"gateway killed", func(t *testing.T, rs []mroute) {
			wait := holds(rs, "gw1", 5*time.Second)
			restart(t, "gw2", "gateway", 7382, "KILL")
			if err := wait(); err != nil {
				t.Errorf("a connection through the other gateway: %v", err)
			}
		}},
		{"controller down", func(t *testing.T, rs []mroute) {
			if err := signal("ctl", "KILL"); err != nil {
				t.Fatal(err)
			}
			defer func() {
				if err := startRole("ctl", "controller"); err != nil {
					t.Error(err)
				}
				if err := ready("ctl", 7381); err != nil {
					t.Error(err)
				}
			}()
			wait := holds(rs, "gw1", 5*time.Second)
			all(t, rs, "with the controller down")
			if err := wait(); err != nil {
				t.Errorf("a connection while the controller is down: %v", err)
			}
		}},
		{"controller restored", func(t *testing.T, rs []mroute) {
			if _, err := in("ctl", "rpmgr", "backup", "--out", "/var/lib/rpmgr/matrix.backup", "--config", "/var/lib/rpmgr/controller.yaml"); err != nil {
				t.Fatal(err)
			}
			addRoute(t, "m-after-backup", 23998, "auto", "con1", "con2")
			eventually(t, 30*time.Second, "the route from after the backup", func() error { return client("check", "-addr", addr("gw1", 23998)) })
			if err := signal("ctl", "TERM"); err != nil {
				t.Fatal(err)
			}
			if _, err := in("ctl", "rpmgr", "restore", "--in", "/var/lib/rpmgr/matrix.backup", "--config", "/var/lib/rpmgr/controller.yaml"); err != nil {
				t.Fatal(err)
			}
			if err := startRole("ctl", "controller"); err != nil {
				t.Fatal(err)
			}
			if err := ready("ctl", 7381); err != nil {
				t.Fatal(err)
			}
			eventually(t, 60*time.Second, "the route from after the backup gone", func() error {
				if client("check", "-addr", addr("gw1", 23998)) == nil {
					return errors.New("it still answers")
				}
				return nil
			})
		}},
		{"access tightened", func(t *testing.T, rs []mroute) {
			wait := holds(rs, "gw1", 20*time.Second)
			for _, r := range rs {
				if _, err := seed("access", "--route", r.name, "--rule", "deny=172.30.0.30/32,fd00:30::30/128"); err != nil {
					t.Fatal(err)
				}
			}
			if err := wait(); err == nil {
				t.Error("connections the tightened policy denies lasted their full time")
			}
			for _, r := range rs {
				if err := r.check("gw2"); err == nil {
					t.Errorf("%s answers a denied client", r.name)
				}
				if _, err := seed("access", "--route", r.name); err != nil {
					t.Fatal(err)
				}
			}
		}},
		{"local policy", func(t *testing.T, rs []mroute) {
			for _, con := range []string{"con1", "con2"} {
				if err := writeFile(con, "policy.yaml", "version: 1\nallow_targets: []\n"); err != nil {
					t.Fatal(err)
				}
			}
			for _, r := range rs {
				eventually(t, 30*time.Second, "blocked by the local policy: "+r.name, func() error {
					if r.check("gw1") == nil {
						return errors.New("it still answers")
					}
					return nil
				})
			}
			for _, con := range []string{"con1", "con2"} {
				if err := writeFile(con, "policy.yaml", connectorPolicy); err != nil {
					t.Fatal(err)
				}
			}
		}},
	}
	for i, sc := range scenarios {
		t.Run(sc.name, func(t *testing.T) {
			rs := cell(t, i)
			sc.run(t, rs)
			all(t, rs, "after "+sc.name)
		})
	}
}
