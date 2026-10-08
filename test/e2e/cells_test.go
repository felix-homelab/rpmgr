// SPDX-License-Identifier: Apache-2.0

//go:build e2e

package e2e

import (
	"fmt"
	"strconv"
	"testing"
	"time"
)

// client runs e2eclient in the client container.
func client(args ...string) error {
	_, err := in("client", append([]string{"e2eclient"}, args...)...)
	return err
}

// eventually retries f for up to d.
func eventually(t *testing.T, d time.Duration, what string, f func() error) {
	t.Helper()
	var err error
	for end := time.Now().Add(d); time.Now().Before(end); time.Sleep(500 * time.Millisecond) {
		if err = f(); err == nil {
			return
		}
	}
	t.Fatalf("%s: %v", what, err)
}

// addRoute seeds a tcp route to the echo service on port, served by connectors.
func addRoute(t *testing.T, name string, port int, transport string, connectors ...string) {
	t.Helper()
	args := []string{"--name", name, "--port", strconv.Itoa(port), "--target", serviceAddr}
	if transport != "" {
		args = append(args, "--transport", transport)
	}
	for _, c := range connectors {
		args = append(args, "--connector", c)
	}
	if _, err := seed("route", args...); err != nil {
		t.Fatal(err)
	}
}

// background runs f and returns a channel with its result.
func background(f func() error) <-chan error {
	done := make(chan error, 1)
	go func() { done <- f() }()
	return done
}

func addr(host string, port int) string { return fmt.Sprintf("%s:%d", host, port) }

// TestTCP: a tcp route on each transport policy carries 1 MiB each way intact through both
// gateways, over IPv4 and IPv6; an open connection survives an unrelated change and a change of
// the same route; a removed route stops answering while an open connection finishes.
func TestTCP(t *testing.T) {
	for i, transport := range []string{"quic", "h2", "auto"} {
		t.Run(transport, func(t *testing.T) {
			port, name := 20001+i, "tcp-"+transport
			addRoute(t, name, port, transport, "con1", "con2")
			eventually(t, 30*time.Second, "the route through gw1", func() error { return client("check", "-addr", addr("gw1", port)) })
			for _, a := range []string{addr("gw2", port), addr("[fd00:30::11]", port), addr("[fd00:30::12]", port)} {
				eventually(t, 15*time.Second, "the route through "+a, func() error { return client("check", "-addr", a) })
			}

			held := background(func() error { return client("hold", "-addr", addr("gw1", port), "-duration", "8s") })
			time.Sleep(time.Second)
			addRoute(t, "other-"+transport, 20101+i, transport, "con1")
			if _, err := seed("route-update", "--name", name, "--idle", "2h"); err != nil {
				t.Fatal(err)
			}
			if err := <-held; err != nil {
				t.Fatalf("a connection across an unrelated and a same-route change: %v", err)
			}

			held = background(func() error { return client("hold", "-addr", addr("gw2", port), "-duration", "4s") })
			time.Sleep(time.Second)
			if _, err := seed("route-update", "--name", name, "--enabled", "false"); err != nil {
				t.Fatal(err)
			}
			if err := client("gone", "-addr", addr("gw1", port), "-duration", "20s"); err != nil {
				t.Fatalf("a removed route: %v", err)
			}
			if err := <-held; err != nil {
				t.Fatalf("an open connection of a removed route within the drain period: %v", err)
			}
		})
	}
}

// TestGateway_DrainAndKill: a gateway stopped with SIGTERM keeps an open connection until it
// ends while the other gateway serves new ones, and serves again after a restart; a gateway killed
// with SIGKILL serves again after a restart.
func TestGateway_DrainAndKill(t *testing.T) {
	port := 20201
	addRoute(t, "drain", port, "auto", "con1", "con2")
	for _, gw := range []string{"gw1", "gw2"} {
		eventually(t, 30*time.Second, "the route through "+gw, func() error { return client("check", "-addr", addr(gw, port)) })
	}
	held := background(func() error { return client("hold", "-addr", addr("gw1", port), "-duration", "6s") })
	time.Sleep(time.Second)
	stopped := background(func() error { return signal("gw1", "TERM") })
	time.Sleep(time.Second)
	if err := client("check", "-addr", addr("gw2", port)); err != nil {
		t.Fatalf("the other gateway while gw1 drains: %v", err)
	}
	if err := <-held; err != nil {
		t.Fatalf("an open connection through a draining gateway: %v", err)
	}
	if err := <-stopped; err != nil {
		t.Fatal(err)
	}
	if err := startRole("gw1", "gateway"); err != nil {
		t.Fatal(err)
	}
	eventually(t, 60*time.Second, "gw1 after a restart", func() error { return client("check", "-addr", addr("gw1", port)) })

	if err := signal("gw2", "KILL"); err != nil {
		t.Fatal(err)
	}
	if err := startRole("gw2", "gateway"); err != nil {
		t.Fatal(err)
	}
	eventually(t, 60*time.Second, "gw2 after SIGKILL and a restart", func() error { return client("check", "-addr", addr("gw2", port)) })
}

// TestController_Down: with the controller down, routes keep working, and a gateway restarted
// meanwhile serves from its last-known-good snapshot.
func TestController_Down(t *testing.T) {
	port := 20301
	addRoute(t, "ctl-down", port, "auto", "con1", "con2")
	eventually(t, 30*time.Second, "the route", func() error { return client("check", "-addr", addr("gw1", port)) })
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
	if err := client("check", "-addr", addr("gw1", port)); err != nil {
		t.Fatalf("with the controller down: %v", err)
	}
	if err := signal("gw1", "KILL"); err != nil {
		t.Fatal(err)
	}
	if err := startRole("gw1", "gateway"); err != nil {
		t.Fatal(err)
	}
	eventually(t, 60*time.Second, "a gateway restarted while the controller is down", func() error {
		return client("check", "-addr", addr("gw1", port))
	})
}

// TestDenyList_PersistedAcrossGatewayRestart (processes clause): a revoked connector loses its
// data sessions, and a gateway restarted while the controller is down still refuses it, from
// the deny-list on its disk, while it serves the other connector's routes from its last-known-good
// snapshot.
func TestDenyList_PersistedAcrossGatewayRestart(t *testing.T) {
	only2, only1 := 20401, 20402
	addRoute(t, "only-con2", only2, "auto", "con2")
	addRoute(t, "only-con1", only1, "auto", "con1")
	for _, p := range []int{only2, only1} {
		eventually(t, 30*time.Second, "the routes", func() error { return client("check", "-addr", addr("gw1", p)) })
	}
	if _, err := seed("revoke", "--kind", "connector", "--name", "con2"); err != nil {
		t.Fatal(err)
	}
	if err := client("gone", "-addr", addr("gw1", only2), "-duration", "20s"); err != nil {
		t.Fatalf("the revoked connector's route: %v", err)
	}
	if err := signal("ctl", "KILL"); err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := startRole("ctl", "controller"); err != nil {
			t.Error(err)
		}
	}()
	if err := signal("gw1", "KILL"); err != nil {
		t.Fatal(err)
	}
	if err := startRole("gw1", "gateway"); err != nil {
		t.Fatal(err)
	}
	eventually(t, 60*time.Second, "the other connector's route after the restart", func() error {
		return client("check", "-addr", addr("gw1", only1))
	})
	time.Sleep(5 * time.Second) // con2 retries its data session within this time
	if err := client("gone", "-addr", addr("gw1", only2), "-duration", "1s"); err != nil {
		t.Fatalf("after a restart without the controller the revoked connector is served again: %v", err)
	}
}
