// SPDX-License-Identifier: Apache-2.0

package itest_test

import (
	"bytes"
	"crypto/rand"
	"fmt"
	"net"
	"os"
	"testing"
	"time"

	"github.com/felix-homelab/rpmgr/internal/routes"
	"github.com/felix-homelab/rpmgr/internal/store"
	"github.com/felix-homelab/rpmgr/internal/store/ent"
	"github.com/felix-homelab/rpmgr/internal/store/ent/route"
)

// udpEchoServer echoes every datagram to its sender.
func udpEchoServer(t *testing.T) int {
	t.Helper()
	c, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = c.Close() })
	go func() {
		buf := make([]byte, 70000)
		for {
			n, from, err := c.ReadFromUDPAddrPort(buf)
			if err != nil {
				return
			}
			_, _ = c.WriteToUDPAddrPort(buf[:n], from)
		}
	}()
	return c.LocalAddr().(*net.UDPAddr).Port
}

// echoes reports whether a payload sent to addr comes back within a few tries.
func echoes(c *net.UDPConn, addr *net.UDPAddr, payload []byte) bool {
	buf := make([]byte, 70000)
	for range 4 {
		if _, err := c.WriteToUDP(payload, addr); err != nil {
			return false
		}
		_ = c.SetReadDeadline(time.Now().Add(250 * time.Millisecond))
		if n, err := c.Read(buf); err == nil && bytes.Equal(buf[:n], payload) {
			return true
		}
	}
	return false
}

// TestUDPRoute_EndToEnd: a udp route configured on the controller carries datagrams from the
// gateway's port to the service behind the connector and back, small and large ones, on QUIC and
// on h2.
func TestUDPRoute_EndToEnd(t *testing.T) {
	p := newDataPlane(t)
	svc, public := udpEchoServer(t), freeTCPUDPPort(t)
	policy := fmt.Sprintf("version: 1\nallow_targets:\n  - cidr: 127.0.0.1/32\n    ports: [%d]\n", svc)
	if err := os.WriteFile(p.conCfg.PolicyFile, []byte(policy), 0o600); err != nil {
		t.Fatal(err)
	}
	c := p.c
	var routeID string
	if _, err := store.ConfigTx(c.Sys, c.DB, func(tx *ent.Tx) ([]string, error) {
		tcp, err := tx.Route.Get(c.Sys, p.routeID)
		if err != nil {
			return nil, err
		}
		group := tcp.GatewayGroupID
		if _, err := routes.AddPool(c.Sys, tx, c.Org, group, routes.UDP, public, public); err != nil {
			return nil, err
		}
		alloc, err := routes.Allocate(c.Sys, tx, c.Org, group, routes.UDP, public)
		if err != nil {
			return nil, err
		}
		r, err := tx.Route.Create().SetOrgID(c.Org).SetName("dns").SetType("udp").SetGatewayGroupID(group).Save(c.Sys)
		if err != nil {
			return nil, err
		}
		routeID = r.ID
		if err := tx.RouteUDP.Create().SetOrgID(c.Org).SetRouteID(r.ID).SetPortAllocationID(alloc.ID).Exec(c.Sys); err != nil {
			return nil, err
		}
		return []string{r.ID}, tx.RouteTarget.Create().SetOrgID(c.Org).SetRouteID(r.ID).SetConnectorID(p.connector).
			SetKind("address").SetHost("127.0.0.1").SetPort(svc).Exec(c.Sys)
	}); err != nil {
		t.Fatal(err)
	}
	to := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: public}
	payload := func(n int) []byte {
		b := make([]byte, n)
		_, _ = rand.Read(b)
		return b
	}
	for _, transport := range []route.Transport{route.TransportQuic, route.TransportH2} {
		if _, err := store.ConfigTx(c.Sys, c.DB, func(tx *ent.Tx) ([]string, error) {
			return []string{routeID}, tx.Route.UpdateOneID(routeID).SetTransport(transport).Exec(c.Sys)
		}); err != nil {
			t.Fatal(err)
		}
		// A new client address after a transport change, so the flow starts on the new transport.
		client, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
		if err != nil {
			t.Fatal(err)
		}
		waitFor(t, fmt.Sprintf("the udp route does not answer on %s", transport), func() bool { return echoes(client, to, payload(100)) })
		if !echoes(client, to, payload(3000)) {
			t.Fatalf("a payload above the datagram limit on %s", transport)
		}
		_ = client.Close()
	}
}
