// SPDX-License-Identifier: Apache-2.0

package itest_test

import (
	"bytes"
	"fmt"
	"io"
	"net"
	"os"
	"testing"
	"time"

	"github.com/felix-homelab/rpmgr/internal/routes"
	"github.com/felix-homelab/rpmgr/internal/store"
	"github.com/felix-homelab/rpmgr/internal/store/ent"
	"github.com/felix-homelab/rpmgr/internal/store/ent/route"
)

// tcpEchoOn echoes every TCP connection on 127.0.0.1:port; it skips the test if the port is taken.
func tcpEchoOn(t *testing.T, port int) {
	t.Helper()
	ln, err := net.Listen("tcp", addr(port))
	if err != nil {
		t.Skipf("port %d is taken for TCP: %v", port, err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() { defer func() { _ = c.Close() }(); _, _ = io.Copy(c, c) }()
		}
	}()
}

// tcpEchoes reports whether a payload sent over a new TCP connection to port comes back.
func tcpEchoes(port int, payload []byte) bool {
	c, err := net.DialTimeout("tcp", addr(port), time.Second)
	if err != nil {
		return false
	}
	defer func() { _ = c.Close() }()
	_ = c.SetDeadline(time.Now().Add(2 * time.Second))
	if _, err := c.Write(payload); err != nil {
		return false
	}
	got := make([]byte, len(payload))
	_, err = io.ReadFull(c, got)
	return err == nil && bytes.Equal(got, payload)
}

// TestTCPUDPRoute_EndToEnd (D83): a tcp_udp route configured on the controller listens on one
// gateway port with TCP and UDP; TCP connections reach the target's TCP service and datagrams its
// UDP service, on the same port number behind the connector.
func TestTCPUDPRoute_EndToEnd(t *testing.T) {
	p := newDataPlane(t)
	svc, public := udpEchoServer(t), freeTCPUDPPort(t)
	tcpEchoOn(t, svc)
	policy := fmt.Sprintf("version: 1\nallow_targets:\n  - cidr: 127.0.0.1/32\n    ports: [%d]\n", svc)
	if err := os.WriteFile(p.conCfg.PolicyFile, []byte(policy), 0o600); err != nil {
		t.Fatal(err)
	}
	c := p.c
	if _, err := store.ConfigTx(c.Sys, c.DB, func(tx *ent.Tx) ([]string, error) {
		existing, err := tx.Route.Get(c.Sys, p.routeID)
		if err != nil {
			return nil, err
		}
		group := existing.GatewayGroupID
		for _, proto := range []routes.Protocol{routes.TCP, routes.UDP} {
			if _, err := routes.AddPool(c.Sys, tx, c.Org, group, proto, public, public); err != nil {
				return nil, err
			}
		}
		tcp, udp, err := routes.AllocateBoth(c.Sys, tx, c.Org, group, public, "", "")
		if err != nil {
			return nil, err
		}
		r, err := tx.Route.Create().SetOrgID(c.Org).SetName("dns").SetType(route.TypeTCPUDP).SetGatewayGroupID(group).Save(c.Sys)
		if err != nil {
			return nil, err
		}
		if err := tx.RouteTCP.Create().SetOrgID(c.Org).SetRouteID(r.ID).SetPortAllocationID(tcp.ID).Exec(c.Sys); err != nil {
			return nil, err
		}
		if err := tx.RouteUDP.Create().SetOrgID(c.Org).SetRouteID(r.ID).SetPortAllocationID(udp.ID).Exec(c.Sys); err != nil {
			return nil, err
		}
		return []string{r.ID}, tx.RouteTarget.Create().SetOrgID(c.Org).SetRouteID(r.ID).SetConnectorID(p.connector).
			SetKind("address").SetHost("127.0.0.1").SetPort(svc).Exec(c.Sys)
	}); err != nil {
		t.Fatal(err)
	}
	client, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = client.Close() }()
	waitFor(t, "the route does not answer on UDP", func() bool {
		return echoes(client, &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: public}, []byte("udp"))
	})
	waitFor(t, "the route does not answer on TCP", func() bool { return tcpEchoes(public, []byte("tcp")) })
}
