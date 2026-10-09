// SPDX-License-Identifier: Apache-2.0

package gateway_test

import (
	"bufio"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/quic-go/quic-go"

	agentv1 "github.com/felix-homelab/rpmgr/gen/rpmgr/agent/v1"
	tunnelv1 "github.com/felix-homelab/rpmgr/gen/rpmgr/tunnel/v1"
	conn "github.com/felix-homelab/rpmgr/internal/connector"
	"github.com/felix-homelab/rpmgr/internal/gateway"
	"github.com/felix-homelab/rpmgr/internal/policy"
	"github.com/felix-homelab/rpmgr/internal/testutil/freeport"
	"github.com/felix-homelab/rpmgr/internal/tunnel"
)

// routeAssignment assigns every route to the world's connector.
type routeAssignment struct{ con string }

func (a routeAssignment) Known(id string) bool       { return id == a.con }
func (a routeAssignment) Connectors(string) []string { return []string{a.con} }

// plane is a gateway with its data-session listener and tcp routes, and a connector with a data
// session to it that delivers every route to target.
type plane struct {
	sessions *gateway.Sessions
	routes   *gateway.TCPRoutes
	targets  *conn.Targets
}

// newPlane starts the gateway and the connector; route IDs map to the service at target, which
// gets a PROXY v1 header.
func newPlane(t *testing.T, target string, routeIDs ...string) *plane {
	t.Helper()
	return newPlaneWith(t, target, "v1", routeIDs...)
}

// newPlaneWith is newPlane with the PROXY protocol version proxy, "none" for none.
func newPlaneWith(t *testing.T, target, proxy string, routeIDs ...string) *plane {
	t.Helper()
	return planeWith(t, target, proxy, nil, routeIDs...)
}

// planeWith is newPlaneWith whose sessions record metrics.
func planeWith(t *testing.T, target, proxy string, metrics *gateway.Metrics, routeIDs ...string) *plane {
	t.Helper()
	w := newWorld(t)
	p := &plane{sessions: gateway.NewSessions(gateway.SessionsOptions{TrustDomain: td, GatewayID: w.gw.ID,
		Assignment: routeAssignment{w.con.ID}, Metrics: metrics})}
	t.Cleanup(p.sessions.Close)
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	tr := &quic.Transport{Conn: pc}
	ln, err := tunnel.ListenQUIC(tr, gateway.QUICTLS(td, w.gw.ID, w.tunnelTLS), tunnel.NewBudget(tunnel.DefaultWindowBudget))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close(); _ = tr.Close() })
	go func() {
		for {
			s, err := ln.Accept(context.Background())
			if err != nil {
				return
			}
			go func() { _ = p.sessions.Serve(context.Background(), s, s.PeerCertificate()) }()
		}
	}()
	p.routes = gateway.NewTCPRoutes(gateway.TCPOptions{Host: "127.0.0.1", Sessions: p.sessions,
		Revision: func() *agentv1.Revision { return &agentv1.Revision{Seq: 7} }})
	t.Cleanup(p.routes.Close)

	host, portStr, _ := net.SplitHostPort(target)
	port, _ := strconv.Atoi(portStr)
	allow, err := policy.Parse([]byte(fmt.Sprintf("version: 1\nallow_targets:\n  - cidr: %s/32\n    ports: [%d]\n", host, port)))
	if err != nil {
		t.Fatal(err)
	}
	cpc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ctr := &quic.Transport{Conn: cpc}
	var con *conn.Sessions
	p.targets = conn.NewTargets(conn.TargetsOptions{Policy: func() *policy.Policy { return allow },
		OnHealth: func(h *tunnelv1.RouteHealth) { con.SetReady(h) }})
	con = conn.New(conn.Options{QUIC: ctr, Streams: p.targets.Handle, TLS: func(string) (*tls.Config, error) {
		return w.conTLS(w.gw.DNSName()), nil
	}})
	t.Cleanup(func() { con.Close(); _ = ctr.Close() })
	var crs []conn.Route
	gws := map[string]string{}
	for _, id := range routeIDs {
		crs = append(crs, conn.Route{ID: id, Targets: []conn.Target{{ID: "tg_" + id, Host: host, Port: uint16(port), //nolint:gosec // G115: a port
			ProxyProtocol: proxy}}})
		gws[id] = conn.TransportQUIC
	}
	p.targets.Set(crs)
	con.Set([]conn.Gateway{{ID: w.gw.ID, Endpoints: []string{pc.LocalAddr().String()}, Routes: gws}})
	eventually(t, "no data session", func() bool { return p.sessions.Count()["quic"] == 1 })
	return p
}

// freePort returns a port that was free a moment ago.
func freePort(t *testing.T) uint16 { return uint16(freeport.Port(t)) } //nolint:gosec // G115: a port

// service accepts connections, strips the PROXY v1 line and hands the rest to serve.
func service(t *testing.T, serve func(c net.Conn, br *bufio.Reader, proxyLine string)) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				br := bufio.NewReader(c)
				line, err := br.ReadString('\n')
				if err != nil {
					_ = c.Close()
					return
				}
				serve(c, br, line)
			}()
		}
	}()
	return ln.Addr().String()
}

func echoService(c net.Conn, br *bufio.Reader, _ string) {
	_, _ = io.Copy(c, br)
	_ = c.(*net.TCPConn).CloseWrite()
	_ = c.Close()
}

func dialPort(t *testing.T, port uint16) *net.TCPConn {
	t.Helper()
	c, err := net.Dial("tcp", net.JoinHostPort("127.0.0.1", strconv.Itoa(int(port))))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = c.Close() })
	return c.(*net.TCPConn)
}

// ping writes and reads back through an echo connection.
func ping(c net.Conn, msg string) error {
	if _, err := c.Write([]byte(msg)); err != nil {
		return err
	}
	_ = c.SetReadDeadline(time.Now().Add(5 * time.Second))
	defer func() { _ = c.SetReadDeadline(time.Time{}) }()
	b := make([]byte, len(msg))
	if _, err := io.ReadFull(c, b); err != nil {
		return err
	}
	if string(b) != msg {
		return fmt.Errorf("echo %q, want %q", b, msg)
	}
	return nil
}

// TestTCPRoutes_Echo: 4 MiB each way arrive intact through gateway and connector, with the client's
// address in the PROXY header; the client's FIN reaches the service and its answer still arrives.
func TestTCPRoutes_Echo(t *testing.T) {
	lines := make(chan string, 4)
	target := service(t, func(c net.Conn, br *bufio.Reader, line string) {
		lines <- line
		echoService(c, br, line)
	})
	p := newPlane(t, target, "rt_1")
	port := freePort(t)
	if st := p.routes.Apply([]gateway.TCPRoute{{ID: "rt_1", Port: port}}); len(st) != 0 {
		t.Fatal(st)
	}
	c := dialPort(t, port)
	up := make([]byte, 4<<20)
	_, _ = rand.Read(up)
	go func() {
		_, _ = c.Write(up)
		_ = c.CloseWrite()
	}()
	down, err := io.ReadAll(c)
	if err != nil || sha256.Sum256(down) != sha256.Sum256(up) {
		t.Fatalf("echo of 4 MiB: %d bytes, %v", len(down), err)
	}
	want := fmt.Sprintf("PROXY TCP4 127.0.0.1 127.0.0.1 %d %d\r\n", c.LocalAddr().(*net.TCPAddr).Port, port)
	if got := <-lines; got != want {
		t.Fatalf("PROXY header %q, want %q", got, want)
	}
}

// TestTCPRoutes_ChangesKeepConnections: neither an unrelated change nor a change of the same
// route on the same port resets an open connection.
func TestTCPRoutes_ChangesKeepConnections(t *testing.T) {
	p := newPlane(t, service(t, echoService), "rt_1", "rt_2")
	p1, p2 := freePort(t), freePort(t)
	p.routes.Apply([]gateway.TCPRoute{{ID: "rt_1", Port: p1}})
	c := dialPort(t, p1)
	if err := ping(c, "before"); err != nil {
		t.Fatal(err)
	}
	p.routes.Apply([]gateway.TCPRoute{{ID: "rt_1", Port: p1}, {ID: "rt_2", Port: p2}})
	if err := ping(c, "after an unrelated change"); err != nil {
		t.Fatal(err)
	}
	if err := ping(dialPort(t, p2), "the added route"); err != nil {
		t.Fatal(err)
	}
	p.routes.Apply([]gateway.TCPRoute{{ID: "rt_1", Port: p1, IdleTimeout: time.Hour}, {ID: "rt_2", Port: p2}})
	if err := ping(c, "after a change of the same route"); err != nil {
		t.Fatal(err)
	}
}

// TestTCPRoutes_RemovedRouteDrains: a removed route's port refuses new connections at once, and
// its open connections work until the drain period ends, then are reset; a route that moves to
// another port is served there.
func TestTCPRoutes_RemovedRouteDrains(t *testing.T) {
	gateway.SetRouteTimers(t, 500*time.Millisecond, time.Second)
	p := newPlane(t, service(t, echoService), "rt_1")
	p1, p2 := freePort(t), freePort(t)
	p.routes.Apply([]gateway.TCPRoute{{ID: "rt_1", Port: p1}})
	c := dialPort(t, p1)
	if err := ping(c, "before"); err != nil {
		t.Fatal(err)
	}
	p.routes.Apply([]gateway.TCPRoute{{ID: "rt_1", Port: p2}})
	if _, err := net.Dial("tcp", net.JoinHostPort("127.0.0.1", strconv.Itoa(int(p1)))); err == nil {
		t.Fatal("the old port still accepts")
	}
	if err := ping(dialPort(t, p2), "on the new port"); err != nil {
		t.Fatal(err)
	}
	if err := ping(c, "while draining"); err != nil {
		t.Fatal(err)
	}
	time.Sleep(700 * time.Millisecond)
	if err := ping(c, "after the drain"); err == nil {
		t.Fatal("a connection survived the drain period")
	}
}

// TestTCPRoutes_PortInUse: a port that is taken makes its route not_ready(port_in_use) without
// holding up the others, and is bound once it is free.
func TestTCPRoutes_PortInUse(t *testing.T) {
	gateway.SetRouteTimers(t, time.Second, 200*time.Millisecond)
	p := newPlane(t, service(t, echoService), "rt_1", "rt_2")
	busy, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	taken := uint16(busy.Addr().(*net.TCPAddr).Port) //nolint:gosec // G115: a port
	free := freePort(t)
	st := p.routes.Apply([]gateway.TCPRoute{{ID: "rt_1", Port: taken}, {ID: "rt_2", Port: free}})
	if len(st) != 1 || st[0].GetResourceId() != "rt_1" || st[0].GetReason() != agentv1.NotReadyReason_NOT_READY_REASON_PORT_IN_USE ||
		!strings.Contains(st[0].GetDetail(), strconv.Itoa(int(taken))) {
		t.Fatalf("status %v", st)
	}
	if err := ping(dialPort(t, free), "the other route"); err != nil {
		t.Fatal(err)
	}
	_ = busy.Close()
	eventually(t, "the freed port was not bound", func() bool { return len(p.routes.Status()) == 0 })
	if err := ping(dialPort(t, taken), "once free"); err != nil {
		t.Fatal(err)
	}
}

// TestTCPRoutes_IdleTimeout: a connection without traffic for the idle timeout is closed; traffic
// in either direction keeps it open.
func TestTCPRoutes_IdleTimeout(t *testing.T) {
	p := newPlane(t, service(t, echoService), "rt_1")
	port := freePort(t)
	p.routes.Apply([]gateway.TCPRoute{{ID: "rt_1", Port: port, IdleTimeout: 400 * time.Millisecond}})
	c := dialPort(t, port)
	for i := range 5 {
		time.Sleep(200 * time.Millisecond)
		if err := ping(c, "keep "+strconv.Itoa(i)); err != nil {
			t.Fatalf("an active connection was closed: %v", err)
		}
	}
	time.Sleep(700 * time.Millisecond)
	if err := ping(c, "late"); err == nil {
		t.Fatal("an idle connection stayed open")
	}
}

// TestTCPRoutes_NoSession: without a ready session for the route the client is reset at once.
func TestTCPRoutes_NoSession(t *testing.T) {
	p := newPlane(t, service(t, echoService), "rt_1")
	port := freePort(t)
	p.routes.Apply([]gateway.TCPRoute{{ID: "rt_other", Port: port}})
	c, err := net.Dial("tcp", net.JoinHostPort("127.0.0.1", strconv.Itoa(int(port))))
	if err == nil { // the reset may also come before the dial returns
		defer func() { _ = c.Close() }()
		_ = c.SetReadDeadline(time.Now().Add(5 * time.Second))
		_, err = c.Read(make([]byte, 1))
	}
	var ne net.Error
	if err == nil || (errors.As(err, &ne) && ne.Timeout()) {
		t.Fatalf("%v; want the connection reset or closed", err)
	}
}

// TestTCPRoutes_Close: Close stops the listeners and the connections.
func TestTCPRoutes_Close(t *testing.T) {
	p := newPlane(t, service(t, echoService), "rt_1")
	port := freePort(t)
	p.routes.Apply([]gateway.TCPRoute{{ID: "rt_1", Port: port}})
	c := dialPort(t, port)
	if err := ping(c, "open"); err != nil {
		t.Fatal(err)
	}
	var closed atomic.Bool
	go func() { p.routes.Close(); closed.Store(true) }()
	eventually(t, "Close did not return", closed.Load)
	if err := ping(c, "after Close"); err == nil {
		t.Fatal("a connection survived Close")
	}
	if st := p.routes.Apply([]gateway.TCPRoute{{ID: "rt_1", Port: port}}); st != nil {
		t.Fatal("Apply after Close")
	}
	if _, err := net.Dial("tcp", net.JoinHostPort("127.0.0.1", strconv.Itoa(int(port)))); err == nil {
		t.Fatal("Apply after Close listens")
	}
}

// TestTCPRoutes_Drain: a draining gateway accepts no new public connection and binds no port, and
// its open connections carry on, counted, until Close; the open stream is counted by Sessions.
func TestTCPRoutes_Drain(t *testing.T) {
	p := newPlane(t, service(t, echoService), "rt_1")
	port := freePort(t)
	p.routes.Apply([]gateway.TCPRoute{{ID: "rt_1", Port: port}})
	c := dialPort(t, port)
	if err := ping(c, "open"); err != nil {
		t.Fatal(err)
	}
	if n := p.sessions.Streams(); n != 1 {
		t.Fatalf("%d streams in flight, want 1", n)
	}
	p.routes.Drain()
	if conn, err := net.Dial("tcp", net.JoinHostPort("127.0.0.1", strconv.Itoa(int(port)))); err == nil {
		_ = conn.Close()
		t.Fatal("a draining gateway accepts")
	}
	if st := p.routes.Apply([]gateway.TCPRoute{{ID: "rt_2", Port: freePort(t)}}); st != nil || p.routes.Conns() != 1 {
		t.Fatalf("Apply while draining: %v, %d connections", st, p.routes.Conns())
	}
	if err := ping(c, "while draining"); err != nil {
		t.Fatal(err)
	}
	_ = c.CloseWrite()
	_, _ = io.ReadAll(c)
	_ = c.Close()
	eventually(t, "the closed connection is still counted", func() bool { return p.routes.Conns() == 0 && p.sessions.Streams() == 0 })
}
