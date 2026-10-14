// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"errors"
	"io"
	"net"
	"testing"
	"time"
)

// TestUpstreamConns (#517): a connection is kept while the route's settings accept the ones it was
// checked with: the same, unverified ones of its connector, or none for a target the route no
// longer has; other settings end it at once. A dial that ends after a change is checked against
// the settings then, so one checked with settings the change replaced is refused.
func TestUpstreamConns(t *testing.T) {
	unverified := UpstreamTLS{ServerName: "nas.local", Verify: VerifyNothing, Connector: "con_1"}
	verified := UpstreamTLS{ServerName: "nas.local", CAPEM: []byte("pem"), Connector: "con_1"}
	elsewhere := UpstreamTLS{ServerName: "nas.local", Verify: VerifyNothing, Connector: "con_2"}
	u := &upstreamConns{conns: map[*upstreamConn]struct{}{}}
	open := func(checked UpstreamTLS) (net.Conn, net.Conn, error) {
		t.Helper()
		a, b := net.Pipe()
		t.Cleanup(func() { _ = a.Close(); _ = b.Close() })
		c, err := u.track("tg_1", checked, a)
		return c, b, err
	}
	ended := func(peer net.Conn) bool {
		_ = peer.SetReadDeadline(time.Now().Add(100 * time.Millisecond))
		_, err := peer.Read(make([]byte, 1))
		return errors.Is(err, io.EOF) || errors.Is(err, io.ErrClosedPipe)
	}

	u.set(map[string]UpstreamTLS{"tg_1": unverified})
	_, peer, err := open(unverified)
	if err != nil {
		t.Fatal(err)
	}
	u.set(map[string]UpstreamTLS{"tg_1": unverified, "tg_2": verified}) // another target
	if ended(peer) {
		t.Fatal("another target's change ended the connection")
	}
	u.set(map[string]UpstreamTLS{"tg_1": verified})
	if !ended(peer) {
		t.Fatal("stricter settings left the connection open")
	}
	if _, _, err := open(unverified); err == nil {
		t.Fatal("a dial checked with replaced settings was accepted")
	}

	c, peer, err := open(verified)
	if err != nil {
		t.Fatal(err)
	}
	u.set(map[string]UpstreamTLS{"tg_1": unverified})
	if ended(peer) {
		t.Fatal("unverified settings of the same connector ended a verified connection")
	}
	u.set(map[string]UpstreamTLS{"tg_2": verified}) // tg_1 removed: its connections finish
	if ended(peer) {
		t.Fatal("removing the target ended its connection")
	}
	u.set(map[string]UpstreamTLS{"tg_1": elsewhere})
	if !ended(peer) {
		t.Fatal("unverified settings of another connector left the connection open")
	}
	_ = c.Close() // a second close is harmless
	if n := len(u.conns); n != 0 {
		t.Fatalf("%d connections still recorded", n)
	}
}
