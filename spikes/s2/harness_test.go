// SPDX-License-Identifier: Apache-2.0

package s2

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/binary"
	"fmt"
	"io"
	"math/rand/v2"
	"net"
	"os"
	"testing"
	"time"
)

var (
	testOrg   = "org_1"
	gatewayID = Identity{Role: "gateway", Org: testOrg, ID: "gw_1"}
	connID    = Identity{Role: "connector", Org: testOrg, ID: "con_1"}
)

// impls are the implementations every criterion runs against. With -tags http2legacy the
// "xnet" entry is x/net's own HTTP/2 code instead of the wrapper around net/http.
func impls() []Impl { return []Impl{Stdlib{}, XNet{}} }

// pair is one data session: a gateway listener, a connector that dialled it, and both sides.
type pair struct {
	gw    *GatewaySession
	con   *ConnectorSession
	proxy *Proxy
	serve chan error // result of the connector's Serve
	ln    net.Listener
}

type pairOpts struct {
	params  Params
	mode    Mode
	oneWay  time.Duration // one-way delay through a proxy; 0 = direct
	onOpen  func(Control) OpenDecision
	onStrm  func(*Stream)
	gateway Identity // identity the connector expects; default gatewayID
}

func newPair(t testing.TB, impl Impl, o pairOpts) *pair {
	t.Helper()
	pki, err := NewTestPKI("rpmgr-s2test")
	if err != nil {
		t.Fatal(err)
	}
	gwCert, err := pki.Issue(gatewayID)
	if err != nil {
		t.Fatal(err)
	}
	conCert, err := pki.Issue(connID)
	if err != nil {
		t.Fatal(err)
	}
	ln, err := tls.Listen("tcp", "127.0.0.1:0", pki.GatewayTLS(gwCert))
	if err != nil {
		t.Fatal(err)
	}
	addr := ln.Addr().String()
	var proxy *Proxy
	if o.oneWay > 0 {
		proxy, err = NewProxy(addr, o.oneWay)
		if err != nil {
			t.Fatal(err)
		}
		addr = proxy.Addr()
	}
	expect := o.gateway
	if expect.ID == "" {
		expect = gatewayID
	}

	p := &pair{proxy: proxy, serve: make(chan error, 1), ln: ln}
	p.con = NewConnectorSession(o.mode, o.onStrm)
	accepted := make(chan net.Conn, 1)
	go func() {
		c, err := ln.Accept()
		if err != nil {
			close(accepted)
			return
		}
		c.(*tls.Conn).Handshake() // errors surface below
		accepted <- c
	}()

	// Connector: dial, check ALPN, serve HTTP/2 on the connection it dialled.
	conn, err := tls.Dial("tcp", addr, pki.ConnectorTLS(conCert, expect))
	if err != nil {
		ln.Close()
		t.Fatalf("connector dial: %v", err)
	}
	if conn.ConnectionState().NegotiatedProtocol != ALPN {
		t.Fatalf("ALPN %q", conn.ConnectionState().NegotiatedProtocol)
	}
	go func() { p.serve <- impl.Serve(conn, p.con, o.params) }()

	// Gateway: accept, handshake, start the HTTP/2 client and the control stream.
	gc, ok := <-accepted
	if !ok {
		t.Fatal("gateway accept failed")
	}
	tc := gc.(*tls.Conn)
	if err := tc.Handshake(); err != nil {
		t.Fatalf("gateway handshake: %v", err)
	}
	p.gw, err = NewGatewaySession(tc, impl, o.params, o.mode, o.onOpen)
	if err != nil {
		t.Fatalf("gateway session: %v", err)
	}
	t.Cleanup(func() {
		p.gw.Close()
		conn.Close()
		ln.Close()
		if proxy != nil {
			proxy.Close()
		}
	})
	return p
}

// pattern is a deterministic byte stream: both ends can regenerate and hash it.
type pattern struct {
	r *rand.ChaCha8
}

func newPattern(seed uint64) *pattern {
	var s [32]byte
	binary.LittleEndian.PutUint64(s[:], seed)
	return &pattern{r: rand.NewChaCha8(s)}
}

func (p *pattern) Read(b []byte) (int, error) { return p.r.Read(b) }

func patternHash(seed uint64, n int64) [32]byte {
	h := sha256.New()
	io.CopyN(h, newPattern(seed), n)
	var out [32]byte
	copy(out[:], h.Sum(nil))
	return out
}

// sizeEnv returns the transfer size: 1 GiB normally, smaller under -short or the race detector.
func sizeEnv() int64 {
	if raceEnabled || testing.Short() {
		return 64 << 20
	}
	if v := os.Getenv("S2_DUPLEX_BYTES"); v != "" {
		var n int64
		fmt.Sscan(v, &n)
		return n
	}
	return 1 << 30
}

func waitErr(t testing.TB, ch <-chan error, d time.Duration, what string) error {
	t.Helper()
	select {
	case err := <-ch:
		return err
	case <-time.After(d):
		t.Fatalf("%s: no result within %v", what, d)
		return nil
	}
}

func ctxTimeout(t testing.TB, d time.Duration) context.Context {
	ctx, cancel := context.WithTimeout(context.Background(), d)
	t.Cleanup(cancel)
	return ctx
}
