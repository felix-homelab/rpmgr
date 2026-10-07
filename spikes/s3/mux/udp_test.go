// SPDX-License-Identifier: Apache-2.0

package mux

import (
	"bufio"
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"reflect"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
)

func startUDP(t *testing.T, certs *Certs, tunnelBudget, h3Budget int64) (*UDPMux, string) {
	t.Helper()
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	m, err := NewUDPMux(pc, UDPConfig{
		Certs:           certs,
		HTTPHostnames:   map[string]tls.Certificate{TestHTTPHost: certs.HTTP, TestHTTPHost2: certs.HTTP2},
		TunnelBudget:    tunnelBudget,
		H3Budget:        h3Budget,
		PendingBudget:   0,
		StreamWindowMax: 16 << 20,
		ConnWindowMax:   256 << 20,
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = m.Close() })
	return m, pc.LocalAddr().String()
}

func h3Client(certs *Certs, addr string) (*http.Client, *http3.Transport) {
	tr := &http3.Transport{
		TLSClientConfig: &tls.Config{RootCAs: certs.Public.Pool()},
		Dial: func(ctx context.Context, _ string, tlsCfg *tls.Config, cfg *quic.Config) (*quic.Conn, error) {
			return quic.DialAddr(ctx, addr, tlsCfg, cfg)
		},
	}
	return &http.Client{Transport: tr, Timeout: 30 * time.Second}, tr
}

func dialTunnelQUIC(ctx context.Context, certs *Certs, addr, sni string, alpn []string, cert *tls.Certificate) (*quic.Conn, error) {
	cfg := tunnelClient(certs, sni, alpn, cert)
	return quic.DialAddr(ctx, addr, cfg, &quic.Config{MaxStreamReceiveWindow: 16 << 20, MaxConnectionReceiveWindow: 256 << 20})
}

// echoStream sends n random bytes on a new stream and checks the echo.
func echoStream(ctx context.Context, c *quic.Conn, n int) error {
	s, err := c.OpenStreamSync(ctx)
	if err != nil {
		return err
	}
	data := make([]byte, n)
	_, _ = rand.Read(data)
	go func() {
		_, _ = s.Write(data)
		_ = s.Close()
	}()
	br := bufio.NewReader(s)
	line, err := br.ReadString('\n')
	if err != nil {
		return err
	}
	if !strings.HasPrefix(line, "tunnel-quic peer=spiffe://") {
		return fmt.Errorf("header %q", line)
	}
	got, err := io.ReadAll(br)
	if err != nil {
		return err
	}
	if sha256.Sum256(got) != sha256.Sum256(data) {
		return fmt.Errorf("echo mismatch: %d of %d bytes", len(got), n)
	}
	return nil
}

func TestUDP_OneListenerServesH3AndTunnelConcurrently(t *testing.T) {
	certs, _ := NewCerts()
	m, direct := startUDP(t, certs, 1<<30, 512<<20)
	addr := delayUDP(t, direct, 10*time.Millisecond) // 20 ms RTT, so windows auto-tune
	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
	defer cancel()

	var wg sync.WaitGroup
	errs := make(chan error, 100)
	// Tunnel: two sessions, 8 streams each, 4 MiB echoed per stream.
	for range 2 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			c, err := dialTunnelQUIC(ctx, certs, addr, TunnelName(), []string{ALPNTunnelQUIC}, &certs.Connector)
			if err != nil {
				errs <- fmt.Errorf("tunnel dial: %w", err)
				return
			}
			defer c.CloseWithError(0, "")
			if p := c.ConnectionState().TLS.NegotiatedProtocol; p != ALPNTunnelQUIC {
				errs <- fmt.Errorf("tunnel ALPN %q", p)
			}
			var swg sync.WaitGroup
			for range 8 {
				swg.Add(1)
				go func() {
					defer swg.Done()
					if err := echoStream(ctx, c, 4<<20); err != nil {
						errs <- fmt.Errorf("tunnel stream: %w", err)
					}
				}()
			}
			swg.Wait()
		}()
	}
	// HTTP/3 at the same time: 40 GETs on two hostnames and 4 uploads of 8 MiB.
	client, tr := h3Client(certs, addr)
	for i := range 44 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			host := TestHTTPHost
			if i%2 == 1 {
				host = TestHTTPHost2
			}
			var resp *http.Response
			var err error
			if i >= 40 {
				resp, err = client.Post("https://"+host+"/", "application/octet-stream", bytes.NewReader(make([]byte, 8<<20)))
			} else {
				resp, err = client.Get("https://" + host + "/")
			}
			if err != nil {
				errs <- fmt.Errorf("h3: %w", err)
				return
			}
			b, _ := io.ReadAll(resp.Body)
			resp.Body.Close()
			if !strings.Contains(string(b), "h3 host="+host) || resp.Proto != "HTTP/3.0" {
				errs <- fmt.Errorf("h3 body %q proto %s", b, resp.Proto)
			}
		}()
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Error(err)
	}
	st := m.Stats()
	t.Logf("budgets after mixed load: %+v", st)
	if st[ALPNTunnelQUIC].Granted == 0 || st[http3.NextProtoH3].Granted == 0 || st["pending"].Granted != 0 {
		t.Fatalf("window increases were not attributed per ALPN: %+v", st)
	}
	// Closing the connections returns their windows to the budgets.
	_ = tr.Close()
	deadline := time.Now().Add(40 * time.Second)
	for time.Now().Before(deadline) {
		st = m.Stats()
		if st[ALPNTunnelQUIC].Used == 0 && st[http3.NextProtoH3].Used == 0 {
			return
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatalf("budgets not released after close: %+v", st)
}

func TestUDP_H3BudgetCannotTakeTunnelShare(t *testing.T) {
	certs, _ := NewCerts()
	// h3 may grow its connection windows by 256 KiB in total, less than one auto-tuning step
	// (768 KiB on loopback), so every h3 increase is refused; tunnels have 1 GiB.
	m, direct := startUDP(t, certs, 1<<30, 256<<10)
	// A 20 ms RTT path makes quic-go's auto-tuning grow the connection windows.
	addr := delayUDP(t, direct, 10*time.Millisecond)
	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
	defer cancel()
	client, tr := h3Client(certs, addr)
	defer tr.Close()
	var wg sync.WaitGroup
	for range 4 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			resp, err := client.Post("https://"+TestHTTPHost+"/", "application/octet-stream", bytes.NewReader(make([]byte, 16<<20)))
			if err != nil {
				t.Error(err)
				return
			}
			_, _ = io.Copy(io.Discard, resp.Body)
			resp.Body.Close()
		}()
	}
	c, err := dialTunnelQUIC(ctx, certs, addr, TunnelName(), []string{ALPNTunnelQUIC}, &certs.Connector)
	if err != nil {
		t.Fatal(err)
	}
	defer c.CloseWithError(0, "")
	if err := echoStream(ctx, c, 32<<20); err != nil {
		t.Fatal(err)
	}
	wg.Wait()
	st := m.Stats()
	t.Logf("budgets: %+v", st)
	if st[http3.NextProtoH3].Denied == 0 {
		t.Fatal("expected the h3 budget to refuse window increases")
	}
	if st[ALPNTunnelQUIC].Denied != 0 || st[ALPNTunnelQUIC].Granted == 0 {
		t.Fatalf("tunnel budget affected: %+v", st[ALPNTunnelQUIC])
	}
	if st[http3.NextProtoH3].Used > st[http3.NextProtoH3].Limit {
		t.Fatalf("h3 budget exceeded: %+v", st[http3.NextProtoH3])
	}
}

// delayUDP relays datagrams between clients and target, delaying each by d in each direction.
// Each direction is a FIFO delay line, so packets are neither reordered nor dropped by the relay.
func delayUDP(t *testing.T, target string, d time.Duration) string {
	t.Helper()
	front, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	_ = front.(*net.UDPConn).SetReadBuffer(16 << 20)
	_ = front.(*net.UDPConn).SetWriteBuffer(16 << 20)
	t.Cleanup(func() { _ = front.Close() })
	taddr, _ := net.ResolveUDPAddr("udp", target)
	type pkt struct {
		due  time.Time
		data []byte
		send func([]byte)
	}
	line := func() chan<- pkt {
		ch := make(chan pkt, 1<<16)
		go func() {
			for p := range ch {
				time.Sleep(time.Until(p.due))
				p.send(p.data)
			}
		}()
		return ch
	}
	toServer, toClient := line(), line()
	var mu sync.Mutex
	backs := map[string]*net.UDPConn{}
	go func() {
		buf := make([]byte, 65535)
		for {
			n, caddr, err := front.ReadFrom(buf)
			if err != nil {
				return
			}
			mu.Lock()
			back, ok := backs[caddr.String()]
			if !ok {
				if back, err = net.DialUDP("udp", nil, taddr); err != nil {
					mu.Unlock()
					continue
				}
				_ = back.SetReadBuffer(16 << 20)
				_ = back.SetWriteBuffer(16 << 20)
				backs[caddr.String()] = back
				t.Cleanup(func() { _ = back.Close() })
				go func() {
					rb := make([]byte, 65535)
					for {
						m, err := back.Read(rb)
						if err != nil {
							return
						}
						toClient <- pkt{time.Now().Add(d), append([]byte(nil), rb[:m]...),
							func(b []byte) { _, _ = front.WriteTo(b, caddr) }}
					}
				}()
			}
			mu.Unlock()
			toServer <- pkt{time.Now().Add(d), append([]byte(nil), buf[:n]...),
				func(b []byte) { _, _ = back.Write(b) }}
		}
	}()
	return front.LocalAddr().String()
}

func TestUDP_Refusals(t *testing.T) {
	certs, _ := NewCerts()
	_, addr := startUDP(t, certs, 1<<30, 1<<30)
	gw := certs.Gateway
	for _, tc := range []struct {
		name string
		sni  string
		alpn []string
		cert *tls.Certificate
		root *tls.Config
	}{
		{"unknown ALPN only", TunnelName(), []string{"h2"}, &certs.Connector, nil},
		{"tunnel ALPN on a route hostname", TestHTTPHost, []string{ALPNTunnelQUIC}, &certs.Connector, nil},
		{"tunnel without client certificate", TunnelName(), []string{ALPNTunnelQUIC}, nil, nil},
		{"tunnel with a gateway certificate", TunnelName(), []string{ALPNTunnelQUIC}, &gw, nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			c, err := dialTunnelQUIC(ctx, certs, addr, tc.sni, tc.alpn, tc.cert)
			if err == nil {
				// TLS 1.3: a refused client certificate surfaces on first use.
				_, err = c.AcceptStream(ctx)
				_ = c.CloseWithError(0, "")
			}
			if err == nil {
				t.Fatal("connection accepted")
			}
		})
	}
	// h3 to the tunnel name (no public certificate for it) fails as well.
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if _, err := quic.DialAddr(ctx, addr, &tls.Config{ServerName: TunnelName(), RootCAs: certs.Public.Pool(),
		NextProtos: []string{http3.NextProtoH3}}, nil); err == nil {
		t.Fatal("h3 on the tunnel name accepted")
	}
}

func TestUDP_OneListenerPerTransport(t *testing.T) {
	certs, _ := NewCerts()
	m, _ := startUDP(t, certs, 1<<20, 1<<20)
	_, err := m.Transport.Listen(&tls.Config{Certificates: []tls.Certificate{certs.Gateway}, NextProtos: []string{"x"}}, nil)
	if err == nil || !strings.Contains(err.Error(), "listener already set") {
		t.Fatalf("second listener on one transport: %v", err)
	}
}

func TestUDP_FactsAboutQuicGo(t *testing.T) {
	// http3.ConfigureTLSConfig replaces NextProtos with ["h3"], also for configs returned by
	// GetConfigForClient, so rpmgr must not call it on the shared listener's config.
	conf := http3.ConfigureTLSConfig(&tls.Config{NextProtos: []string{http3.NextProtoH3, ALPNTunnelQUIC},
		GetConfigForClient: func(*tls.ClientHelloInfo) (*tls.Config, error) {
			return &tls.Config{NextProtos: []string{ALPNTunnelQUIC}}, nil
		}})
	if !slices.Equal(conf.NextProtos, []string{http3.NextProtoH3}) {
		t.Fatalf("NextProtos %v", conf.NextProtos)
	}
	inner, _ := conf.GetConfigForClient(&tls.ClientHelloInfo{})
	if !slices.Equal(inner.NextProtos, []string{http3.NextProtoH3}) {
		t.Fatalf("inner NextProtos %v", inner.NextProtos)
	}
	// quic.Config.GetConfigForClient sees only the remote address: no ALPN, no SNI.
	var fields []string
	ct := reflect.TypeFor[quic.ClientInfo]()
	for i := range ct.NumField() {
		fields = append(fields, ct.Field(i).Name)
	}
	if !slices.Equal(fields, []string{"RemoteAddr", "AddrVerified"}) {
		t.Fatalf("quic.ClientInfo fields %v", fields)
	}
}
