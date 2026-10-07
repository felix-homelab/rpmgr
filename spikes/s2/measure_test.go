// SPDX-License-Identifier: Apache-2.0

package s2

import (
	"bytes"
	"context"
	"io"
	"os"
	"sort"
	"testing"
	"time"
)

func measureEnabled(t *testing.T) {
	if os.Getenv("S2_MEASURE") != "1" {
		t.Skip("set S2_MEASURE=1 to run the measurements")
	}
}

func median(ds []time.Duration) time.Duration {
	sort.Slice(ds, func(i, j int) bool { return ds[i] < ds[j] })
	return ds[len(ds)/2]
}

// Criterion 5: what OpenRequest costs, and how much a first chunk carried in it hides. The far
// end of the relay is an echo service on the gateway itself, so every extra round trip between
// connector and gateway shows up directly.
func TestMeasureOpenLatency(t *testing.T) {
	measureEnabled(t)
	const runs = 15
	chunk := bytes.Repeat([]byte("c"), 1024)
	for _, impl := range impls() {
		for _, rtt := range []time.Duration{0, 20 * time.Millisecond, 80 * time.Millisecond} {
			p := newPair(t, impl, pairOpts{params: RPMGRParams(), mode: ModeFramed, oneWay: rtt / 2,
				onStrm: func(st *Stream) { st.WriteResult(ResultOK); echoServe(st) },
				onOpen: func(c Control) OpenDecision {
					return OpenDecision{Accept: true, Serve: func(st *Stream) {
						if len(c.FirstChunk) > 0 {
							st.Write(c.FirstChunk) // answer the first flight at once
						}
						echoServe(st)
					}}
				}})
			var ping, gwOpen, reqNoChunk, reqChunk []time.Duration
			for i := 0; i < runs; i++ {
				d, err := p.con.Ping(ctxTimeout(t, 5*time.Second))
				if err != nil {
					t.Fatal(err)
				}
				ping = append(ping, d)

				// Gateway-opened stream (a public TCP connection): StreamOpen and the client's
				// first bytes go out together; the answer comes back after one round trip.
				start := time.Now()
				st, err := p.gw.OpenStream(context.Background(), StreamOpen{Kind: KindTCP, RouteID: "echo"})
				if err != nil {
					t.Fatal(err)
				}
				st.Write(chunk)
				got := make([]byte, len(chunk))
				if _, err := io.ReadFull(st, got); err != nil {
					t.Fatal(err)
				}
				gwOpen = append(gwOpen, time.Since(start))
				st.Close()

				// Connector-initiated stream without a first chunk: OpenRequest, wait for the
				// gateway-opened stream, then send.
				start = time.Now()
				cs, err := p.con.RequestStream(ctxTimeout(t, 15*time.Second), KindRelayOut, nil)
				if err != nil {
					t.Fatal(err)
				}
				cs.Write(chunk)
				if _, err := io.ReadFull(cs, got); err != nil {
					t.Fatal(err)
				}
				reqNoChunk = append(reqNoChunk, time.Since(start))
				cs.CloseWrite()
				io.Copy(io.Discard, cs)

				// With the first chunk inside the OpenRequest.
				start = time.Now()
				cs, err = p.con.RequestStream(ctxTimeout(t, 15*time.Second), KindRelayOut, chunk)
				if err != nil {
					t.Fatal(err)
				}
				if _, err := io.ReadFull(cs, got); err != nil {
					t.Fatal(err)
				}
				reqChunk = append(reqChunk, time.Since(start))
				cs.CloseWrite()
				io.Copy(io.Discard, cs)
			}
			t.Logf("RESULT impl=%s rtt=%v ping=%v gateway_open_first_answer=%v open_request_no_chunk=%v open_request_first_chunk=%v",
				impl.Name(), rtt, median(ping).Round(100*time.Microsecond), median(gwOpen).Round(100*time.Microsecond),
				median(reqNoChunk).Round(100*time.Microsecond), median(reqChunk).Round(100*time.Microsecond))
			p.gw.Close()
		}
	}
}

// Single-stream throughput at 100 ms RTT with default and tuned windows, per direction. 03
// computes ≈ 84 Mbit/s for the client-to-service direction with x/net's 1 MiB server default.
func TestMeasureThroughputAt100ms(t *testing.T) {
	measureEnabled(t)
	for _, impl := range impls() {
		for _, c := range []struct {
			name   string
			params Params
			bytes  int64
		}{{"defaults", Params{}, 32 << 20}, {"rpmgr", RPMGRParams(), 256 << 20}} {
			p := newPair(t, impl, pairOpts{params: c.params, mode: ModeRaw, oneWay: 50 * time.Millisecond,
				onStrm: func(st *Stream) {
					st.WriteResult(ResultOK)
					if st.Open.RouteID == "down" {
						io.CopyN(st, newPattern(11), c.bytes)
						io.Copy(io.Discard, st)
						st.CloseWrite()
						return
					}
					io.Copy(io.Discard, st) // "up": sink
					st.CloseWrite()
				}})
			// up: gateway → connector (public client to service), limited by the connector's
			// (HTTP/2 server's) receive window.
			st, err := p.gw.OpenStream(context.Background(), StreamOpen{Kind: KindTCP, RouteID: "up"})
			if err != nil {
				t.Fatal(err)
			}
			st.Result()
			start := time.Now()
			io.CopyN(st, newPattern(10), c.bytes)
			st.CloseWrite()
			io.Copy(io.Discard, st) // the connector's FIN arrives after it read everything
			up := time.Since(start)

			// down: connector → gateway, limited by the gateway's (HTTP/2 client's) window.
			st, err = p.gw.OpenStream(context.Background(), StreamOpen{Kind: KindTCP, RouteID: "down"})
			if err != nil {
				t.Fatal(err)
			}
			st.Result()
			start = time.Now()
			n, _ := io.CopyN(io.Discard, st, c.bytes)
			down := time.Since(start)
			st.CloseWrite()
			io.Copy(io.Discard, st)
			mbit := func(b int64, d time.Duration) float64 { return float64(b) * 8 / d.Seconds() / 1e6 }
			t.Logf("RESULT impl=%s windows=%s rtt=100ms up=%.0f Mbit/s down=%.0f Mbit/s (%d MiB each)",
				impl.Name(), c.name, mbit(c.bytes, up), mbit(n, down), c.bytes>>20)
			p.gw.Close()
		}
	}
}
