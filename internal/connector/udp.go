// SPDX-License-Identifier: Apache-2.0

package connector

import (
	"context"
	"errors"
	"net"
	"sync"
	"syscall"
	"time"

	tunnelv1 "github.com/felix-homelab/rpmgr/gen/rpmgr/tunnel/v1"
	"github.com/felix-homelab/rpmgr/internal/policy"
	"github.com/felix-homelab/rpmgr/internal/tunnel"
)

// udpFlowQueue is how many payloads a flow queues towards its target before it drops.
const udpFlowQueue = 64

// datagramsOf returns the datagram multiplexer of the QUIC session a stream from the gateway runs
// on, or nil on the TCP transport.
func datagramsOf(st tunnel.Stream) *tunnel.Datagrams {
	if c, ok := st.(*countedStream); ok {
		if q, ok := c.s.s.(*tunnel.QUICSession); ok {
			return q.Datagrams()
		}
	}
	return nil
}

// dialUDP connects a UDP socket of its own to a target of a udp route that the local policy
// allows; the socket is the flow's, so the target's replies reach the right client.
func (t *Targets) dialUDP(ctx context.Context, r Route, open *tunnelv1.StreamOpen) (tunnelv1.ResultCode, net.Conn, string) {
	timeout := dialUpstream
	if ms := open.GetOpenTimeoutMs(); ms > 0 && time.Duration(ms)*time.Millisecond < timeout {
		timeout = time.Duration(ms) * time.Millisecond
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	d := &net.Dialer{Control: policy.Control(t.o.Policy)}
	code := tunnelv1.ResultCode_RESULT_CODE_UPSTREAM_REFUSED
	for _, tg := range order(r.Targets) {
		if tg.UnixPath != "" {
			continue
		}
		conn, err := t.o.Metrics.dial(ctx, d, r.ID, "udp", tg.String(), isBlocked)
		if err != nil {
			var b *policy.BlockedError
			if errors.As(err, &b) {
				t.blocked(r.ID, b.Target)
				continue
			}
			code = codeOf(err)
			if ctx.Err() != nil {
				break
			}
			continue
		}
		return tunnelv1.ResultCode_RESULT_CODE_NO_ERROR, conn, tg.ID
	}
	return code, nil, ""
}

// relayUDP carries one flow between its stream and its target socket until either ends: the
// gateway's payloads come as datagrams or frames, and the target's go back as datagrams when they
// fit, as frames otherwise. The gateway decides when an idle flow ends.
func (t *Targets) relayUDP(ctx context.Context, route string, st tunnel.Stream, conn net.Conn) {
	done := make(chan struct{})
	var once sync.Once
	end := func() { once.Do(func() { close(done) }) }
	stop := context.AfterFunc(ctx, end)
	defer stop()

	dg := datagramsOf(st)
	id, ok := tunnel.StreamID(st)
	if !ok {
		dg = nil
	}
	queue := make(chan []byte, udpFlowQueue)
	if dg != nil {
		defer dg.Register(id, func(b []byte) {
			select {
			case queue <- b:
			default:
				t.o.UDPMetrics.Dropped.WithLabelValues(route, "queue_full").Inc()
			}
		})()
	}
	var wg sync.WaitGroup
	wg.Go(func() { // frames from the gateway
		defer end()
		for {
			b, err := tunnel.ReadFrame(st)
			if err != nil {
				return
			}
			select {
			case queue <- b:
			case <-done:
				return
			}
		}
	})
	wg.Go(func() { // to the target
		defer end()
		for {
			select {
			case <-done:
				return
			case b := <-queue:
				if _, err := conn.Write(b); errors.Is(err, net.ErrClosed) {
					return
				}
			}
		}
	})
	wg.Go(func() { // the target's replies
		defer end()
		buf := make([]byte, tunnel.MaxUDPPayload)
		for {
			n, err := conn.Read(buf)
			if errors.Is(err, syscall.ECONNREFUSED) {
				continue // an ICMP port unreachable for an earlier payload; the flow goes on
			}
			if err != nil {
				return
			}
			if dg != nil && dg.Fits(id, n) {
				if !dg.Send(id, buf[:n]) {
					t.o.UDPMetrics.Dropped.WithLabelValues(route, "queue_full").Inc()
				}
				continue
			}
			if dg != nil {
				t.o.UDPMetrics.Oversize.WithLabelValues(route).Inc()
			}
			if tunnel.WriteFrame(st, buf[:n]) != nil {
				return
			}
		}
	})
	<-done
	_ = conn.Close()
	_ = st.Close()
	wg.Wait()
}
