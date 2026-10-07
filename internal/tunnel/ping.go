// SPDX-License-Identifier: Apache-2.0

package tunnel

import (
	"context"
	"time"

	tunnelv1 "github.com/felix-homelab/rpmgr/gen/rpmgr/tunnel/v1"
)

// The session Ping (docs/03-connections.md, "Timeouts, keepalive and backoff").
const (
	PingInterval = 15 * time.Second
	// pingPadding makes every Ping packet larger than 42 bytes: quic-go never answers a smaller
	// packet with a stateless reset [F quic-go v0.63.0 transport.go:633-637], so a restarted
	// gateway would otherwise be noticed only at the idle timeout.
	pingPadding = 64
)

// SendPings sends a padded Ping through send every interval until ctx ends or a send fails, and
// returns that error. The Pongs measure the round-trip time; a Ping never takes a session out of
// service by itself.
func SendPings(ctx context.Context, send func(*tunnelv1.SessionMessage) error, interval time.Duration) error {
	t := time.NewTicker(interval)
	defer t.Stop()
	for seq := uint64(1); ; seq++ {
		select {
		case <-ctx.Done():
			return nil
		case <-t.C:
			if err := send(&tunnelv1.SessionMessage{Msg: &tunnelv1.SessionMessage_Ping{Ping: &tunnelv1.Ping{
				Seq: seq, Padding: make([]byte, pingPadding)}}}); err != nil {
				return err
			}
		}
	}
}
