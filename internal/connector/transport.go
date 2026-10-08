// SPDX-License-Identifier: Apache-2.0

package connector

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"sync"
	"time"

	"github.com/quic-go/quic-go"
)

// The happy-eyeballs timing (docs/03-connections.md, "Transports and fallback", "Timeouts,
// keepalive and backoff"); variables for tests.
var (
	// raceDelay is the head start of QUIC in a race.
	raceDelay = 300 * time.Millisecond
	// winnerTTL is how long a race's winner is used for a gateway and local source address.
	winnerTTL = 24 * time.Hour
	// reprobeEvery is how often QUIC is tried again while TCP is in use.
	reprobeEvery = 10 * time.Minute
	// demoteFor is how long QUIC is not tried at all after a session timed out mid-way.
	demoteFor = time.Hour
)

// chooser decides the transport of a gateway's auto link: the winner of the last race from the
// same local source address within 24 h, h2 while QUIC is demoted, and otherwise a new race.
type chooser struct {
	now func() time.Time

	mu      sync.Mutex
	winners map[winnerKey]winner
	demoted map[string]time.Time // gateway ID → until
}

type winnerKey struct {
	gateway string
	local   netip.Addr
}

type winner struct {
	transport string
	at        time.Time
}

func newChooser(now func() time.Time) *chooser {
	return &chooser{now: now, winners: map[winnerKey]winner{}, demoted: map[string]time.Time{}}
}

// plan returns the transport to dial for the gateway from local, or "" to race.
func (c *chooser) plan(gateway string, local netip.Addr) string {
	c.mu.Lock()
	defer c.mu.Unlock()
	now := c.now()
	if now.Before(c.demoted[gateway]) {
		return TransportH2
	}
	if w, ok := c.winners[winnerKey{gateway, local}]; ok && now.Sub(w.at) < winnerTTL {
		return w.transport
	}
	return ""
}

// won records the winner of a race, or a successful re-probe.
func (c *chooser) won(gateway string, local netip.Addr, transport string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.winners[winnerKey{gateway, local}] = winner{transport: transport, at: c.now()}
}

// forget drops the winner after its transport failed to connect, so that the next attempt races.
func (c *chooser) forget(gateway string, local netip.Addr) {
	c.mu.Lock()
	defer c.mu.Unlock()
	delete(c.winners, winnerKey{gateway, local})
}

// blackholed demotes QUIC to the gateway for demoteFor, after a QUIC session timed out.
func (c *chooser) blackholed(gateway string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.demoted[gateway] = c.now().Add(demoteFor)
	for k := range c.winners {
		if k.gateway == gateway {
			delete(c.winners, k)
		}
	}
}

// mayProbe reports whether QUIC may be re-probed: not while it is demoted.
func (c *chooser) mayProbe(gateway string) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return !c.now().Before(c.demoted[gateway])
}

// isBlackhole reports whether a QUIC session ended because the path stopped carrying its packets:
// an idle timeout, as opposed to the gateway closing it or a stateless reset.
func isBlackhole(err error) bool {
	var idle *quic.IdleTimeoutError
	return errors.As(err, &idle)
}

// localAddr is the address the kernel picks to reach the endpoint: connecting a UDP socket sends
// nothing.
func localAddr(ctx context.Context, ep string) (netip.Addr, error) {
	host, port, err := net.SplitHostPort(ep)
	if err != nil {
		return netip.Addr{}, err
	}
	addrs, err := net.DefaultResolver.LookupNetIP(ctx, "ip", host)
	if err != nil || len(addrs) == 0 {
		return netip.Addr{}, errors.Join(errors.New("connector: cannot resolve "+host), err)
	}
	c, err := net.Dial("udp", net.JoinHostPort(addrs[0].Unmap().String(), port))
	if err != nil {
		return netip.Addr{}, err
	}
	defer func() { _ = c.Close() }()
	return c.LocalAddr().(*net.UDPAddr).AddrPort().Addr().Unmap(), nil
}
