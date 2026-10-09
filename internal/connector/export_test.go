// SPDX-License-Identifier: Apache-2.0

package connector

import (
	"context"
	"net"
	"net/netip"
	"testing"
	"time"
)

// SetTransportTimers shortens the happy-eyeballs timers for one test that must not run in
// parallel with others.
func SetTransportTimers(t testing.TB, race, reprobe, demote time.Duration) {
	oldRace, oldReprobe, oldDemote := raceDelay, reprobeEvery, demoteFor
	raceDelay, reprobeEvery, demoteFor = race, reprobe, demote
	t.Cleanup(func() { raceDelay, reprobeEvery, demoteFor = oldRace, oldReprobe, oldDemote })
}

// NewProxyDialer is ProxyDialer with the direct dial function of a test.
func NewProxyDialer(getenv func(string) string, dial func(ctx context.Context, network, addr string) (net.Conn, error)) (
	func(ctx context.Context, addr string) (net.Conn, error), error) {
	return newProxyDialer(getenv, dial)
}

// SetRouteDrain shortens how long a removed route takes streams, for one test that must not run
// in parallel with others.
func SetRouteDrain(t testing.TB, d time.Duration) {
	old := routeDrain
	routeDrain = d
	t.Cleanup(func() { routeDrain = old })
}

// Order is order.
var Order = order

// CodeOf is codeOf.
var CodeOf = codeOf

// Chooser exposes the transport cache to tests.
type Chooser struct{ c *chooser }

// NewChooser returns a chooser on the clock now.
func NewChooser(now func() time.Time) Chooser { return Chooser{newChooser(now)} }

func (c Chooser) Plan(gw string, local netip.Addr) string    { return c.c.plan(gw, local) }
func (c Chooser) Won(gw string, local netip.Addr, tr string) { c.c.won(gw, local, tr) }
func (c Chooser) Forget(gw string, local netip.Addr)         { c.c.forget(gw, local) }
func (c Chooser) Blackholed(gw string)                       { c.c.blackholed(gw) }
func (c Chooser) MayProbe(gw string) bool                    { return c.c.mayProbe(gw) }

// IsBlackhole is isBlackhole.
var IsBlackhole = isBlackhole

// SetPingInterval shortens the session Ping's interval, for one test that must not run in
// parallel with others.
func SetPingInterval(t testing.TB, d time.Duration) {
	old := pingEvery
	pingEvery = d
	t.Cleanup(func() { pingEvery = old })
}
