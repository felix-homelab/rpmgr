// SPDX-License-Identifier: Apache-2.0

package connector

import (
	"context"
	"net"
	"testing"
	"time"
)

// SetRetireAfter shortens how long a retired session keeps its streams, for one test that must
// not run in parallel with others.
func SetRetireAfter(t testing.TB, d time.Duration) {
	old := retireAfter
	retireAfter = d
	t.Cleanup(func() { retireAfter = old })
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
