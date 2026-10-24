// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"net/netip"
	"sync"
	"time"
)

// The client table of a rate_limit rule on a gateway (docs/03-connections.md, "Timeouts,
// keepalive and backoff"): at most clientKeys client addresses. When it is full, the addresses
// whose bucket is full again are dropped, at most once a second; if none is, new addresses are
// refused, so a flood of addresses never makes the gateway forget the clients it limits. Every
// minute the addresses idle long enough to be full again are dropped and the map is made anew, as
// a Go map never gives back the memory of deleted keys. clientKeys is a variable for tests.
var clientKeys = 65_536

const (
	clientFullSweep = time.Second
	clientIdleSweep = time.Minute
)

// clientTable counts the clients of one rate_limit rule, for every route whose policies carry it.
type clientTable struct {
	perSecond, burst float64
	now              func() time.Time

	mu        sync.Mutex
	clients   map[netip.Prefix]clientBucket
	lastSweep time.Time
}

// clientBucket is a client's tokens when it last came, in Unix nanoseconds: 16 bytes.
type clientBucket struct {
	tokens float64
	last   int64
}

// refilled is the bucket's tokens at now.
func (t *clientTable) refilled(b clientBucket, now int64) float64 {
	return min(t.burst, b.tokens+float64(now-b.last)/float64(time.Second)*t.perSecond)
}

func newClientTable(c ClientRate, now func() time.Time) *clientTable {
	if now == nil {
		now = time.Now
	}
	return &clientTable{perSecond: float64(max(c.PerSecond, 1)), burst: float64(max(c.Burst, 1)), now: now,
		clients: map[netip.Prefix]clientBucket{}, lastSweep: now()}
}

// clientKey is a client's key: its IPv4 address, or its IPv6 /64, so that a host cannot escape by
// using many addresses of its own prefix. An address that is not IP, which no listener gives, is
// the zero Prefix.
func clientKey(ip netip.Addr) netip.Prefix {
	ip = ip.Unmap().WithZone("")
	if !ip.IsValid() {
		return netip.Prefix{}
	}
	if ip.Is6() {
		p, _ := ip.Prefix(64)
		return p
	}
	return netip.PrefixFrom(ip, 32)
}

// has reports whether a client's bucket has a token, or room for a new client, without taking
// it; when not, wait is how long until it may.
func (t *clientTable) has(key netip.Prefix) (ok bool, wait time.Duration) {
	return t.use(key, false)
}

// take takes one token of a client's bucket; when there is none, wait is how long until there is.
func (t *clientTable) take(key netip.Prefix) (ok bool, wait time.Duration) {
	return t.use(key, true)
}

func (t *clientTable) use(key netip.Prefix, take bool) (ok bool, wait time.Duration) {
	t.mu.Lock()
	defer t.mu.Unlock()
	at := t.now()
	now := at.UnixNano()
	if since := at.Sub(t.lastSweep); since >= clientIdleSweep || len(t.clients) >= clientKeys && since >= clientFullSweep {
		t.sweep(at)
	}
	b, known := t.clients[key]
	if !known {
		if len(t.clients) >= clientKeys {
			return false, clientFullSweep
		}
		b = clientBucket{tokens: t.burst, last: now}
	}
	b.tokens = t.refilled(b, now)
	b.last = now
	if b.tokens < 1 {
		if known {
			t.clients[key] = b
		}
		return false, time.Duration((1 - b.tokens) / t.perSecond * float64(time.Second))
	}
	if take {
		b.tokens--
		t.clients[key] = b
	}
	return true, 0
}

// sweep makes the map anew without the clients whose bucket is full again: forgetting them
// changes nothing.
func (t *clientTable) sweep(now time.Time) {
	t.lastSweep = now
	kept := make(map[netip.Prefix]clientBucket, len(t.clients)/2)
	for k, b := range t.clients {
		if t.refilled(b, now.UnixNano()) < t.burst {
			kept[k] = b
		}
	}
	t.clients = kept
}

// size is the number of clients the table holds.
func (t *clientTable) size() int {
	t.mu.Lock()
	defer t.mu.Unlock()
	return len(t.clients)
}
