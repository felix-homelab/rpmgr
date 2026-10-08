// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"container/list"
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"net/netip"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"golang.org/x/crypto/argon2"

	"github.com/felix-homelab/rpmgr/internal/ratelimit"
)

// The cost bounds of basic auth (docs/04-security.md, "Secrets at rest and in logs").
const (
	basicAuthCacheSize = 10000 // cached verifications
	basicAuthHashes    = 2     // argon2id verifications at once per gateway
	basicAuthBurst     = 20    // verifications per client address at once, refilled at 10 per minute
	basicAuthRefill    = 6 * time.Second
)

// basicAuthTTL is how long a verification is cached; a variable for tests.
var basicAuthTTL = 5 * time.Minute

// BasicAuthRule is a basic_auth rule as the gateway checks it.
type BasicAuthRule struct {
	PolicyID          string
	CredentialVersion string
	// Users maps a user name to its argon2id hash.
	Users map[string]PHC
}

// PHC is a parsed argon2id hash in PHC string format.
type PHC struct {
	time, memory uint32
	threads      uint8
	salt, hash   []byte
}

// argon2id bounds of a hash the gateway verifies, so a snapshot cannot make it spend more than a
// password hash of docs/04-security.md would.
const (
	maxArgonMemory  = 256 * 1024 // KiB
	maxArgonTime    = 10
	maxArgonThreads = 16
)

// ParsePHC parses "$argon2id$v=19$m=<KiB>,t=<n>,p=<n>$<salt>$<hash>", base64 without padding.
func ParsePHC(s string) (PHC, error) {
	parts := strings.Split(s, "$")
	if len(parts) != 6 || parts[0] != "" || parts[1] != "argon2id" || parts[2] != "v=19" {
		return PHC{}, errors.New("not an argon2id hash of version 19 in PHC format")
	}
	var h PHC
	for _, kv := range strings.Split(parts[3], ",") {
		k, v, _ := strings.Cut(kv, "=")
		n, err := strconv.ParseUint(v, 10, 32)
		if err != nil {
			return PHC{}, fmt.Errorf("parameter %q", kv)
		}
		switch k {
		case "m":
			h.memory = uint32(n)
		case "t":
			h.time = uint32(n)
		case "p":
			if n > maxArgonThreads {
				return PHC{}, fmt.Errorf("parameter %q", kv)
			}
			h.threads = uint8(n)
		default:
			return PHC{}, fmt.Errorf("parameter %q", kv)
		}
	}
	var err error
	if h.salt, err = base64.RawStdEncoding.DecodeString(parts[4]); err != nil || len(h.salt) < 8 {
		return PHC{}, errors.New("a salt of fewer than 8 bytes")
	}
	if h.hash, err = base64.RawStdEncoding.DecodeString(parts[5]); err != nil || len(h.hash) < 16 || len(h.hash) > 64 {
		return PHC{}, errors.New("a hash of fewer than 16 or more than 64 bytes")
	}
	if h.memory < 8*uint32(h.threads) || h.memory > maxArgonMemory || h.time < 1 || h.time > maxArgonTime || h.threads < 1 {
		return PHC{}, errors.New("argon2id parameters out of bounds")
	}
	return h, nil
}

// verify reports whether password matches the hash.
func (h PHC) verify(password string) bool {
	got := argon2.IDKey([]byte(password), h.salt, h.time, h.memory, h.threads, uint32(len(h.hash))) //nolint:gosec // G115: at most 64
	return subtle.ConstantTimeCompare(got, h.hash) == 1
}

// dummyPHC is verified for a user name a rule does not know, so the answer takes as long.
var dummyPHC = PHC{time: 3, memory: 64 * 1024, threads: 4, salt: make([]byte, 16), hash: make([]byte, 32)}

// BasicAuth checks basic-auth credentials with argon2id once and caches the result for a while,
// keyed by an HMAC under a gateway-local key over the policy, its credential version, the user
// and the password, so a cached verification serves only the same credentials of the same policy
// version (docs/04-security.md, "Secrets at rest and in logs"). Verifications are rate-limited
// per client address before hashing, and their number at once is capped.
type BasicAuth struct {
	key   [32]byte
	now   func() time.Time
	sem   chan struct{}
	limit *ratelimit.Limiter

	mu      sync.Mutex
	order   *list.List // of *cached, most recent first
	entries map[[32]byte]*list.Element

	hashes atomic.Int64 // verifications done
	busy   atomic.Int64 // verifications running now
	peak   atomic.Int64 // the most at once
}

type cached struct {
	key     [32]byte
	scope   string // policy ID and credential version
	expires time.Time
}

// NewBasicAuth returns an empty cache with a new random key.
func NewBasicAuth(now func() time.Time) *BasicAuth {
	if now == nil {
		now = time.Now
	}
	b := &BasicAuth{now: now, sem: make(chan struct{}, basicAuthHashes), order: list.New(), entries: map[[32]byte]*list.Element{},
		limit: ratelimit.New(basicAuthRefill, basicAuthBurst, now)}
	_, _ = rand.Read(b.key[:])
	return b
}

// ErrRateLimited is returned when a client address has used its verifications for now.
var ErrRateLimited = errors.New("gateway: too many basic-auth verifications from this address")

// Check reports whether user and password pass every rule; an error is ErrRateLimited or the
// context's.
func (b *BasicAuth) Check(ctx context.Context, client netip.Addr, rules []BasicAuthRule, user, password string) (bool, error) {
	for _, r := range rules {
		ok, err := b.pass(ctx, client, r, user, password)
		if err != nil || !ok {
			return false, err
		}
	}
	return true, nil
}

func (b *BasicAuth) pass(ctx context.Context, client netip.Addr, r BasicAuthRule, user, password string) (bool, error) {
	scope := r.PolicyID + "\x00" + r.CredentialVersion
	k := b.cacheKey(scope, user, password)
	if b.hit(k) {
		return true, nil
	}
	if !b.limit.Allow(client.String()) {
		return false, ErrRateLimited
	}
	select {
	case b.sem <- struct{}{}:
	case <-ctx.Done():
		return false, ctx.Err()
	}
	n := b.busy.Add(1)
	for p := b.peak.Load(); n > p && !b.peak.CompareAndSwap(p, n); p = b.peak.Load() {
	}
	h, known := r.Users[user]
	if !known {
		h = dummyPHC
	}
	ok := h.verify(password) && known
	b.hashes.Add(1)
	b.busy.Add(-1)
	<-b.sem
	if ok {
		b.put(k, scope)
	}
	return ok, nil
}

// cacheKey is HMAC-SHA256 under the gateway's key of the scope, the user's length, the user and
// the password, so ("al", "ice1") and ("ali", "ce1") differ.
func (b *BasicAuth) cacheKey(scope, user, password string) [32]byte {
	m := hmac.New(sha256.New, b.key[:])
	var n [8]byte
	for _, part := range []string{scope, user} {
		binary.BigEndian.PutUint64(n[:], uint64(len(part)))
		m.Write(n[:])
		m.Write([]byte(part))
	}
	m.Write([]byte(password))
	var k [32]byte
	copy(k[:], m.Sum(nil))
	return k
}

func (b *BasicAuth) hit(k [32]byte) bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	e, ok := b.entries[k]
	if !ok {
		return false
	}
	if c := e.Value.(*cached); !b.now().Before(c.expires) {
		b.order.Remove(e)
		delete(b.entries, k)
		return false
	}
	return true
}

func (b *BasicAuth) put(k [32]byte, scope string) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if e, ok := b.entries[k]; ok {
		b.order.Remove(e)
	}
	b.entries[k] = b.order.PushFront(&cached{key: k, scope: scope, expires: b.now().Add(basicAuthTTL)})
	for b.order.Len() > basicAuthCacheSize {
		last := b.order.Back()
		b.order.Remove(last)
		delete(b.entries, last.Value.(*cached).key)
	}
}

// Retain forgets every cached verification of a rule not among rules: a changed or removed rule
// of a snapshot is flushed at once.
func (b *BasicAuth) Retain(rules []BasicAuthRule) {
	keep := map[string]bool{}
	for _, r := range rules {
		keep[r.PolicyID+"\x00"+r.CredentialVersion] = true
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	for e := b.order.Front(); e != nil; {
		next := e.Next()
		if c := e.Value.(*cached); !keep[c.scope] {
			b.order.Remove(e)
			delete(b.entries, c.key)
		}
		e = next
	}
}

// Cached returns the number of cached verifications.
func (b *BasicAuth) Cached() int {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.order.Len()
}

// Hashes returns how many argon2id verifications were done, and the most at once.
func (b *BasicAuth) Hashes() (done, peak int64) { return b.hashes.Load(), b.peak.Load() }
