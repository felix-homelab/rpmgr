// SPDX-License-Identifier: Apache-2.0

package gateway_test

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"net/http"
	"net/netip"
	"sync"
	"testing"
	"time"

	"golang.org/x/crypto/argon2"

	"github.com/felix-homelab/rpmgr/internal/gateway"
)

// phc hashes password with cheap argon2id parameters, m KiB and t passes, in PHC format.
func phc(t *testing.T, password string, m, passes uint32) string {
	t.Helper()
	salt := make([]byte, 16)
	_, _ = rand.Read(salt)
	key := argon2.IDKey([]byte(password), salt, passes, m, 1, 32)
	return fmt.Sprintf("$argon2id$v=19$m=%d,t=%d,p=1$%s$%s", m, passes, base64.RawStdEncoding.EncodeToString(salt),
		base64.RawStdEncoding.EncodeToString(key))
}

func rule(t *testing.T, policy, version string, users ...string) gateway.BasicAuthRule {
	t.Helper()
	r := gateway.BasicAuthRule{PolicyID: policy, CredentialVersion: version, Users: map[string]gateway.PHC{}}
	for i := 0; i+1 < len(users); i += 2 {
		h, err := gateway.ParsePHC(phc(t, users[i+1], 8, 1))
		if err != nil {
			t.Fatal(err)
		}
		r.Users[users[i]] = h
	}
	return r
}

var clientA, clientB = netip.MustParseAddr("192.0.2.1"), netip.MustParseAddr("198.51.100.1")

// TestBasicAuth_HashOncePerTTL: repeated requests with the same valid credentials cost one
// argon2id verification per cache lifetime; failed attempts are rate-limited per client address
// before hashing; verifications at once are capped.
func TestBasicAuth_HashOncePerTTL(t *testing.T) {
	gateway.SetBasicAuthTTL(t, 300*time.Millisecond)
	ctx := context.Background()
	b := gateway.NewBasicAuth(nil)
	rules := []gateway.BasicAuthRule{rule(t, "ap_1", "v1", "alice", "correct horse")}
	for range 3 {
		if ok, err := b.Check(ctx, clientA, rules, "alice", "correct horse"); !ok || err != nil {
			t.Fatalf("valid credentials: %v %v", ok, err)
		}
	}
	if done, _ := b.Hashes(); done != 1 {
		t.Fatalf("%d verifications for three requests, want 1", done)
	}
	time.Sleep(400 * time.Millisecond)
	if ok, _ := b.Check(ctx, clientA, rules, "alice", "correct horse"); !ok {
		t.Fatal("valid credentials after the cache lifetime")
	}
	if done, _ := b.Hashes(); done != 2 {
		t.Fatalf("%d verifications after the cache lifetime, want 2", done)
	}

	// Failed attempts: the burst is verified, then refused without hashing.
	b = gateway.NewBasicAuth(nil)
	refused := 0
	for i := range 25 {
		ok, err := b.Check(ctx, clientA, rules, "alice", fmt.Sprintf("guess %d", i))
		switch {
		case errors.Is(err, gateway.ErrRateLimited):
			refused++
		case ok || err != nil:
			t.Fatalf("a wrong password: %v %v", ok, err)
		}
	}
	if done, _ := b.Hashes(); done != 20 || refused != 5 {
		t.Fatalf("%d verifications, %d refused; want 20 and 5", done, refused)
	}
	if ok, err := b.Check(ctx, clientB, rules, "alice", "correct horse"); !ok || err != nil {
		t.Fatalf("another address: %v %v", ok, err)
	}

	// Verifications at once are capped, whatever the clients.
	slow := gateway.BasicAuthRule{PolicyID: "ap_2", CredentialVersion: "v1", Users: map[string]gateway.PHC{}}
	h, err := gateway.ParsePHC(phc(t, "pw", 16*1024, 2))
	if err != nil {
		t.Fatal(err)
	}
	slow.Users["bob"] = h
	b = gateway.NewBasicAuth(nil)
	var wg sync.WaitGroup
	for i := range byte(12) {
		wg.Go(func() {
			_, _ = b.Check(ctx, netip.AddrFrom4([4]byte{10, 0, 0, i}), []gateway.BasicAuthRule{slow}, "bob", fmt.Sprint(i))
		})
	}
	wg.Wait()
	if done, peak := b.Hashes(); done != 12 || peak > 2 || peak < 1 {
		t.Fatalf("%d verifications, %d at once; want 12 and at most 2", done, peak)
	}
}

// TestBasicAuth_CacheScopedToPolicy: a verification cached for one policy does not pass another
// policy's rule, user and password are length-separated in the key, and a rule that changes is
// flushed and verified again.
func TestBasicAuth_CacheScopedToPolicy(t *testing.T) {
	ctx := context.Background()
	b := gateway.NewBasicAuth(nil)
	x, y := rule(t, "ap_x", "v1", "alice", "pw"), rule(t, "ap_y", "v1", "alice", "pw")
	if ok, _ := b.Check(ctx, clientA, []gateway.BasicAuthRule{x}, "alice", "pw"); !ok {
		t.Fatal("org X's route")
	}
	if ok, _ := b.Check(ctx, clientA, []gateway.BasicAuthRule{y}, "alice", "pw"); !ok {
		t.Fatal("org Y's route")
	}
	if done, _ := b.Hashes(); done != 2 {
		t.Fatalf("%d verifications, want one per policy", done)
	}

	split := rule(t, "ap_s", "v1", "al", "ice1")
	if ok, _ := b.Check(ctx, clientA, []gateway.BasicAuthRule{split}, "al", "ice1"); !ok {
		t.Fatal(`("al", "ice1")`)
	}
	if ok, _ := b.Check(ctx, clientA, []gateway.BasicAuthRule{split}, "ali", "ce1"); ok {
		t.Fatal(`("ali", "ce1") passed on ("al", "ice1")'s cache entry`)
	}

	// The rule changes, here its password: the snapshot's Retain flushes the old entries at once,
	// and the old password no longer passes.
	before := b.Cached()
	x2 := rule(t, "ap_x", "v2", "alice", "new pw")
	b.Retain([]gateway.BasicAuthRule{x2, y, split})
	if b.Cached() != before-1 {
		t.Fatalf("%d cached after the change, want %d", b.Cached(), before-1)
	}
	if ok, _ := b.Check(ctx, clientA, []gateway.BasicAuthRule{x2}, "alice", "pw"); ok {
		t.Fatal("the old password passed the changed rule")
	}
	if ok, _ := b.Check(ctx, clientA, []gateway.BasicAuthRule{x2}, "alice", "new pw"); !ok {
		t.Fatal("the new password")
	}
	// Every rule must pass.
	if ok, _ := b.Check(ctx, clientA, []gateway.BasicAuthRule{x2, y}, "alice", "new pw"); ok {
		t.Fatal("credentials of one rule passed two")
	}
}

// TestParsePHC: argon2id hashes in PHC format within the gateway's bounds.
func TestParsePHC(t *testing.T) {
	if _, err := gateway.ParsePHC(phc(t, "pw", 64*1024, 3)); err != nil {
		t.Fatal(err)
	}
	salt, hash := "c2FsdHNhbHRzYWx0", "aGFzaGhhc2hoYXNoaGFzaGhhc2hoYXNoaGFzaA"
	for name, s := range map[string]string{
		"empty":           "",
		"argon2i":         "$argon2i$v=19$m=8,t=1,p=1$" + salt + "$" + hash,
		"version 16":      "$argon2id$v=16$m=8,t=1,p=1$" + salt + "$" + hash,
		"too much memory": "$argon2id$v=19$m=1048576,t=1,p=1$" + salt + "$" + hash,
		"too many passes": "$argon2id$v=19$m=8,t=11,p=1$" + salt + "$" + hash,
		"no passes":       "$argon2id$v=19$m=8,t=0,p=1$" + salt + "$" + hash,
		"short salt":      "$argon2id$v=19$m=8,t=1,p=1$c2FsdA$" + hash,
		"short hash":      "$argon2id$v=19$m=8,t=1,p=1$" + salt + "$aGFzaA",
		"unknown key":     "$argon2id$v=19$m=8,t=1,p=1,x=2$" + salt + "$" + hash,
		"bad base64":      "$argon2id$v=19$m=8,t=1,p=1$" + salt + "$!!",
		"too few parts":   "$argon2id$v=19$m=8,t=1,p=1$" + salt,
	} {
		if _, err := gateway.ParsePHC(s); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

// TestHTTPRoutes_BasicAuth: an http route with basic auth asks for credentials, refuses wrong ones,
// lets the right ones through without passing them upstream, and limits a guessing client.
func TestHTTPRoutes_BasicAuth(t *testing.T) {
	upstream := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = fmt.Fprintf(w, "auth=%q", r.Header.Get("Authorization")) //nolint:gosec // G705: the test upstream echoes as plain text
	})
	route := gateway.HTTPRoute{ID: "rt_web", Upstream: "http", Hosts: []gateway.HTTPHost{{Hostname: "app.example.com"}},
		BasicAuth: []gateway.BasicAuthRule{rule(t, "ap_1", "v1", "alice", "pw")}}
	e := newHTTPEnv(t, upstream, route)
	c := e.client(false)
	if r := get(t, c, "https://app.example.com/", nil); r.status != http.StatusUnauthorized ||
		r.header.Get("WWW-Authenticate") != `Basic realm="rpmgr", charset="UTF-8"` {
		t.Fatalf("no credentials: %d %v", r.status, r.header)
	}
	creds := func(user, pw string) http.Header {
		req, _ := http.NewRequest(http.MethodGet, "/", nil)
		req.SetBasicAuth(user, pw)
		return http.Header{"Authorization": req.Header.Values("Authorization")}
	}
	if r := get(t, c, "https://app.example.com/", creds("alice", "wrong")); r.status != http.StatusUnauthorized {
		t.Fatalf("a wrong password: %d", r.status)
	}
	if r := get(t, c, "https://app.example.com/", creds("alice", "pw")); r.status != http.StatusOK || r.body != `auth=""` {
		t.Fatalf("the right password: %d %q", r.status, r.body)
	}
	status := 0
	for i := range 25 {
		if status = get(t, c, "https://app.example.com/", creds("alice", fmt.Sprint(i))).status; status == http.StatusTooManyRequests {
			break
		}
	}
	if status != http.StatusTooManyRequests {
		t.Fatalf("a guessing client was never limited: %d", status)
	}
	if r := get(t, c, "https://app.example.com/", creds("alice", "pw")); r.status != http.StatusOK {
		t.Fatalf("the cached right password while limited: %d", r.status)
	}
}
