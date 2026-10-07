// SPDX-License-Identifier: Apache-2.0

package controlplane

import (
	"context"
	"encoding/json"
	"errors"
	"io/fs"
	"net"
	"net/http/httptest"
	"path/filepath"
	"testing"
	"time"

	"github.com/mholt/acmez/v3/acme"

	"github.com/felix-homelab/rpmgr/spikes/s6/internal/dbstore"
	"github.com/felix-homelab/rpmgr/spikes/s6/internal/gateway"
)

func TestIsChallengeKey(t *testing.T) {
	for key, want := range map[string]bool{
		"acme/127.0.0.1:1234-dir/challenge_tokens/app.example.test.json":              true,
		"acme/acme-staging-v02.api.letsencrypt.org-directory/challenge_tokens/a.json": true,
		"certificates/127.0.0.1:1234-dir/app.example.test/app.example.test.json":      false,
		"acme/ca/challenge_tokens/sub/a.json":                                         false,
		"acme/ca/challenge_tokens/a.crt":                                              false,
		"challenge_tokens.json":                                                       false,
	} {
		if got := IsChallengeKey(key); got != want {
			t.Errorf("IsChallengeKey(%q) = %v, want %v", key, got, want)
		}
	}
}

func newGateway(t *testing.T) *gateway.Gateway {
	t.Helper()
	h, _ := net.Listen("tcp", "127.0.0.1:0")
	s, _ := net.Listen("tcp", "127.0.0.1:0")
	g := gateway.New("gw", h, s)
	t.Cleanup(g.Close)
	return g
}

func TestSyncStoragePushesBeforeStoringAndRemovesOnDelete(t *testing.T) {
	ctx := context.Background()
	st, err := dbstore.Open(filepath.Join(t.TempDir(), "c.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	g := newGateway(t)
	srv := httptest.NewServer(gateway.ControlHandler(g, "tok"))
	defer srv.Close()
	good := &HTTPSession{ID: "gw", URL: srv.URL, Token: "tok"}
	s := &SyncStorage{Storage: st, Route: func(string) []Session { return []Session{good} }}

	key := "acme/ca/challenge_tokens/a.test.json"
	ch := acme.Challenge{Type: acme.ChallengeTypeHTTP01, Token: "t", KeyAuthorization: "t.k",
		Identifier: acme.Identifier{Type: "dns", Value: "a.test"}}
	v, _ := json.Marshal(ch)
	if err := s.Store(ctx, key, v); err != nil {
		t.Fatal(err)
	}
	if !g.HasChallenge("a.test") {
		t.Fatal("challenge not on the gateway after Store")
	}
	if err := s.Delete(ctx, key); err != nil {
		t.Fatal(err)
	}
	if g.HasChallenge("a.test") {
		t.Fatal("challenge still on the gateway after Delete")
	}

	// A wrong token, an unroutable name and malformed JSON fail Store, and nothing is stored.
	bad := &HTTPSession{ID: "gw", URL: srv.URL, Token: "wrong"}
	for name, s := range map[string]*SyncStorage{
		"rejected push": {Storage: st, Route: func(string) []Session { return []Session{good, bad} }},
		"no gateway":    {Storage: st, Route: func(string) []Session { return nil }},
	} {
		if err := s.Store(ctx, key, v); err == nil {
			t.Errorf("%s: Store succeeded", name)
		}
		if _, err := st.Load(ctx, key); !errors.Is(err, fs.ErrNotExist) {
			t.Errorf("%s: challenge stored although the push failed", name)
		}
	}
	if err := s.Store(ctx, key, []byte("{not json")); err == nil {
		t.Error("malformed challenge JSON was stored")
	}
	// Other keys pass straight through.
	if err := s.Store(ctx, "certificates/ca/a.test/a.test.crt", []byte("x")); err != nil {
		t.Fatal(err)
	}
}

func TestLocalSessionTimesOutWhenDropped(t *testing.T) {
	g := newGateway(t)
	sess := &LocalSession{GW: g}
	sess.Drop.Store(true)
	s := &SyncStorage{Storage: nil, Route: func(string) []Session { return []Session{sess} },
		PushTimeout: 200 * time.Millisecond}
	start := time.Now()
	err := s.fanout(context.Background(), gateway.ChallengeUpdate{Challenge: acme.Challenge{
		Type: acme.ChallengeTypeHTTP01, Token: "t", KeyAuthorization: "k",
		Identifier: acme.Identifier{Value: "a.test"}}})
	if !errors.Is(err, context.DeadlineExceeded) || time.Since(start) > 2*time.Second {
		t.Fatalf("fanout to a dropped session = %v after %v", err, time.Since(start))
	}
}
