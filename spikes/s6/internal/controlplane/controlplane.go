// SPDX-License-Identifier: Apache-2.0

// Package controlplane connects certmagic on the controller to the gateways that answer
// HTTP-01 and TLS-ALPN-01 challenges.
//
// certmagic v0.25.6 has no hook for custom HTTP-01 or TLS-ALPN-01 solvers: only DNS01Solver is
// configurable, and the built-in HTTP-01 and TLS-ALPN-01 solvers are wrapped in its
// "distributed solver", which stores the challenge (JSON of acme.Challenge, including the key
// authorization) under "<issuer prefix>/challenge_tokens/<name>.json" before the solver returns
// and acmez asks the CA to validate, and deletes it in CleanUp. SyncStorage decorates the
// controller's storage: when such a key is stored it pushes the challenge to every gateway that
// serves the name and returns only after all of them acknowledged; when it is deleted it removes
// the challenge again. The gateways never read the storage.
package controlplane

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"path"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/caddyserver/certmagic"
	"github.com/mholt/acmez/v3/acme"

	"github.com/felix-homelab/rpmgr/spikes/s6/internal/gateway"
)

// Session is the controller's end of one gateway's control session.
type Session interface {
	GatewayID() string
	PushChallenge(ctx context.Context, u gateway.ChallengeUpdate) error
}

// LocalSession simulates a control session to an in-process gateway: the update is delivered
// after Latency and acknowledged once applied. Drop simulates a gateway that never answers.
type LocalSession struct {
	GW      *gateway.Gateway
	Latency time.Duration
	Drop    atomic.Bool
}

// GatewayID implements Session.
func (s *LocalSession) GatewayID() string { return s.GW.ID }

// PushChallenge implements Session.
func (s *LocalSession) PushChallenge(ctx context.Context, u gateway.ChallengeUpdate) error {
	ack := make(chan error, 1)
	go func() {
		if s.Drop.Load() {
			return // lost: no ack ever arrives
		}
		time.Sleep(s.Latency)
		ack <- s.GW.ApplyChallenge(context.WithoutCancel(ctx), u)
	}()
	select {
	case err := <-ack:
		return err
	case <-ctx.Done():
		return fmt.Errorf("push to gateway %s: %w", s.GW.ID, ctx.Err())
	}
}

// HTTPSession pushes to a gateway in another process through gateway.ControlHandler.
type HTTPSession struct {
	ID, URL, Token string
	Client         *http.Client
}

// GatewayID implements Session.
func (s *HTTPSession) GatewayID() string { return s.ID }

// PushChallenge implements Session.
func (s *HTTPSession) PushChallenge(ctx context.Context, u gateway.ChallengeUpdate) error {
	b, err := json.Marshal(u)
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, s.URL, bytes.NewReader(b))
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+s.Token)
	req.Header.Set("Content-Type", "application/json")
	c := s.Client
	if c == nil {
		c = http.DefaultClient
	}
	resp, err := c.Do(req)
	if err != nil {
		return fmt.Errorf("push to gateway %s: %w", s.ID, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusNoContent {
		msg, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		return fmt.Errorf("push to gateway %s: HTTP %d: %s", s.ID, resp.StatusCode, bytes.TrimSpace(msg))
	}
	return nil
}

// Router returns the sessions of the gateways that serve a hostname (in rpmgr: the gateways of
// the route's gateway group).
type Router func(hostname string) []Session

// SyncStorage is a certmagic.Storage decorator that keeps the gateways' challenge state in sync
// with certmagic's distributed-solver keys.
type SyncStorage struct {
	certmagic.Storage
	Route       Router
	PushTimeout time.Duration

	Pushed atomic.Int64 // challenges pushed and acknowledged by every gateway
	Failed atomic.Int64 // pushes that failed or timed out
}

// Unwrap gives access to the decorated storage's locker extensions.
func (s *SyncStorage) Unwrap() certmagic.Storage { return s.Storage }

// IsChallengeKey reports whether key is one of certmagic's distributed-solver challenge keys.
func IsChallengeKey(key string) bool {
	return path.Base(path.Dir(key)) == "challenge_tokens" && strings.HasSuffix(key, ".json")
}

// Store implements certmagic.Storage. For a challenge key it pushes first and stores only when
// every gateway acknowledged; an error fails certmagic's Present, so the CA is never asked to
// validate a challenge that no gateway can answer.
func (s *SyncStorage) Store(ctx context.Context, key string, value []byte) error {
	if IsChallengeKey(key) {
		var ch acme.Challenge
		if err := json.Unmarshal(value, &ch); err != nil {
			return fmt.Errorf("controlplane: decoding challenge %q: %w", key, err)
		}
		if err := s.fanout(ctx, gateway.ChallengeUpdate{Challenge: ch}); err != nil {
			s.Failed.Add(1)
			return err
		}
		s.Pushed.Add(1)
	}
	return s.Storage.Store(ctx, key, value)
}

// Delete implements certmagic.Storage. For a challenge key the gateways forget the challenge;
// failures are reported but do not block the deletion (a stale challenge answers nothing useful).
func (s *SyncStorage) Delete(ctx context.Context, key string) error {
	if IsChallengeKey(key) {
		if v, err := s.Storage.Load(ctx, key); err == nil {
			var ch acme.Challenge
			if json.Unmarshal(v, &ch) == nil {
				_ = s.fanout(ctx, gateway.ChallengeUpdate{Remove: true, Challenge: ch})
			}
		}
	}
	return s.Storage.Delete(ctx, key)
}

func (s *SyncStorage) fanout(ctx context.Context, u gateway.ChallengeUpdate) error {
	sessions := s.Route(u.Challenge.Identifier.Value)
	if len(sessions) == 0 {
		return fmt.Errorf("controlplane: no gateway serves %q", u.Challenge.Identifier.Value)
	}
	timeout := s.PushTimeout
	if timeout == 0 {
		timeout = 10 * time.Second
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	var wg sync.WaitGroup
	errs := make([]error, len(sessions))
	for i, sess := range sessions {
		wg.Add(1)
		go func() {
			defer wg.Done()
			errs[i] = sess.PushChallenge(ctx, u)
		}()
	}
	wg.Wait()
	return errors.Join(errs...)
}

// Lock, Unlock, TryLock and RenewLockLease forward to the decorated storage so that certmagic
// still sees its optional locker interfaces.

// TryLock implements certmagic.TryLocker if the decorated storage does.
func (s *SyncStorage) TryLock(ctx context.Context, name string) (bool, error) {
	l, ok := s.Storage.(certmagic.TryLocker)
	if !ok {
		return false, errors.New("controlplane: storage has no TryLock")
	}
	return l.TryLock(ctx, name)
}

// RenewLockLease implements certmagic.LockLeaseRenewer if the decorated storage does.
func (s *SyncStorage) RenewLockLease(ctx context.Context, name string, d time.Duration) error {
	l, ok := s.Storage.(certmagic.LockLeaseRenewer)
	if !ok {
		return nil
	}
	return l.RenewLockLease(ctx, name, d)
}
